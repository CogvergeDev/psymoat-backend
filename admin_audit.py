"""Backend admin audit events. No raw bodies, credentials or response dumps.

Events are append-only and paired by request_id. A started event with no outcome
means unknown, never failure. Provision the table before deploying this module.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import ipaddress
import logging
import os
import time
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from flask import current_app, g, has_request_context, jsonify, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request


TABLE_NAME = "AdminAuditLogs"
KEY_SCHEMA = [{"AttributeName": "pk", "KeyType": "HASH"},
              {"AttributeName": "sk", "KeyType": "RANGE"}]
logger = logging.getLogger(__name__)

# Exact method/rule pairs prevent student submissions/payments being classified
# as administrative changes. Catalog/admin and /admin routes are covered below.
ROUTES = {
    ("POST", "/grant-paid-access"): "access.grant",
    ("POST", "/change-password"): "password.reset",
    ("POST", "/export-users-by-plan"): "users.export",
    ("DELETE", "/delete-payment-fields"): "access.remove",
    ("POST", "/cleanup-expired-plans"): "subscriptions.cleanup",
    ("POST", "/get-users-with-exams-paid-for-no-payment-fields"): "subscriptions.reconcile",
    ("GET", "/get-active-paid-users"): "users.paid_list",
    ("POST", "/remove-user-graphs"): "graphs.reset",
    ("POST", "/remove-graphs-all-users"): "graphs.reset_all",
    ("POST", "/add-new-lecture"): "lecture.create",
    ("PUT", "/update-lecture/<string:lecture_id>"): "lecture.update",
    ("DELETE", "/delete-lecture/<string:lecture_id>"): "lecture.delete",
    ("POST", "/add-standalone-note"): "note.create",
    ("PUT", "/update-standalone-note/<string:note_id>"): "note.update",
    ("DELETE", "/delete-standalone-note/<string:note_id>"): "note.delete",
    ("POST", "/generate-video-upload-url"): "video.upload_url",
    ("POST", "/upload-lecture-video"): "video.upload",
    ("POST", "/process-video"): "video.process",
    ("DELETE", "/delete-lecture-video"): "video.delete",
    ("POST", "/initialize-new-exam"): "exam.create",
    ("POST", "/initialize-new-module"): "module.create",
    ("POST", "/add-to-module/<string:module_id>"): "questions.add",
    ("POST", "/create-new-mock-test"): "mock_test.create",
    ("POST", "/blogs/create-new"): "blog.create",
    ("PUT", "/blogs/edit"): "blog.update",
    ("DELETE", "/blogs/delete/<string:blog_id>"): "blog.delete",
    ("POST", "/upload"): "content.upload",
    ("GET", "/get-all-exam-details"): "exams.list",
    ("GET", "/get-all-module-details"): "modules.list",
    ("GET", "/get-all-lectures/<string:exam_id>"): "lectures.list",
    ("GET", "/get-standalone-notes/<string:exam_id>"): "notes.list",
    ("GET", "/get-nonstandard-yt-lectures"): "lectures.diagnose_list",
    ("GET", "/diagnose-lecture-issue"): "lecture.diagnose",
    ("GET", "/catalog/exams"): "exams.list",
    ("GET", "/catalog/lectures/<lecture_id>/placement"): "lecture.placement_read",
}
READ_POSTS = {"users.export", "admin.admin_get_user_route", "admin.admin_payment_history_route"}

# Allowlisting is deliberately recursive. Unknown fields and nested secrets are
# dropped, even if a client adds them to an otherwise legitimate payload.
SAFE_FIELDS = set("""
email user_id plan_id months exam_ids unit_ids is_paid plan_valid_till
exams_paid_for units_paid_for last_subscription_plan_id last_subscription_valid_till
subscription_expiry_source lecture_id note_id exam_id module_id blog_id test_id
id name exam_name module_name title category instructor_details instructor_name
date_time_of_zoom_lec key_topics description notes_markdown instructor_bio bio
yt_link zoom_link video_key filename content_type folder_id section_id unit_id
placement display_title lecture_number order syllabus_number icon active is_active
kind lecture_count status count payment_count cleared_count failed_count
removed_fields changed_fields reason content_length size outcome error_category
exists fields processed_count skipped_count snapshot_error user_count
""".split())
CONTENT_FIELDS = {"notes_markdown", "description", "instructor_bio", "bio",
                  "key_topics", "zoom_link", "yt_link"}
USER_FIELDS = "email user_id is_paid plan_id plan_valid_till exams_paid_for units_paid_for last_subscription_plan_id last_subscription_valid_till subscription_expiry_source".split()


def safe_fields(data, depth=0, budget=None):
    """Bounded DynamoDB-safe metadata; no unrestricted request/response strings."""
    if not isinstance(data, dict) or depth > 4:
        return {}
    budget = [500] if budget is None else budget
    result = {}
    for key, value in data.items():
        if key not in SAFE_FIELDS:
            continue
        if budget[0] <= 0:
            result['_truncated'] = True
            break
        budget[0] -= 1
        if key in CONTENT_FIELDS:
            text = str(value)
            result[key] = {"sha256": hashlib.sha256(text.encode()).hexdigest(), "length": len(text)}
        elif key == 'video_key' and isinstance(value, str):
            result[key] = target_value(key, value)
        else:
            result[key] = safe_value(value, depth + 1, budget)
    return result


def safe_value(value, depth=0, budget=None):
    budget = [500] if budget is None else budget
    if value is None or isinstance(value, (bool, int, Decimal)):
        return value
    if isinstance(value, float):
        return Decimal(str(value)) if Decimal(str(value)).is_finite() else None
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, dict):
        return safe_fields(value, depth, budget)
    if isinstance(value, (list, tuple, set)) and depth <= 4:
        values = list(value)
        items = []
        for item in values[:100]:
            if budget[0] <= 0:
                break
            budget[0] -= 1
            items.append(safe_value(item, depth + 1, budget))
        return items if len(values) == len(items) else {"items": items, "total_count": len(values), "truncated": True}
    return None


def action_for(rule, method, endpoint=""):
    if method == "OPTIONS":
        return None
    method = "GET" if method == "HEAD" else method
    if rule.startswith("/admin/") or rule.startswith("/catalog/admin/"):
        return "admin." + endpoint.replace("lecture_catalog.", "catalog.")
    if rule.startswith("/create-") and rule.endswith("-table"):
        return "table.provision"
    return ROUTES.get((method, rule))


def target_value(key, value):
    text = str(value)
    if key == 'video_key' and ('://' in text or '?' in text):
        return 'sha256:' + hashlib.sha256(text.encode()).hexdigest()
    return text[:512]


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return None


def ip_details(req, trusted_hops=0):
    peer = valid_ip(req.remote_addr or "")
    raw = req.headers.get("X-Forwarded-For", "")
    # Preserve the rightmost (proxy-appended) entries when bounding a header.
    chain = [valid_ip(part) for part in raw.split(",")[-20:]] if raw else []
    ip = peer
    source = "peer"
    if 0 < trusted_hops <= len(chain) and all(chain):
        ip, source = chain[-trusted_hops], "trusted_forwarded"
    return {"ip": ip, "ip_source": source, "peer_ip": peer,
            "forwarded_ips_unverified": [part for part in chain if part]}


class AuditUnavailable(RuntimeError):
    pass


class AuditStore:
    def __init__(self, table):
        self.table = table

    def write(self, context, phase, details=None, event_id=None):
        now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        event_id = event_id or str(uuid4())
        # Stable key across retries, including an ambiguous network timeout.
        item = {"pk": "DAY#" + now[:10], "sk": now + "#" + event_id,
                "schema_version": 1, "timestamp_utc": now,
                "request_id": context.request_id, "phase": phase,
                "action": context.action, "method": context.method,
                "route": context.rule, "actor": context.actor,
                "network": context.network, "target": context.target,
                "details": details or {}}
        # Maliciously large metadata must not cause a >400KB item or a stalled
        # action. Keep the action/target/outcome and describe omitted sections.
        import json
        if len(json.dumps(item, default=str).encode()) > 64000:
            original_details = item['details']
            item['details'] = {key: value for key, value in item['details'].items()
                               if key in ('outcome', 'http_status', 'duration_ms', 'error_category', 'operation_id')}
            core = {'email', 'plan_id', 'months', 'is_paid', 'plan_valid_till',
                    'last_subscription_plan_id', 'last_subscription_valid_till',
                    'lecture_id', 'note_id', 'exam_id', 'id', 'title', 'name', 'exists'}
            for section in ('requested', 'before', 'after', 'result'):
                if isinstance(original_details.get(section), dict):
                    item['details'][section] = {key: value for key, value in original_details[section].items() if key in core}
            item['details']['metadata_omitted'] = 'exceeded_64kb'
        for attempt in range(3):
            try:
                self.table.put_item(Item=item, ConditionExpression="attribute_not_exists(pk) AND attribute_not_exists(sk)")
                return
            except ClientError as error:
                if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                    return  # This exact immutable event was already saved.
                if attempt == 2:
                    raise AuditUnavailable("Audit storage unavailable") from None
            except Exception:
                if attempt == 2:
                    raise AuditUnavailable("Audit storage unavailable") from None


@dataclass
class AuditContext:
    store: AuditStore
    action: str
    method: str
    rule: str
    actor: dict
    network: dict
    target: dict
    request_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: float = field(default_factory=time.monotonic)
    details: dict = field(default_factory=dict)
    start_saved: bool = False
    writes_pending: bool = False


def current_audit():
    return getattr(g, "admin_audit", None) if has_request_context() else None


def audit_state(**details):
    """Attach safe controller-observed state to the enclosing request outcome."""
    context = current_audit()
    if context:
        for key, value in details.items():
            if key in ("before", "after", "result"):
                context.details[key] = safe_fields(value)


def audit_child_start(email, before, changes):
    """Durable per-account evidence for a bulk operation; gate each mutation."""
    parent = current_audit()
    if not parent:
        return None
    child = AuditContext(parent.store, parent.action, parent.method, parent.rule,
                         parent.actor, parent.network, {"email": str(email)[:512]}, request_id=parent.request_id)
    child.details = {"operation_id": str(uuid4()), "before": safe_fields(before), "requested": safe_fields(changes)}
    child.store.write(child, "account_started", child.details)
    return child


def audit_child_finish(child, outcome, after=None, error=None):
    if child:
        details = {**child.details, "outcome": outcome, "after": safe_fields(after or {})}
        if error:
            details["error_category"] = type(error).__name__
        finish_event(child, "account_completed", details)


def finish_event(context, phase, details):
    if 'video_key' in details:
        details = {**details, **safe_fields({'video_key': details['video_key']})}
    try:
        context.store.write(context, phase, details)
    except AuditUnavailable:
        context.writes_pending = True
        parent = current_audit()
        if parent:
            parent.writes_pending = True
        # Never dump the exception, payload or target into infrastructure logs.
        logger.error("ADMIN_AUDIT_OUTCOME_UNSAVED request_id=%s phase=%s", context.request_id, phase)


def snapshot(db, target, action):
    """Projected observations for content edit/delete diagnostics, not locks."""
    table, key, fields = None, None, None
    if target.get("lecture_id") and ("lecture" in action or "placement" in action):
        table, key = db.LectureTable, {"lecture_id": target["lecture_id"]}
    elif target.get("note_id"):
        table, key = db.NotesTable, {"note_id": target["note_id"]}
    elif target.get("entity_id") and target.get("exam") and target.get("kind"):
        table = db.dynamodb_resource.Table(os.getenv("LECTURE_CATALOG_TABLE", "LectureCatalog"))
        key = {"pk": "EXAM#" + target["exam"], "sk": target["kind"] + "#" + target["entity_id"]}
    elif (target.get("exam") or target.get("exam_id")) and ("exam" in action or "toggle" in action):
        table, key = db.ExamTable, {"exam_id": target.get("exam") or target["exam_id"]}
    elif target.get("email") and action == "access.remove":
        table, key, fields = db.UserTable, {"email": target["email"]}, USER_FIELDS
    if table is None:
        return None
    fields = fields or sorted(SAFE_FIELDS)
    names = {"#f" + str(i): name for i, name in enumerate(fields)}
    result = table.get_item(Key=key, ConsistentRead=True,
                            ProjectionExpression=", ".join(names), ExpressionAttributeNames=names)
    observed = {"exists": "Item" in result, **safe_fields(result.get("Item", {}))}
    if key.get('lecture_id') and action.startswith('admin.catalog.'):
        from lecture_catalog import Catalog
        observed['placement'] = safe_fields(Catalog(db).placement(key['lecture_id']) or {})
    return observed


def install_admin_audit(app, db, store=None):
    if store is None:
        client = db.dynamodb_resource.meta.client
        resource = boto3.resource('dynamodb', region_name=client.meta.region_name,
                                  endpoint_url=client.meta.endpoint_url,
                                  aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                                  aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                                  config=Config(connect_timeout=2, read_timeout=3, retries={'total_max_attempts': 1}))
        store = AuditStore(resource.Table(os.getenv("ADMIN_AUDIT_TABLE", TABLE_NAME)))
    app.extensions["admin_audit"] = store
    app.config.setdefault("ADMIN_AUDIT_TRUSTED_PROXY_HOPS", int(os.getenv("ADMIN_AUDIT_TRUSTED_PROXY_HOPS", "0")))

    @app.before_request
    def start_admin_audit():
        if request.url_rule is None:
            return None
        rule = request.url_rule.rule
        action = action_for(rule, request.method, request.endpoint or "")
        if action is None:
            return None
        actor = {"authentication": "unauthenticated"}
        if "JWT_SECRET_KEY" in current_app.config:
            try:
                verify_jwt_in_request(optional=True)
                identity = get_jwt_identity()
                if identity:
                    actor = {"authentication": "verified_jwt", "identity": str(identity)[:512]}
            except Exception:
                actor = {"authentication": "invalid_jwt"}
        body = request.get_json(silent=True)
        body = body if isinstance(body, dict) else {}
        target = {key: target_value(key, value) for key, value in (request.view_args or {}).items()}
        for key in ("email", "lecture_id", "note_id", "exam_id", "module_id", "blog_id", "test_id", "video_key", "plan_id"):
            if isinstance(body.get(key), str):
                target[key] = target_value(key, body[key])
            elif key in request.args:
                target[key] = target_value(key, request.args[key])
        context = AuditContext(store, action, request.method, rule, actor,
                               ip_details(request, current_app.config["ADMIN_AUDIT_TRUSTED_PROXY_HOPS"]), target)
        g.admin_audit = context
        context.details["requested"] = safe_fields(body)
        context.details["query"] = safe_fields(request.args.to_dict())
        try:
            store.write(context, "started", context.details)
            context.start_saved = True
        except AuditUnavailable:
            logger.error("ADMIN_AUDIT_START_UNSAVED request_id=%s", context.request_id)
            mutates = (request.method not in ("GET", "HEAD") and action not in READ_POSTS) or action == "table.provision"
            if mutates:
                return jsonify(message="Administrative audit storage is unavailable. No action was performed. Please retry.", request_id=context.request_id), 503
        # Content observations are optional; an unavailable source table must
        # not replace the endpoint's own validation or error handling.
        if request.method not in ("GET", "HEAD"):
            try:
                before = snapshot(db, target, action)
                if before is not None:
                    context.details["before"] = before
            except Exception as error:
                context.details["snapshot_error"] = type(error).__name__

    @app.after_request
    def finish_admin_audit(response):
        context = current_audit()
        if context is None:
            return response
        result = response.get_json(silent=True) if response.is_json else None
        result = result if isinstance(result, dict) else {}
        status = str(result.get("status", "")).lower()
        outcome = "failed" if response.status_code >= 400 or status in ("error", "failed") else "succeeded"
        if status == "partial_success":
            outcome = "partial_success"
        audit_result = {**context.details.get('result', {}), **safe_fields(result)}
        if outcome == 'succeeded' and audit_result.get('failed_count', 0):
            outcome = 'partial_success' if audit_result.get('count') or audit_result.get('cleared_count') else 'failed'
        if response.status_code == 202:
            outcome = "accepted"
        if not context.start_saved and response.status_code == 503:
            outcome = "blocked"
        details = {**context.details, "outcome": outcome, "http_status": response.status_code,
                   "duration_ms": int((time.monotonic() - context.started_at) * 1000), "result": audit_result}
        if response.status_code >= 400:
            details["error_category"] = "http_" + str(response.status_code)
        for entity in ("lecture", "note", "entity", "blog"):
            if isinstance(result.get(entity), dict):
                details["result"][entity] = safe_fields(result[entity])
                for key in ("lecture_id", "note_id", "id", "blog_id"):
                    if result[entity].get(key):
                        context.target[key] = target_value(key, result[entity][key])
                        if entity == 'entity' and key == 'id':
                            context.target['entity_id'] = context.target[key]
        for key in ("lecture_id", "note_id", "id", "video_key"):
            if isinstance(result.get(key), str):
                context.target[key] = target_value(key, result[key])
                if key == 'id' and context.action == 'admin.catalog.create_exam':
                    context.target['exam_id'] = context.target[key]
        # No CSV bodies or user/payment lists are copied into the audit table.
        for key in ("users", "payments", "all_lectures", "notes", "exams"):
            if isinstance(result.get(key), (list, dict)):
                details["result"][key + "_count"] = len(result[key])
        if request.method not in ("GET", "HEAD") and outcome in ("succeeded", "partial_success"):
            try:
                after = snapshot(db, context.target, context.action)
                if after is not None:
                    details["after"] = after
            except Exception as error:
                details["snapshot_error"] = type(error).__name__
        finish_event(context, "completed", details)
        response.headers["X-Admin-Audit-Request-Id"] = context.request_id
        if context.writes_pending or not context.start_saved:
            response.headers["X-Admin-Audit-Status"] = "incomplete"
        return response
