"""Backfill script: Convert user submission history into UserActivity and streak data.

This script scans historical question submissions (from QNAHistory, TestsSolvedUserData,
and UserTable) and aggregates them into daily activity records in the UserActivity table.
This ensures a smooth transition when introducing or restoring streaks and activity heatmaps.

The default operation is a read-only preview. Applying requires an explicit scope and
AWS account confirmation, creates a complete local backup first, and only raises
existing counters via conditional updates. See --help for operational commands.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shlex
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from zoneinfo import ZoneInfo
from dateutil import parser as date_parser
from botocore.exceptions import ClientError
from dotenv import load_dotenv

# Load environment variables before importing controller
load_dotenv()
import controller

IST = ZoneInfo("Asia/Kolkata")
DEFAULT_STREAK_GOAL = getattr(controller, "STREAK_DAILY_QUESTION_GOAL", 20)
TABLE_NAME = controller.UserActivityTable.name
BACKUP_FORMAT_VERSION = 1


class MigrationError(RuntimeError):
    """Raised when the migration cannot safely continue."""


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return {"__decimal__": str(value)}
    if isinstance(value, bytes):
        return {"__bytes_hex__": value.hex()}
    raise TypeError(f"Cannot JSON-serialize {type(value).__name__}")


def _json_object_hook(value: Dict[str, Any]) -> Any:
    if set(value) == {"__decimal__"}:
        return Decimal(value["__decimal__"])
    if set(value) == {"__bytes_hex__"}:
        return bytes.fromhex(value["__bytes_hex__"])
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        default=_json_default,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _safe_account_id_from_arn(table_arn: str) -> str:
    match = re.match(r"^arn:[^:]+:dynamodb:[^:]+:(\d{12}):table/", table_arn)
    if not match:
        raise MigrationError(f"Could not determine AWS account from table ARN: {table_arn}")
    return match.group(1)


def inspect_target() -> Dict[str, str]:
    """Return the exact DynamoDB target without mutating it."""
    description = controller.dynamodb_resource.meta.client.describe_table(
        TableName=TABLE_NAME
    )["Table"]
    table_arn = description["TableArn"]
    return {
        "account_id": _safe_account_id_from_arn(table_arn),
        "region": table_arn.split(":")[3],
        "table_name": description["TableName"],
        "table_arn": table_arn,
    }


def require_target_confirmation(target: Dict[str, str], confirmed_account_id: Optional[str]) -> None:
    if confirmed_account_id != target["account_id"]:
        raise MigrationError(
            "Refusing to write. Re-run with "
            f"--confirm-account-id {shlex.quote(target['account_id'])} after verifying "
            f"that {target['table_arn']} is the intended live table."
        )


def scan_entire_table(table: Any, *, consistent_read: bool = False) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    scan_args: Dict[str, Any] = {"ConsistentRead": consistent_read}
    while True:
        response = table.scan(**scan_args)
        items.extend(response.get("Items", []))
        last_key = response.get("LastEvaluatedKey")
        if not last_key:
            return items
        scan_args["ExclusiveStartKey"] = last_key


def create_local_backup(target: Dict[str, str], backup_dir: Path) -> Path:
    """Create a compressed, checksummed local backup of the complete activity table."""
    backup_dir.mkdir(parents=True, exist_ok=True)
    items = scan_entire_table(controller.UserActivityTable, consistent_read=True)
    items.sort(key=lambda item: (str(item.get("email", "")), str(item.get("activity_date", ""))))
    items_hash = hashlib.sha256(_canonical_json(items)).hexdigest()
    created_at = datetime.now(IST).isoformat(timespec="seconds")
    stamp = datetime.now(IST).strftime("%Y%m%dT%H%M%S%f%z")
    destination = backup_dir / f"UserActivity-{target['account_id']}-{stamp}.json.gz"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    payload = {
        "format_version": BACKUP_FORMAT_VERSION,
        "created_at": created_at,
        "target": target,
        "item_count": len(items),
        "items_sha256": items_hash,
        "items": items,
    }
    try:
        with gzip.open(temporary, "wt", encoding="utf-8") as handle:
            json.dump(payload, handle, default=_json_default, sort_keys=True)
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def load_local_backup(path: Path) -> Dict[str, Any]:
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        payload = json.load(handle, object_hook=_json_object_hook)
    if payload.get("format_version") != BACKUP_FORMAT_VERSION:
        raise MigrationError(f"Unsupported backup format in {path}")
    items = payload.get("items")
    if not isinstance(items, list):
        raise MigrationError(f"Backup {path} does not contain an item list")
    actual_hash = hashlib.sha256(_canonical_json(items)).hexdigest()
    if actual_hash != payload.get("items_sha256"):
        raise MigrationError(f"Backup checksum verification failed for {path}")
    if len(items) != payload.get("item_count"):
        raise MigrationError(f"Backup item count verification failed for {path}")
    return payload


def restore_local_backup(path: Path, target: Dict[str, str]) -> Tuple[int, int]:
    """Restore exact backed-up state. Run only while application writes are paused."""
    payload = load_local_backup(path)
    backup_target = payload.get("target", {})
    if backup_target.get("table_arn") != target["table_arn"]:
        raise MigrationError(
            f"Backup targets {backup_target.get('table_arn')}, not {target['table_arn']}"
        )

    backup_items = payload["items"]
    backup_keys = {
        (str(item["email"]), str(item["activity_date"])) for item in backup_items
    }
    current_items = scan_entire_table(controller.UserActivityTable, consistent_read=True)
    keys_to_delete = [
        {"email": item["email"], "activity_date": item["activity_date"]}
        for item in current_items
        if (str(item["email"]), str(item["activity_date"])) not in backup_keys
    ]

    with controller.UserActivityTable.batch_writer(
        overwrite_by_pkeys=["email", "activity_date"]
    ) as batch:
        for item in backup_items:
            batch.put_item(Item=item)
        for key in keys_to_delete:
            batch.delete_item(Key=key)
    return len(backup_items), len(keys_to_delete)


def extract_ist_date(ts_val: Any) -> Optional[str]:
    """Parse various timestamp representations and return 'YYYY-MM-DD' in IST."""
    if not ts_val:
        return None

    # Numeric epoch timestamp (seconds or milliseconds)
    if isinstance(ts_val, (int, float)):
        try:
            if ts_val > 1e11:  # milliseconds
                ts_val = ts_val / 1000.0
            dt = datetime.fromtimestamp(ts_val, tz=IST)
            return dt.strftime("%Y-%m-%d")
        except Exception:
            return None

    if isinstance(ts_val, str):
        ts_val = ts_val.strip()
        if not ts_val:
            return None

        # Numeric string epoch
        if ts_val.isdigit():
            try:
                val = float(ts_val)
                if val > 1e11:
                    val = val / 1000.0
                dt = datetime.fromtimestamp(val, tz=IST)
                return dt.strftime("%Y-%m-%d")
            except Exception:
                pass

        # Standard Psymoat timestamp format: "YYYY-MM-DD HH:MM:SS"
        if len(ts_val) >= 10 and ts_val[4] == '-' and ts_val[7] == '-':
            # If standard string without timezone offset or 'Z', get_time() produced it in IST
            if 'T' not in ts_val and '+' not in ts_val and not ts_val.endswith('Z'):
                return ts_val[:10]

            # ISO 8601 format
            try:
                dt = date_parser.parse(ts_val)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=IST)
                else:
                    dt = dt.astimezone(IST)
                return dt.strftime("%Y-%m-%d")
            except Exception:
                return ts_val[:10]

        # Generic dateutil fallback
        try:
            dt = date_parser.parse(ts_val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IST)
            else:
                dt = dt.astimezone(IST)
            return dt.strftime("%Y-%m-%d")
        except Exception:
            return None

    return None


def fetch_registered_users(target_email: Optional[str] = None) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Fetch user profile(s) and build user_id -> email mappings."""
    users_by_email: Dict[str, Dict[str, Any]] = {}
    user_id_to_email: Dict[str, str] = {}

    if target_email:
        resp = controller.UserTable.get_item(Key={'email': target_email})
        if 'Item' in resp:
            item = resp['Item']
            canonical_email = str(item['email']).strip()
            users_by_email[canonical_email] = item
            user_id = item.get('user_id')
            if user_id:
                user_id_to_email[str(user_id)] = canonical_email
        return users_by_email, user_id_to_email

    scan_args = {
        'ProjectionExpression': 'email, user_id, fullName, tests_submitted'
    }
    while True:
        response = controller.UserTable.scan(**scan_args)
        for item in response.get('Items', []):
            email = item.get('email')
            if not email:
                continue
            email = str(email).strip()
            users_by_email[email] = item
            user_id = item.get('user_id')
            if user_id:
                user_id_to_email[str(user_id)] = email

        last_key = response.get('LastEvaluatedKey')
        if not last_key:
            break
        scan_args['ExclusiveStartKey'] = last_key

    return users_by_email, user_id_to_email


def collect_qna_history(
    target_email: Optional[str],
    user_id_to_email: Dict[str, str],
    canonical_email_by_fold: Dict[str, str],
) -> Tuple[Dict[str, Dict[str, Dict[str, Any]]], int]:
    """
    Scan QNAHistoryTable to aggregate module quiz practice answers.
    Returns:
        aggregated: dict of email -> { date_str: { 'questions': int, 'batches': set } }
        total_records: total items processed
    """
    aggregated: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(
        lambda: defaultdict(lambda: {'questions': 0, 'batches': set()})
    )
    total_records = 0

    print("[1/3] Scanning QNAHistory for quiz submissions...", flush=True)
    scan_args: Dict[str, Any] = {}
    if target_email:
        # Find target user_id if present
        target_uid = None
        for uid, em in user_id_to_email.items():
            if em.casefold() == target_email.casefold():
                target_uid = uid
                break

        if target_uid:
            scan_args['FilterExpression'] = (
                controller.Attr('email').eq(target_email) | controller.Attr('user_id').eq(target_uid)
            )
        else:
            scan_args['FilterExpression'] = controller.Attr('email').eq(target_email)
    while True:
        response = controller.QNAHistoryTable.scan(**scan_args)
        items = response.get('Items', [])
        total_records += len(items)

        for item in items:
            email = item.get('email')
            if not email:
                user_id = item.get('user_id')
                if user_id and str(user_id) in user_id_to_email:
                    email = user_id_to_email[str(user_id)]

            if not email:
                continue
            email = str(email).strip()
            email = canonical_email_by_fold.get(email.casefold(), email)

            if target_email and email.casefold() != target_email.casefold():
                continue

            ts = item.get('timestamp')
            date_str = extract_ist_date(ts)
            if not date_str:
                continue

            module_id = item.get('module_id') or item.get('exam_id') or 'module'
            batch_key = f"{module_id}_{ts}"

            user_day = aggregated[email][date_str]
            user_day['questions'] += 1
            user_day['batches'].add(batch_key)

        last_key = response.get('LastEvaluatedKey')
        if not last_key:
            break
        scan_args['ExclusiveStartKey'] = last_key

    print(f"      Processed {total_records} QNAHistory records.", flush=True)

    return aggregated, total_records


def collect_tests_history(
    target_email: Optional[str],
    canonical_email_by_fold: Dict[str, str],
) -> Tuple[Dict[str, Dict[str, Dict[str, Any]]], int]:
    """
    Scan TestsSolvedUserDataTable to aggregate mock test submissions.
    Returns:
        aggregated: dict of email -> { date_str: { 'questions': int, 'tests_count': int, 'test_ids': set } }
        total_tests: total test submissions processed
    """
    aggregated: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(
        lambda: defaultdict(lambda: {'questions': 0, 'tests_count': 0, 'test_ids': set()})
    )
    total_tests = 0

    print("[2/3] Scanning TestsSolvedUserData for mock test submissions...", flush=True)
    if target_email:
        resp = controller.TestsSolvedUserDataTable.get_item(Key={'email': target_email})
        items = [resp['Item']] if 'Item' in resp else []
    else:
        items = scan_entire_table(controller.TestsSolvedUserDataTable)

    for item in items:
        email = item.get('email')
        if not email:
            continue
        email = str(email).strip()
        email = canonical_email_by_fold.get(email.casefold(), email)

        if target_email and email.casefold() != target_email.casefold():
            continue

        tests_submitted = item.get('tests_submitted', [])
        if not isinstance(tests_submitted, list):
            continue

        for test in tests_submitted:
            if not isinstance(test, dict):
                continue
            total_tests += 1

            ts = test.get('timestamp')
            date_str = extract_ist_date(ts)
            if not date_str:
                continue

            test_id = str(test.get('test_id') or test.get('exam_id') or f"test_{total_tests}")
            detailed_qna = test.get('detailed_user_test_qna', [])

            # The frontend stores every test question and uses null for unanswered ones.
            # Do not turn an all-unanswered test into an all-answered test.
            answered_count = 0
            if isinstance(detailed_qna, list):
                answered_count = sum(
                    1
                    for question in detailed_qna
                    if isinstance(question, dict)
                    and any(
                        key in question and question.get(key) not in (None, "")
                        for key in ("selected_answer", "selected_option")
                    )
                )
            if not detailed_qna:
                correct_ids = test.get("correct_answers_qid", [])
                wrong_ids = test.get("wrong_answers_qid", [])
                if isinstance(correct_ids, list) and isinstance(wrong_ids, list):
                    answered_count = len(correct_ids) + len(wrong_ids)

            user_day = aggregated[email][date_str]
            user_day['questions'] += answered_count
            user_day['tests_count'] += 1
            user_day['test_ids'].add(f"{test_id}_{ts}")

    print(f"      Processed {total_tests} mock test submissions.", flush=True)

    return aggregated, total_tests


def collect_user_table_fallback(
    users_by_email: Dict[str, Dict[str, Any]],
    existing_tests_by_email: Dict[str, Dict[str, Dict[str, Any]]]
) -> int:
    """Check UserTable.tests_submitted for any mock tests not present in TestsSolvedUserData."""
    fallback_count = 0
    unresolved: List[str] = []
    for email, user in users_by_email.items():
        tests_submitted = user.get('tests_submitted', [])
        if not isinstance(tests_submitted, list) or not tests_submitted:
            continue

        for test in tests_submitted:
            if not isinstance(test, dict):
                continue

            ts = test.get('timestamp')
            date_str = extract_ist_date(ts)
            if not date_str:
                continue

            test_id = str(test.get('test_id') or test.get('exam_id') or "test")
            test_key = f"{test_id}_{ts}"

            user_day = existing_tests_by_email[email][date_str]
            if test_key not in user_day['test_ids']:
                # UserTable stores only a summary for newer submissions. Never use
                # total_marks as a question count because questions can have different marks.
                explicit_count = test.get('questions_answered', test.get('total_questions'))
                if explicit_count is None:
                    unresolved.append(f"{email}:{test_id}:{ts}")
                    continue
                q_count = int(explicit_count)
                if q_count < 0:
                    raise MigrationError(f"Negative question count in UserTable for {test_key}")
                user_day['test_ids'].add(test_key)
                user_day['tests_count'] += 1
                user_day['questions'] += q_count
                fallback_count += 1

    if fallback_count > 0:
        print(f"      Recovered {fallback_count} additional tests from UserTable records.")
    if unresolved:
        sample = ", ".join(unresolved[:5])
        raise MigrationError(
            f"Found {len(unresolved)} UserTable-only test submission(s) without an exact "
            f"answered-question count; refusing to guess. Sample: {sample}"
        )
    return fallback_count


def calculate_streak_stats(
    daily_activity: Dict[str, int],
    goal: int = DEFAULT_STREAK_GOAL
) -> Dict[str, Any]:
    """Calculate streak metrics matching get_user_activity_summary logic."""
    if not daily_activity:
        return {
            'active_days': 0,
            'total_questions': 0,
            'current_streak': 0,
            'longest_streak': 0,
        }

    today = datetime.now(IST).date()
    all_dates = sorted(daily_activity.keys())
    if not all_dates:
        return {
            'active_days': 0,
            'total_questions': 0,
            'current_streak': 0,
            'longest_streak': 0,
        }

    first_date = datetime.strptime(all_dates[0], "%Y-%m-%d").date()
    days_span = (today - first_date).days + 1
    if days_span < 1:
        days_span = 1

    daily_questions = [
        daily_activity.get((first_date + timedelta(days=offset)).isoformat(), 0)
        for offset in range(days_span)
    ]

    active_days = sum(q > 0 for q in daily_activity.values())
    total_questions = sum(daily_activity.values())

    longest_streak = 0
    running_streak = 0
    for questions_completed in daily_questions:
        if questions_completed >= goal:
            running_streak += 1
            longest_streak = max(longest_streak, running_streak)
        else:
            running_streak = 0

    # Match controller.get_user_activity_summary: a current streak must include today.
    current_streak = 0
    streak_date = today
    while streak_date >= first_date:
        if daily_activity.get(streak_date.isoformat(), 0) < goal:
            break
        current_streak += 1
        streak_date -= timedelta(days=1)

    return {
        'active_days': active_days,
        'total_questions': total_questions,
        'current_streak': current_streak,
        'longest_streak': longest_streak,
    }


def fetch_existing_user_activity(email: str) -> Dict[str, Dict[str, Any]]:
    """Fetch existing UserActivity records for a user."""
    records: Dict[str, Dict[str, Any]] = {}
    query_args = {
        'KeyConditionExpression': controller.Key('email').eq(email),
        'ConsistentRead': True,
    }
    while True:
        resp = controller.UserActivityTable.query(**query_args)
        for item in resp.get('Items', []):
            date_str = item.get('activity_date')
            if date_str:
                records[date_str] = item
        last_key = resp.get('LastEvaluatedKey')
        if not last_key:
            break
        query_args['ExclusiveStartKey'] = last_key
    return records


def index_activity_snapshot(items: List[Dict[str, Any]]) -> Dict[str, Dict[str, Dict[str, Any]]]:
    indexed: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    for item in items:
        email = item.get("email")
        activity_date = item.get("activity_date")
        if email and activity_date:
            indexed[str(email)][str(activity_date)] = item
    return indexed


def _conditional_max_update(item: Dict[str, Any], field: str) -> bool:
    """Atomically raise one numeric field, never lower it, and preserve other attributes."""
    value = int(item[field])
    try:
        controller.UserActivityTable.update_item(
            Key={
                "email": item["email"],
                "activity_date": item["activity_date"],
            },
            UpdateExpression="SET #field = :value, updated_at = :updated_at",
            ConditionExpression="attribute_not_exists(#field) OR #field < :value",
            ExpressionAttributeNames={"#field": field},
            ExpressionAttributeValues={
                ":value": value,
                ":updated_at": item["updated_at"],
            },
        )
        return True
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return False
        raise


def write_activity_max(item: Dict[str, Any]) -> bool:
    """Merge an activity item with atomic maxima; safe alongside live ADD updates."""
    questions_changed = _conditional_max_update(item, "questions_completed")
    sets_changed = _conditional_max_update(item, "sets_completed")
    return questions_changed or sets_changed


def backfill(
    target_email: Optional[str] = None,
    apply_changes: bool = False,
    goal: int = DEFAULT_STREAK_GOAL,
    verbose: bool = False,
    existing_activity_snapshot: Optional[List[Dict[str, Any]]] = None,
) -> int:
    """Main backfill execution routine."""
    print("=" * 70)
    print("PSYMOAT: USER SUBMISSION HISTORY -> ACTIVITY & STREAK BACKFILL")
    print("=" * 70)
    mode_str = "APPLY (WRITING TO DYNAMODB)" if apply_changes else "DRY-RUN (PREVIEW ONLY, NO WRITES)"
    print(f"Mode: {mode_str}")
    if target_email:
        print(f"Target user: {target_email}")
    else:
        print("Target user: ALL USERS")
    print(f"Daily Question Goal: {goal}")
    print("Write Strategy: ATOMIC MAX MERGE (never lowers existing counts)")
    print("-" * 70)

    # 1. Fetch user mapping
    users_by_email, user_id_to_email = fetch_registered_users(target_email)
    canonical_email_by_fold = {email.casefold(): email for email in users_by_email}
    if target_email and users_by_email:
        target_email = next(iter(users_by_email))
    print(f"Found {len(users_by_email)} user record(s) in UserTable.")

    # 2. Collect quiz submissions from QNAHistory
    qna_data, _ = collect_qna_history(
        target_email, user_id_to_email, canonical_email_by_fold
    )

    # 3. Collect mock test submissions from TestsSolvedUserData
    tests_data, _ = collect_tests_history(target_email, canonical_email_by_fold)

    # 4. Fallback: check UserTable tests_submitted
    collect_user_table_fallback(users_by_email, tests_data)

    # 5. Determine the full set of emails with submissions or requested email
    target_emails: Set[str] = set()
    if target_email:
        target_emails.add(target_email.strip())
    else:
        target_emails.update(qna_data.keys())
        target_emails.update(tests_data.keys())
        # Also include all registered users so we inspect their streak stats
        target_emails.update(users_by_email.keys())

    sorted_emails = sorted(target_emails)
    print(f"\n[3/3] Aggregating activity and preparing updates for {len(sorted_emails)} user(s)...")
    print("-" * 70)

    total_records_written = 0
    total_records_skipped = 0
    users_with_activity = 0
    snapshot_by_email = (
        index_activity_snapshot(existing_activity_snapshot)
        if existing_activity_snapshot is not None
        else None
    )

    for email in sorted_emails:
        user_qna = qna_data.get(email, {})
        user_tests = tests_data.get(email, {})

        all_active_dates = set(user_qna.keys()) | set(user_tests.keys())
        if not all_active_dates:
            if target_email or verbose:
                print(f"• User: {email} - No historical submission records found.")
            continue

        users_with_activity += 1

        # Fetch existing UserActivity records
        existing_records = (
            snapshot_by_email.get(email, {})
            if snapshot_by_email is not None
            else fetch_existing_user_activity(email)
        )
        existing_daily = {
            d: int(item.get('questions_completed', 0))
            for d, item in existing_records.items()
        }
        stats_before = calculate_streak_stats(existing_daily, goal=goal)

        # Merge historical submissions per date
        computed_daily: Dict[str, Dict[str, int]] = {}
        for d in sorted(all_active_dates):
            q_qna = user_qna.get(d, {}).get('questions', 0)
            batches_qna = len(user_qna.get(d, {}).get('batches', set()))

            q_test = user_tests.get(d, {}).get('questions', 0)
            count_test = user_tests.get(d, {}).get('tests_count', 0)

            total_q = q_qna + q_test
            total_sets = max(1 if total_q > 0 else 0, batches_qna + count_test)

            if total_q <= 0:
                continue

            computed_daily[d] = {
                'questions_completed': total_q,
                'sets_completed': total_sets,
            }

        # Calculate final daily map
        final_daily_questions: Dict[str, int] = {}
        items_to_write: List[Dict[str, Any]] = []

        now_ist = datetime.now(IST).isoformat(timespec='seconds')

        # Combine all dates (existing + computed)
        all_dates_combined = set(existing_records.keys()) | set(computed_daily.keys())
        for d in sorted(all_dates_combined):
            comp = computed_daily.get(d)
            exist = existing_records.get(d)

            if not exist:
                if comp:
                    final_q = comp['questions_completed']
                    final_s = comp['sets_completed']
                else:
                    final_q = int(exist.get('questions_completed', 0)) if exist else 0
                    final_s = int(exist.get('sets_completed', 0)) if exist else 0
            else:
                # Merge mode: take max so existing progress is never lost
                exist_q = int(exist.get('questions_completed', 0))
                exist_s = int(exist.get('sets_completed', 0))
                comp_q = comp['questions_completed'] if comp else 0
                comp_s = comp['sets_completed'] if comp else 0

                final_q = max(exist_q, comp_q)
                final_s = max(exist_s, comp_s)

            final_daily_questions[d] = final_q

            # Check if write is needed
            if exist:
                curr_q = int(exist.get('questions_completed', 0))
                curr_s = int(exist.get('sets_completed', 0))
                if curr_q == final_q and curr_s == final_s:
                    total_records_skipped += 1
                    continue

            items_to_write.append({
                'email': email,
                'activity_date': d,
                'questions_completed': final_q,
                'sets_completed': final_s,
                'updated_at': now_ist,
            })

        stats_after = calculate_streak_stats(final_daily_questions, goal=goal)

        user_name = users_by_email.get(email, {}).get('fullName', '')
        display_name = f"{user_name} ({email})" if user_name else email

        if verbose or target_email:
            print(f"\nUser: {display_name}")
            print(f"  Dates active: {len(all_active_dates)} | Dates to update: {len(items_to_write)}")
            print(f"  Streak Before: Current={stats_before['current_streak']}, Longest={stats_before['longest_streak']}, Questions={stats_before['total_questions']}")
            print(f"  Streak After:  Current={stats_after['current_streak']}, Longest={stats_after['longest_streak']}, Questions={stats_after['total_questions']}")

        if verbose:
            for d in sorted(computed_daily.keys()):
                info = computed_daily[d]
                print(f"    - {d}: {info['questions_completed']} questions ({info['sets_completed']} set(s))")

        # Apply writes if requested
        if apply_changes and items_to_write:
            for item in items_to_write:
                try:
                    if write_activity_max(item):
                        total_records_written += 1
                    else:
                        total_records_skipped += 1
                    time.sleep(0.01)  # small throttle to stay within DynamoDB limits
                except Exception as write_err:
                    raise MigrationError(
                        f"Failed writing {email} on {item['activity_date']}: {write_err}"
                    ) from write_err
        elif not apply_changes:
            total_records_written += len(items_to_write)

    print("\n" + "=" * 70)
    print("BACKFILL SUMMARY")
    print("=" * 70)
    print(f"Users evaluated:           {len(sorted_emails)}")
    print(f"Users with submission data: {users_with_activity}")
    if apply_changes:
        print(f"Records written:           {total_records_written}")
        print(f"Records already up-to-date:{total_records_skipped}")
        print("Status:                    SUCCESSFULLY COMMITTED TO DYNAMODB")
    else:
        print(f"Records pending write:     {total_records_written}")
        print(f"Records already up-to-date:{total_records_skipped}")
        print("Status:                    DRY RUN COMPLETED - NO WRITES MADE")
    print("=" * 70)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert historical Psymoat submissions into UserActivity and streak data."
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--email",
        type=str,
        default=None,
        help="Target exactly one user by email."
    )
    scope.add_argument(
        "--all-users",
        action="store_true",
        help="Explicitly target all users. Required for an all-user apply."
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Back up UserActivity locally, then atomically merge the backfill."
    )
    action.add_argument(
        "--backup-only",
        action="store_true",
        help="Create a local backup without running the backfill."
    )
    action.add_argument(
        "--restore-backup",
        type=Path,
        help="Restore UserActivity to an exact local backup (maintenance window only)."
    )
    parser.add_argument(
        "--confirm-account-id",
        help="Required for writes; must exactly match the table ARN's 12-digit AWS account ID."
    )
    parser.add_argument(
        "--confirm-restore",
        choices=["RESTORE"],
        help="Required with --restore-backup to acknowledge replacement/deletion of table items."
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "backups" / "user_activity",
        help="Directory for compressed local backups."
    )
    parser.add_argument(
        "--goal",
        type=int,
        default=DEFAULT_STREAK_GOAL,
        help=f"Daily question goal for streak calculations (default: {DEFAULT_STREAK_GOAL})."
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show per-day submission breakdowns."
    )

    args = parser.parse_args()

    try:
        if args.goal <= 0:
            raise MigrationError("--goal must be greater than zero")

        target = inspect_target()
        print(f"DynamoDB target: {target['table_arn']}")

        if args.restore_backup:
            require_target_confirmation(target, args.confirm_account_id)
            if args.confirm_restore != "RESTORE":
                raise MigrationError("--restore-backup also requires --confirm-restore RESTORE")
            restored, deleted = restore_local_backup(args.restore_backup, target)
            print(
                f"Restored {restored} backed-up item(s) and removed {deleted} post-backup item(s)."
            )
            return 0

        if args.backup_only:
            backup_path = create_local_backup(target, args.backup_dir)
            verified = load_local_backup(backup_path)
            print(f"Backup verified: {backup_path} ({verified['item_count']} item(s))")
            return 0

        if not args.email and not args.all_users:
            raise MigrationError("Choose --email USER or --all-users explicitly")

        snapshot: Optional[List[Dict[str, Any]]] = None
        if args.apply:
            require_target_confirmation(target, args.confirm_account_id)
            backup_path = create_local_backup(target, args.backup_dir)
            verified = load_local_backup(backup_path)
            snapshot = verified["items"]
            print(f"Pre-write backup verified: {backup_path} ({verified['item_count']} item(s))")

        return backfill(
            target_email=args.email,
            apply_changes=args.apply,
            goal=args.goal,
            verbose=args.verbose,
            existing_activity_snapshot=snapshot,
        )
    except (ClientError, MigrationError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
