"""Additive lecture catalog. Existing Lecture/Module records keep their identities.

All student queries are scoped to an exam or a folder partition. Catalog writes
use transactions so placement pointers and folder counts cannot drift on moves.
"""
import os
import secrets
from datetime import datetime
from functools import wraps
from decimal import Decimal

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required


def identifier(value):
    value = str(value or "").strip()
    if not value or len(value) > 100 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in value):
        raise ValueError("Invalid catalog identifier")
    return value


def label(value):
    value = str(value or "").strip()
    if not value or len(value) > 250:
        raise ValueError("A name of 1–250 characters is required")
    return value


def number(value, default=0):
    if value is None or value == "":
        return default
    try:
        parsed = Decimal(str(value))
    except Exception as exc:
        raise ValueError("A valid whole number is required") from exc
    if not parsed.is_finite() or parsed != int(parsed) or not 0 <= parsed <= 999999:
        raise ValueError("Order and lecture numbers must be whole numbers from 0 to 999999")
    return int(parsed)


def placement_sort_key(item, lecture_id):
    """Build a non-colliding DynamoDB key for unit and unitless lectures."""
    unit_id = item.get("unit_id") or "~"
    return f"LECTURE#{item['section_id']}#{unit_id}#{lecture_id}"


def public(item):
    def convert(value):
        if isinstance(value, Decimal):
            return int(value) if value == int(value) else float(value)
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        if isinstance(value, list):
            return [convert(v) for v in value]
        return value
    return {k: convert(v) for k, v in item.items() if k not in ("pk", "sk")}


class Catalog:
    def __init__(self, db):
        self.db = db
        self.table = db.dynamodb_resource.Table(os.getenv("LECTURE_CATALOG_TABLE", "LectureCatalog"))

    def get(self, pk, sk):
        return self.table.get_item(Key={"pk": pk, "sk": sk}, ConsistentRead=True).get("Item")

    def query(self, pk, prefix=""):
        condition = Key("pk").eq(pk)
        if prefix:
            condition &= Key("sk").begins_with(prefix)
        args = {"KeyConditionExpression": condition, "ConsistentRead": True}
        items = []
        while True:
            result = self.table.query(**args)
            items.extend(result.get("Items", []))
            if not result.get("LastEvaluatedKey"):
                return items
            args["ExclusiveStartKey"] = result["LastEvaluatedKey"]

    def exams(self):
        args, items = {}, []
        while True:
            response = self.db.ExamTable.scan(**args)
            items.extend(response.get("Items", []))
            if not response.get("LastEvaluatedKey"):
                break
            args["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        # Preserve the existing exam picker's exclusion of the internal test exam.
        return sorted([{"id": x["exam_id"], "name": x["exam_name"], "active": x.get("catalog_active", x["exam_id"] != "BYP0UD")} for x in items], key=lambda x: x["name"].casefold())

    def require_exam(self, exam):
        item = self.db.ExamTable.get_item(Key={"exam_id": identifier(exam)}, ConsistentRead=True).get("Item")
        if not item:
            raise ValueError("Exam does not exist")
        return item

    def metadata(self, exam):
        self.require_exam(exam)
        rows = self.query(f"EXAM#{exam}")
        result = {"folders": [], "sections": [], "units": []}
        for item in rows:
            if item.get("kind") in result:
                result[item["kind"]].append(public(item))
        for values in result.values():
            values.sort(key=lambda x: (x.get("order", 0), x["name"].casefold(), x["id"]))
        return result

    def entity(self, exam, kind, entity_id):
        identifier(exam)
        if kind not in ("folders", "sections", "units"):
            raise ValueError("Unknown catalog entity")
        return self.get(f"EXAM#{exam}", f"{kind}#{identifier(entity_id)}")

    def save_entity(self, exam, kind, data, entity_id=None):
        self.require_exam(exam)
        if kind not in ("folders", "sections", "units"):
            raise ValueError("Unknown catalog entity")
        entity_id = identifier(entity_id or secrets.token_hex(6))
        old = self.entity(exam, kind, entity_id)
        item = {"pk": f"EXAM#{exam}", "sk": f"{kind}#{entity_id}", "kind": kind, "id": entity_id,
                "name": label(data.get("name")), "order": number(data.get("order")), "exam_id": exam}
        if kind == "folders":
            item.update(description=str(data.get("description", ""))[:1000], icon=str(data.get("icon", "📚"))[:20],
                        active=data.get("active", True) is True)
        if kind == "units":
            section_id = identifier(data.get("section_id"))
            if not self.entity(exam, "sections", section_id):
                raise ValueError("Select a section belonging to this exam")
            if old and old["section_id"] != section_id and self.references(exam, kind, entity_id):
                raise ValueError("Move this unit's lectures before changing its section")
            item.update(section_id=section_id, syllabus_number=number(data.get("syllabus_number"), None))
        # Update only editable attributes, preserving counters changed by concurrent assignments.
        keys = [k for k in item if k not in ("pk", "sk")]
        self.table.update_item(Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET " + ", ".join(f"#f{i} = :v{i}" for i in range(len(keys))),
            ExpressionAttributeNames={f"#f{i}": k for i, k in enumerate(keys)},
            ExpressionAttributeValues={f":v{i}": item[k] for i, k in enumerate(keys)})
        return public(self.entity(exam, kind, entity_id))

    def references(self, exam, kind, entity_id):
        field = {"folders": "folder_id", "sections": "section_id", "units": "unit_id"}[kind]
        for folder in self.metadata(exam)["folders"]:
            if any(row.get(field) == entity_id for row in self.query(f"FOLDER#{exam}#{folder['id']}", "LECTURE#")):
                return True
        return False

    def delete_entity(self, exam, kind, entity_id):
        if not self.entity(exam, kind, entity_id):
            raise ValueError("Catalog entry does not exist")
        if kind == "sections" and any(u["section_id"] == entity_id for u in self.metadata(exam)["units"]):
            raise ValueError("Move or remove the section's units first")
        if self.references(exam, kind, entity_id):
            raise ValueError("Move the lectures first. Populated entries cannot be deleted; folders can be hidden instead.")
        self.table.delete_item(Key={"pk": f"EXAM#{exam}", "sk": f"{kind}#{entity_id}"})

    def placement(self, lecture_id):
        item = self.get(f"LECTURE#{identifier(lecture_id)}", "PLACEMENT")
        return public(item) if item else None

    def validate_placement(self, exam, data):
        self.require_exam(exam)
        folder = self.entity(exam, "folders", data.get("folder_id"))
        section = self.entity(exam, "sections", data.get("section_id"))
        unit_id = data.get("unit_id")
        unit = self.entity(exam, "units", unit_id) if unit_id else None
        if not folder or not section or (unit_id and not unit):
            raise ValueError("Choose an existing folder and section, plus a valid unit when one is selected")
        if unit and unit["section_id"] != section["id"]:
            raise ValueError("The unit belongs to another section")
        return {"exam_id": exam, "folder_id": folder["id"], "section_id": section["id"], "unit_id": unit["id"] if unit else None,
                "display_title": label(data.get("display_title")), "lecture_number": number(data.get("lecture_number"), None),
                "order": number(data.get("order"))}

    def assign(self, lecture_id, exam, data, lecture=None, extra_ops=None):
        lecture_id = identifier(lecture_id)
        item = self.validate_placement(exam, data)
        lecture = lecture or self.db.LectureTable.get_item(Key={"lecture_id": lecture_id}, ConsistentRead=True).get("Item")
        if not lecture or lecture.get("exam_id") != exam:
            raise ValueError("Lecture does not exist in the selected exam")
        if not lecture.get("yt_link"):
            raise ValueError("A recording must have a video before it can be placed in a folder")
        old = self.placement(lecture_id)
        version = int(old.get("version", 0)) if old else 0
        item.update(lecture_id=lecture_id, version=version + 1)
        pk = f"FOLDER#{exam}#{item['folder_id']}"
        sk = placement_sort_key(item, lecture_id)
        pointer = dict(item, pk=f"LECTURE#{lecture_id}", sk="PLACEMENT")
        condition = {"ConditionExpression": "attribute_not_exists(pk)"} if not old else {
            "ConditionExpression": "#v = :v", "ExpressionAttributeNames": {"#v": "version"}, "ExpressionAttributeValues": {":v": version}}
        ops = [{"Put": {"TableName": self.table.name, "Item": pointer, **condition}},
               {"Put": {"TableName": self.table.name, "Item": dict(item, pk=pk, sk=sk)}}]
        old_pk = f"FOLDER#{old['exam_id']}#{old['folder_id']}" if old else None
        old_sk = placement_sort_key(old, lecture_id) if old else None
        if old and (pk, sk) != (old_pk, old_sk):
            ops.append({"Delete": {"TableName": self.table.name, "Key": {"pk": old_pk, "sk": old_sk}}})
        if pk != old_pk:
            for value, delta in ((item, 1), (old, -1)):
                if value:
                    ops.append({"Update": {"TableName": self.table.name,
                        "Key": {"pk": f"EXAM#{value['exam_id']}", "sk": f"folders#{value['folder_id']}"},
                        "UpdateExpression": "ADD lecture_count :delta", "ExpressionAttributeValues": {":delta": delta},
                        "ConditionExpression": "attribute_exists(pk)"}})
        self.db.dynamodb_resource.meta.client.transact_write_items(TransactItems=ops + (extra_ops or []))
        return item

    def save_lecture(self, data, lecture_id=None):
        """Atomically save the recording, catalog placement and legacy module list."""
        old = self.db.LectureTable.get_item(Key={"lecture_id": identifier(lecture_id)}, ConsistentRead=True).get("Item") if lecture_id else None
        if lecture_id and not old:
            raise ValueError("Lecture does not exist")
        lecture_id = lecture_id or self.db.generate_id()
        fields = ("category", "title", "instructor_details", "key_topics", "description", "zoom_link", "exam_id", "module_id", "notes_markdown", "duration")
        item = dict(old or {}, lecture_id=lecture_id)
        item.update({k: data[k] for k in fields if k in data})
        item["exam_id"] = identifier(item.get("exam_id"))
        item["title"] = label(item.get("title"))
        item["date_time_of_zoom_lec"] = datetime.fromisoformat(data.get("date_time_of_zoom_lec", "")).replace(microsecond=0).isoformat()
        item["yt_link"] = self.db.normalize_yt_link_to_key(str(data.get("yt_link", "")))
        if not item["yt_link"]:
            raise ValueError("A video is required for a recorded lecture")
        if not isinstance(item.get("instructor_details"), dict):
            raise ValueError("Instructor details are required")
        placement = data.get("catalog")
        if not placement:
            raise ValueError("Choose a folder and section")
        self.validate_placement(item["exam_id"], placement)
        old_module = (old or {}).get("module_id")
        new_module = item.get("module_id")
        ops = []
        if new_module:
            exam = self.require_exam(item["exam_id"])
            if new_module not in exam.get("modules", []):
                raise ValueError("Learning module does not belong to this exam")
        if old_module != new_module:
            for module_id, adding in ((old_module, False), (new_module, True)):
                if not module_id:
                    continue
                module = self.db.ModuleTable.get_item(Key={"module_id": module_id}, ConsistentRead=True).get("Item")
                if not module:
                    raise ValueError("Learning module does not exist")
                before = module.get("lectures", [])
                after = [x for x in before if x != lecture_id] + ([lecture_id] if adding else [])
                values = {":after": after}
                condition = "attribute_not_exists(lectures)"
                if "lectures" in module:
                    condition = "lectures = :before"
                    values[":before"] = before
                ops.append({"Update": {"TableName": self.db.ModuleTable.name, "Key": {"module_id": module_id},
                    "UpdateExpression": "SET lectures = :after", "ConditionExpression": condition, "ExpressionAttributeValues": values}})
        revision = int((old or {}).get("catalog_revision", 0))
        item["catalog_revision"] = revision + 1
        condition = {"ConditionExpression": "attribute_not_exists(lecture_id)"}
        if old:
            # Check all original editable fields: legacy writers do not increment catalog_revision.
            checked = list(dict.fromkeys([*fields, "yt_link", "date_time_of_zoom_lec", "catalog_revision"]))
            expressions, names, values = [], {}, {}
            for i, field in enumerate(checked):
                names[f"#f{i}"] = field
                if field in old:
                    expressions.append(f"#f{i} = :v{i}")
                    values[f":v{i}"] = old[field]
                else:
                    expressions.append(f"attribute_not_exists(#f{i})")
            condition = {"ConditionExpression": " AND ".join(expressions), "ExpressionAttributeNames": names, "ExpressionAttributeValues": values}
        ops.append({"Put": {"TableName": self.db.LectureTable.name, "Item": item, **condition}})
        self.assign(lecture_id, item["exam_id"], placement, lecture=item, extra_ops=ops)
        return lecture_id

    def folder_content(self, exam, folder_id, section_id=None, search="", admin=False):
        meta = self.metadata(exam)
        folder = next((f for f in meta["folders"] if f["id"] == folder_id), None)
        if not folder or (not admin and not folder.get("active", True)):
            raise ValueError("Folder is unavailable")
        prefix = f"LECTURE#{identifier(section_id)}#" if section_id else "LECTURE#"
        placements = self.query(f"FOLDER#{exam}#{identifier(folder_id)}", prefix)
        # Batch only this folder/section's IDs; never read the entire exam's lectures.
        lectures = {}
        for offset in range(0, len(placements), 100):
            pending = {self.db.LectureTable.name: {"Keys": [{"lecture_id": x["lecture_id"]} for x in placements[offset:offset + 100]],
                "ProjectionExpression": "lecture_id, exam_id, title, instructor_details, date_time_of_zoom_lec, yt_link"}}
            for attempt in range(5):
                response = self.db.dynamodb_resource.batch_get_item(RequestItems=pending)
                lectures.update({x["lecture_id"]: x for x in response.get("Responses", {}).get(self.db.LectureTable.name, [])})
                pending = response.get("UnprocessedKeys", {})
                if not pending:
                    break
            if pending:
                raise RuntimeError("Some recordings could not be loaded. Please retry.")
        units = {x["id"]: x for x in meta["units"]}
        sections = {x["id"]: x for x in meta["sections"]}
        result = []
        for p in placements:
            lecture = lectures.get(p["lecture_id"])
            if not lecture or lecture.get("exam_id") != exam:
                continue
            # Catalog placement is explicit; only an actual video makes it playable.
            if not admin and not lecture.get("yt_link"):
                continue
            title = p["display_title"]
            instructor = lecture.get("instructor_details") or {}
            if search.casefold() not in f"{title} {instructor.get('name', '')} {units.get(p.get('unit_id'), {}).get('name', '')}".casefold():
                continue
            result.append(dict(public(p), title=title, instructor_details=instructor,
                               date_time_of_zoom_lec=lecture.get("date_time_of_zoom_lec"), available=bool(lecture.get("yt_link"))))
        result.sort(key=lambda x: (sections.get(x["section_id"], {}).get("order", 0), units.get(x.get("unit_id"), {}).get("order", 0),
                                   x.get("unit_id") or "", x["order"], x["lecture_number"] or 0, x["lecture_id"]))
        if not admin:
            meta["folders"] = [f for f in meta["folders"] if f.get("active", True)]
        return dict(meta, folder=folder, lectures=result)

    def delete_lecture(self, lecture_id):
        lecture_id = identifier(lecture_id)
        lecture = self.db.LectureTable.get_item(Key={"lecture_id": lecture_id}, ConsistentRead=True).get("Item")
        if not lecture:
            raise ValueError("Lecture does not exist")
        ops = [{"Delete": {"TableName": self.db.LectureTable.name, "Key": {"lecture_id": lecture_id}}}]
        p = self.placement(lecture_id)
        if p:
            ops.extend([
                {"Delete": {"TableName": self.table.name, "Key": {"pk": f"LECTURE#{lecture_id}", "sk": "PLACEMENT"},
                    "ConditionExpression": "#v = :v", "ExpressionAttributeNames": {"#v": "version"}, "ExpressionAttributeValues": {":v": p["version"]}}},
                {"Delete": {"TableName": self.table.name, "Key": {"pk": f"FOLDER#{p['exam_id']}#{p['folder_id']}", "sk": placement_sort_key(p, lecture_id)}}},
                {"Update": {"TableName": self.table.name, "Key": {"pk": f"EXAM#{p['exam_id']}", "sk": f"folders#{p['folder_id']}"},
                    "UpdateExpression": "ADD lecture_count :delta", "ExpressionAttributeValues": {":delta": -1}}},
            ])
        module_id = lecture.get("module_id")
        if module_id:
            module = self.db.ModuleTable.get_item(Key={"module_id": module_id}, ConsistentRead=True).get("Item")
            if module and lecture_id in module.get("lectures", []):
                ops.append({"Update": {"TableName": self.db.ModuleTable.name, "Key": {"module_id": module_id},
                    "UpdateExpression": "SET lectures = :after", "ConditionExpression": "lectures = :before",
                    "ExpressionAttributeValues": {":before": module["lectures"], ":after": [x for x in module["lectures"] if x != lecture_id]}}})
        self.db.dynamodb_resource.meta.client.transact_write_items(TransactItems=ops)


def create_catalog_blueprint(db):
    bp = Blueprint("lecture_catalog", __name__)
    catalog = Catalog(db)

    def admin_required(fn):
        @wraps(fn)
        @jwt_required()
        def wrapped(*args, **kwargs):
            allowed = {email.strip().casefold() for email in os.getenv("CATALOG_ADMIN_EMAILS", "").split(",") if email.strip()}
            if str(get_jwt_identity()).casefold() not in allowed:
                return jsonify(message="Your signed-in account is not enabled for catalog administration."), 403
            return fn(*args, **kwargs)
        return wrapped

    @bp.errorhandler(ValueError)
    def invalid(error):
        return jsonify(message=str(error)), 400

    @bp.errorhandler(ClientError)
    def database_error(error):
        code = error.response.get("Error", {}).get("Code")
        if code in ("TransactionCanceledException", "ConditionalCheckFailedException"):
            return jsonify(message="This entry changed during saving. Reload and try again."), 409
        return jsonify(message="The lecture catalog is not available. Please retry or contact an administrator."), 503

    @bp.errorhandler(RuntimeError)
    def temporarily_unavailable(error):
        return jsonify(message=str(error)), 503

    @bp.get("/catalog/exams")
    def exams():
        return jsonify(exams=[e for e in catalog.exams() if e["active"]])

    @bp.get("/catalog/<exam>/folders")
    def folders(exam):
        return jsonify(folders=[f for f in catalog.metadata(exam)["folders"] if f.get("active", True)])

    @bp.get("/catalog/<exam>/folders/<folder>")
    def recordings(exam, folder):
        return jsonify(catalog.folder_content(exam, folder, request.args.get("section"), request.args.get("q", "")))

    @bp.get("/catalog/lectures/<lecture_id>/placement")
    def placement(lecture_id):
        return jsonify(placement=catalog.placement(lecture_id))

    @bp.get("/catalog/admin/<exam>")
    @admin_required
    def admin_metadata(exam):
        meta = catalog.metadata(exam)
        existing = db.get_modules_by_exam_id(exam).get("modules", [])
        return jsonify(**meta, modules=existing)

    @bp.post("/catalog/admin/exams")
    @admin_required
    def create_exam():
        name = label(request.get_json().get("name"))
        result = db.initialize_new_exam(name)
        if result.get("status") != "success":
            raise ValueError("Exam could not be created")
        return jsonify(id=result["exam_id"], name=name), 201

    @bp.put("/catalog/admin/exams/<exam>")
    @admin_required
    def edit_exam(exam):
        catalog.require_exam(exam)
        data = request.get_json()
        db.ExamTable.update_item(Key={"exam_id": exam}, UpdateExpression="SET exam_name = :name",
                                 ExpressionAttributeValues={":name": label(data.get("name"))})
        return jsonify(status="success")

    @bp.post("/catalog/admin/<exam>/<kind>")
    @admin_required
    def create_entity(exam, kind):
        return jsonify(entity=catalog.save_entity(exam, kind, request.get_json())), 201

    @bp.put("/catalog/admin/<exam>/<kind>/<entity_id>")
    @admin_required
    def edit_entity(exam, kind, entity_id):
        return jsonify(entity=catalog.save_entity(exam, kind, request.get_json(), entity_id))

    @bp.delete("/catalog/admin/<exam>/<kind>/<entity_id>")
    @admin_required
    def delete_entity(exam, kind, entity_id):
        catalog.delete_entity(exam, kind, entity_id)
        return jsonify(status="success")

    @bp.put("/catalog/admin/lectures/<lecture_id>/placement")
    @admin_required
    def save_placement(lecture_id):
        data = request.get_json()
        return jsonify(placement=catalog.assign(lecture_id, identifier(data.get("exam_id")), data))

    @bp.post("/catalog/admin/lectures")
    @admin_required
    def add_lecture():
        return jsonify(lecture_id=catalog.save_lecture(request.get_json()), status="success"), 201

    @bp.put("/catalog/admin/lectures/<lecture_id>")
    @admin_required
    def edit_lecture(lecture_id):
        catalog.save_lecture(request.get_json(), lecture_id)
        return jsonify(lecture_id=lecture_id, status="success")

    @bp.delete("/catalog/admin/lectures/<lecture_id>")
    @admin_required
    def delete_lecture(lecture_id):
        catalog.delete_lecture(lecture_id)
        return jsonify(status="success")

    return bp
