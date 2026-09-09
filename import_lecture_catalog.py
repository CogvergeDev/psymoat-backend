"""Dry-run first, additive import of an explicitly approved catalog manifest.

No Lecture or Module writes. Run with --manifest FILE --report REPORT.
Add --apply --backup BACKUP only after the manifest and reconciliation are approved.
"""
import argparse
import json
from pathlib import Path
from collections import Counter
from boto3.dynamodb.conditions import Key

from lecture_catalog import Catalog, identifier, label, number, public


def validate_manifest(data):
    exam = identifier(data.get("exam_id"))
    lookup = {}
    for kind in ("folders", "sections", "units"):
        items = data.get(kind, [])
        ids = [identifier(item.get("id")) for item in items]
        if len(set(ids)) != len(ids):
            raise ValueError(f"Duplicate {kind} IDs")
        lookup[kind] = set(ids)
        for item in items:
            label(item.get("name")); number(item.get("order"))
    for unit in data["units"]:
        if unit.get("section_id") not in lookup["sections"]:
            raise ValueError("Unit references an unknown section")
    ids = set()
    for item in data.get("lectures", []):
        lid = identifier(item.get("lecture_id"))
        if lid in ids:
            raise ValueError(f"Duplicate lecture ID: {lid}")
        ids.add(lid)
        if item.get("exam_id") != exam:
            raise ValueError("Lecture exam does not match the manifest")
        for kind, field in (("folders", "folder_id"), ("sections", "section_id")):
            if item.get(field) not in lookup[kind]:
                raise ValueError(f"Lecture {lid} references an unknown {field}")
        unit_id = item.get("unit_id")
        if unit_id not in (None, ""):
            if unit_id not in lookup["units"]:
                raise ValueError(f"Lecture {lid} references an unknown unit_id")
            unit = next(u for u in data["units"] if u["id"] == unit_id)
            if unit["section_id"] != item["section_id"]:
                raise ValueError(f"Lecture {lid} has a unit/section mismatch")
        label(item.get("display_title")); number(item.get("order")); number(item.get("lecture_number"), None)
    return exam


def reconcile(data, catalog):
    exam = validate_manifest(data)
    catalog.require_exam(exam)
    missing, wrong_exam, no_video, conflicts, metadata_conflicts = [], [], [], [], []
    for kind in ("folders", "sections", "units"):
        for entity in data[kind]:
            existing = catalog.entity(exam, kind, entity["id"])
            if existing and any(existing.get(k) != v for k, v in entity.items()):
                metadata_conflicts.append(f"{kind}/{entity['id']}")
    for p in data["lectures"]:
        item = catalog.db.LectureTable.get_item(Key={"lecture_id": p["lecture_id"]}, ConsistentRead=True).get("Item")
        if not item:
            missing.append(p["lecture_id"])
        elif item.get("exam_id") != exam:
            wrong_exam.append(p["lecture_id"])
        elif not item.get("yt_link"):
            no_video.append(p["lecture_id"])
        old = catalog.placement(p["lecture_id"])
        expected = {k: p.get(k) for k in ("exam_id", "folder_id", "section_id", "unit_id", "display_title", "lecture_number", "order")}
        if old and any(old.get(k) != v for k, v in expected.items()):
            conflicts.append(p["lecture_id"])
    args = {"IndexName": "ExamUpcomingLecturesIndex", "KeyConditionExpression": Key("exam_id").eq(exam),
            "ProjectionExpression": "lecture_id, yt_link, date_time_of_zoom_lec"}
    live = []
    while True:
        result = catalog.db.LectureTable.query(**args)
        live.extend(result.get("Items", []))
        if not result.get("LastEvaluatedKey"): break
        args["ExclusiveStartKey"] = result["LastEvaluatedKey"]
    supplied = {x["lecture_id"] for x in data["lectures"]}
    database_only = sorted(x["lecture_id"] for x in live if x.get("yt_link") and x["lecture_id"] not in supplied)
    accepted_extra = set(data.get("acknowledged_database_only_ids", []))
    return {"exam_id": exam, "lecture_count": len(supplied), "folder_counts": dict(Counter(x["folder_id"] for x in data["lectures"])),
            "missing_ids": missing, "wrong_exam_ids": wrong_exam, "no_video_ids": no_video,
            "conflicting_existing_placements": conflicts, "conflicting_catalog_entries": metadata_conflicts, "database_only_ids": database_only,
            "unresolved_database_only_ids": sorted(set(database_only) - accepted_extra),
            "approved": data.get("approved") is True and all(x.get("approved") is True for x in data["lectures"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--backup")
    args = parser.parse_args()
    from dotenv import load_dotenv
    load_dotenv()
    import controller
    data = json.loads(Path(args.manifest).read_text())
    catalog = Catalog(controller)
    report = reconcile(data, catalog)
    Path(args.report).write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if not args.apply:
        print("Dry run only. No database writes.")
        return
    if not args.backup or not report["approved"]:
        raise ValueError("Apply requires an approved manifest, every lecture approved, and --backup")
    if any(report[key] for key in ("missing_ids", "wrong_exam_ids", "no_video_ids", "conflicting_existing_placements", "conflicting_catalog_entries", "unresolved_database_only_ids")):
        raise ValueError("Resolve the reconciliation issues before import")
    exam = data["exam_id"]
    before = catalog.query(f"EXAM#{exam}")
    for folder in data["folders"]:
        before.extend(catalog.query(f"FOLDER#{exam}#{folder['id']}"))
    for p in data["lectures"]:
        old = catalog.get(f"LECTURE#{p['lecture_id']}", "PLACEMENT")
        if old: before.append(old)
    # Exclusive creation prevents overwriting a previous backup on retries.
    with open(args.backup, "x") as handle:
        json.dump(before, handle, default=str, indent=2)
    for kind in ("folders", "sections", "units"):
        for entity in data[kind]:
            existing = catalog.entity(exam, kind, entity["id"])
            if existing:
                if any(existing.get(k) != v for k, v in entity.items()):
                    raise ValueError(f"Existing {kind} entry differs: {entity['id']}. Review it in God Mode.")
            else:
                catalog.save_entity(exam, kind, entity, entity["id"])
    for p in data["lectures"]:
        if catalog.placement(p["lecture_id"]):
            continue  # Reconciliation established equality; never duplicate counts.
        catalog.assign(p["lecture_id"], exam, p)
    counts = {x["id"]: x.get("lecture_count", 0) for x in catalog.metadata(exam)["folders"]}
    for folder, count in report["folder_counts"].items():
        if counts.get(folder) != count:
            raise RuntimeError(f"Folder count mismatch after import: {folder}")
    print("Approved catalog imported. Original Lecture and Module records are unchanged.")


if __name__ == "__main__":
    main()
