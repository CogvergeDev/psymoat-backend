"""Backfill module difficulty counts or verify them against the legacy reader."""

import argparse
import secrets

from botocore.exceptions import ClientError

import controller as db


def scan_items(table, **options):
    while True:
        page = table.scan(ConsistentRead=True, **options)
        yield from page.get("Items", [])
        if not page.get("LastEvaluatedKey"):
            break
        options["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def module_snapshots():
    modules = {
        module["module_id"]: module
        for module in scan_items(db.ModuleTable, ProjectionExpression="module_id, questionBankRevision")
    }
    for module_id in modules:
        parts = module_id.split("_")
        if any("_".join(parts[:end]) in modules for end in range(1, len(parts))):
            raise RuntimeError(f"Overlapping module prefixes for {module_id}; leave scan reads enabled")
    return modules


def backfill(modules):
    counts = {module_id: dict.fromkeys(db.QUESTION_DIFFICULTIES, 0) for module_id in modules}
    for question in scan_items(db.QuestionTable, ProjectionExpression="question_id, difficulty"):
        level = question.get("difficulty")
        if level not in db.QUESTION_DIFFICULTIES:
            continue
        parts = question["question_id"].split("_")
        for end in range(1, len(parts)):
            module_id = "_".join(parts[:end])
            if module_id in counts:
                counts[module_id][level] += 1
                break

    failed = 0
    for module_id, module in modules.items():
        condition, values = db.question_bank_revision_condition(module)
        values.update({":counts": counts[module_id], ":revision": secrets.token_hex(16)})
        try:
            db.ModuleTable.update_item(
                Key={"module_id": module_id},
                UpdateExpression="SET questionDifficultyCounts = :counts, questionBankRevision = :revision",
                ConditionExpression=condition,
                ExpressionAttributeValues=values,
            )
        except ClientError as error:
            if error.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise
            print(f"{module_id}: question bank changed during backfill. Rerun --apply.")
            failed += 1
    print(f"Backfilled {len(modules) - failed}/{len(modules)} modules.")
    return failed == 0


def verify(modules):
    failed = 0
    for module_id, snapshot in modules.items():
        expected = {
            level: db.count_questions_by_difficulty(module_id, level, consistent_read=True)
            for level in db.QUESTION_DIFFICULTIES
        }
        current = db.ModuleTable.get_item(Key={"module_id": module_id}, ConsistentRead=True).get("Item", {})
        actual = db.stored_difficulty_counts(current)
        if current.get("questionBankRevision") != snapshot.get("questionBankRevision"):
            print(f"{module_id}: question bank changed during verification. Rerun --verify.")
            failed += 1
        elif actual != expected:
            print(f"{module_id}: stored {actual}, scan {expected}.")
            failed += 1
    print(f"Verified {len(modules) - failed}/{len(modules)} modules against question scans.")
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--apply", action="store_true", help="Write counts to the Module table.")
    mode.add_argument("--verify", action="store_true", help="Compare stored counts to live scans without writing.")
    args = parser.parse_args()
    modules = module_snapshots()
    success = backfill(modules) if args.apply else verify(modules)
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
