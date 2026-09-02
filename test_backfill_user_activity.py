import tempfile
import unittest
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

import backfill_user_activity as migration


class FakeScanTable:
    def __init__(self, items):
        self.items = items

    def scan(self, **_kwargs):
        return {"Items": list(self.items)}


class FakeConditionalTable:
    def __init__(self, item=None):
        self.item = dict(item or {})

    def update_item(self, **kwargs):
        field = kwargs["ExpressionAttributeNames"]["#field"]
        value = kwargs["ExpressionAttributeValues"][":value"]
        current = self.item.get(field)
        if current is not None and current >= value:
            error = {
                "Error": {"Code": "ConditionalCheckFailedException", "Message": "condition"}
            }
            raise migration.ClientError(error, "UpdateItem")
        self.item.update(kwargs["Key"])
        self.item[field] = value
        self.item["updated_at"] = kwargs["ExpressionAttributeValues"][":updated_at"]


class FakeRestoreTable:
    def __init__(self, items):
        self.items = {
            (item["email"], item["activity_date"]): dict(item) for item in items
        }

    def scan(self, **_kwargs):
        return {"Items": list(self.items.values())}

    def batch_writer(self, **_kwargs):
        table = self

        class Writer:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def put_item(self, Item):
                table.items[(Item["email"], Item["activity_date"])] = dict(Item)

            def delete_item(self, Key):
                table.items.pop((Key["email"], Key["activity_date"]), None)

        return Writer()


class BackfillTests(unittest.TestCase):
    def test_extract_ist_date_converts_utc(self):
        self.assertEqual(
            migration.extract_ist_date("2026-09-02T20:30:00Z"),
            "2026-09-03",
        )

    def test_atomic_merge_never_lowers_counts_or_removes_attributes(self):
        table = FakeConditionalTable(
            {
                "email": "person@example.com",
                "activity_date": "2026-09-03",
                "questions_completed": 30,
                "sets_completed": 1,
                "future_attribute": "preserved",
            }
        )
        candidate = {
            "email": "person@example.com",
            "activity_date": "2026-09-03",
            "questions_completed": 20,
            "sets_completed": 3,
            "updated_at": datetime.now(migration.IST).isoformat(),
        }
        with patch.object(migration.controller, "UserActivityTable", table):
            changed = migration.write_activity_max(candidate)

        self.assertTrue(changed)
        self.assertEqual(table.item["questions_completed"], 30)
        self.assertEqual(table.item["sets_completed"], 3)
        self.assertEqual(table.item["future_attribute"], "preserved")

    def test_backup_round_trip_preserves_decimal_and_checksum(self):
        items = [
            {
                "email": "person@example.com",
                "activity_date": "2026-09-03",
                "questions_completed": Decimal("20"),
                "sets_completed": Decimal("1"),
            }
        ]
        target = {
            "account_id": "123456789012",
            "region": "us-east-1",
            "table_name": "UserActivity",
            "table_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/UserActivity",
        }
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(
                migration.controller, "UserActivityTable", FakeScanTable(items)
            ):
                path = migration.create_local_backup(target, Path(directory))
            loaded = migration.load_local_backup(path)

        self.assertEqual(loaded["items"], items)
        self.assertEqual(loaded["item_count"], 1)

    def test_restore_replaces_changed_items_and_deletes_post_backup_items(self):
        original = [
            {
                "email": "person@example.com",
                "activity_date": "2026-09-02",
                "questions_completed": Decimal("20"),
            }
        ]
        target = {
            "account_id": "123456789012",
            "region": "us-east-1",
            "table_name": "UserActivity",
            "table_arn": "arn:aws:dynamodb:us-east-1:123456789012:table/UserActivity",
        }
        table = FakeRestoreTable(original)
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(migration.controller, "UserActivityTable", table):
                path = migration.create_local_backup(target, Path(directory))
                table.items[("person@example.com", "2026-09-02")][
                    "questions_completed"
                ] = Decimal("999")
                table.items[("new@example.com", "2026-09-03")] = {
                    "email": "new@example.com",
                    "activity_date": "2026-09-03",
                    "questions_completed": Decimal("40"),
                }
                restored, deleted = migration.restore_local_backup(path, target)

        self.assertEqual(restored, 1)
        self.assertEqual(deleted, 1)
        self.assertEqual(list(table.items.values()), original)

    def test_mock_test_counts_only_selected_answers(self):
        tests_table = FakeScanTable(
            [
                {
                    "email": "Person@Example.com",
                    "tests_submitted": [
                        {
                            "test_id": "t1",
                            "timestamp": "2026-09-03T00:00:00Z",
                            "detailed_user_test_qna": [
                                {"selected_answer": "A"},
                                {"selected_answer": None},
                                {"selected_answer": ""},
                            ],
                        }
                    ],
                }
            ]
        )
        with patch.object(migration.controller, "TestsSolvedUserDataTable", tests_table):
            aggregated, _ = migration.collect_tests_history(
                None, {"person@example.com": "person@example.com"}
            )

        self.assertEqual(
            aggregated["person@example.com"]["2026-09-03"]["questions"], 1
        )


if __name__ == "__main__":
    unittest.main()
