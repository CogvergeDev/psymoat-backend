import unittest
from unittest.mock import patch

import controller


class FakeTable:
    def __init__(self, items):
        self.items = items
        self.calls = []

    def get_item(self, **kwargs):
        self.calls.append(kwargs)
        item = self.items.get(kwargs["Key"]["email"])
        return {"Item": item} if item is not None else {}


class UserTestDataTests(unittest.TestCase):
    def test_merges_summary_and_detailed_attempts_without_duplicates(self):
        summary = {
            "email": "Student@Example.com",
            "tests_submitted": [
                {
                    "test_id": "test-1",
                    "timestamp": "2026-09-01T10:00:00Z",
                    "marks_scored": 12,
                    "total_marks": 20,
                },
                {
                    "test_id": "test-2",
                    "timestamp": "2026-09-02T10:00:00Z",
                    "marks_scored": 16,
                    "total_marks": 20,
                },
            ],
        }
        detailed = {
            "email": "Student@Example.com",
            "tests_submitted": [
                {
                    "test_id": "test-1",
                    "timestamp": "2026-09-01T10:00:00Z",
                    "marks_scored": 12,
                    "total_marks": 20,
                    "detailed_user_test_qna": [{"question_id": "q-1"}],
                }
            ],
        }
        summary_table = FakeTable({"Student@Example.com": summary})
        detailed_table = FakeTable({"Student@Example.com": detailed})

        with patch.object(controller, "UserTable", summary_table), patch.object(
            controller, "TestsSolvedUserDataTable", detailed_table
        ):
            result = controller.get_user_test_data("Student@Example.com")

        self.assertEqual(len(result), 2)
        test_one = next(item for item in result if item["test_id"] == "test-1")
        self.assertEqual(test_one["detailed_user_test_qna"], [{"question_id": "q-1"}])
        self.assertTrue(all(call["ConsistentRead"] for call in detailed_table.calls))
        self.assertTrue(all(call["ConsistentRead"] for call in summary_table.calls))

    def test_reads_lowercase_legacy_partition_and_returns_empty_for_new_user(self):
        detailed_table = FakeTable(
            {
                "student@example.com": {
                    "tests_submitted": [
                        {
                            "testId": "test-3",
                            "marks_scored": 8,
                            "total_marks": 20,
                        }
                    ]
                }
            }
        )
        summary_table = FakeTable({})

        with patch.object(controller, "UserTable", summary_table), patch.object(
            controller, "TestsSolvedUserDataTable", detailed_table
        ):
            result = controller.get_user_test_data("Student@Example.com")
            empty_result = controller.get_user_test_data("new@example.com")

        self.assertEqual([item["testId"] for item in result], ["test-3"])
        self.assertEqual(empty_result, [])


if __name__ == "__main__":
    unittest.main()
