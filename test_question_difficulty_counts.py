import os
import unittest
from unittest.mock import patch

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

import backfill_question_difficulty_counts as migration
import controller as db


class QuestionDifficultyCountsTests(unittest.TestCase):
    def setUp(self):
        aws = mock_aws()
        aws.start()
        self.addCleanup(aws.stop)
        resource = boto3.resource("dynamodb", region_name="us-east-1")
        for name, key in (
            ("Question", "question_id"), ("Module", "module_id"), ("Exam", "exam_id"),
            ("User", "email"), ("QNAHistory", "qna_id"),
        ):
            table = resource.create_table(
                TableName=name,
                BillingMode="PAY_PER_REQUEST",
                KeySchema=[{"AttributeName": key, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": key, "AttributeType": "S"}],
            )
            table_patch = patch.object(db, name + "Table", table)
            table_patch.start()
            self.addCleanup(table_patch.stop)
        flag = patch.dict(os.environ, {"USE_STORED_QUESTION_DIFFICULTY_COUNTS": "0"})
        flag.start()
        self.addCleanup(flag.stop)
        db.ExamTable.put_item(Item={"exam_id": "exam", "modules": ["module", "empty"]})
        db.ModuleTable.put_item(Item={"module_id": "module", "numberOfQuestions": 3})
        db.ModuleTable.put_item(Item={"module_id": "empty", "numberOfQuestions": 0})

    def put_question(self, question_id, level):
        db.QuestionTable.put_item(Item={"question_id": question_id, "difficulty": level})

    def submit(self, user):
        data = {
            "email": "student@example.com", "exam_id": "exam", "module_id": "module",
            "completed_idx": 1, "easy_correct": 1, "hard_incorrect": 1,
            "detailed_user_qna": [{"question_id": "module_f_1", "time_taken": 3}],
        }
        with patch.object(db, "record_question_activity"):
            result = db.submit_questions(data, user)
        self.assertIn("Attributes", result)
        return result["Attributes"]

    def backfill_and_verify(self):
        self.assertTrue(migration.backfill(migration.module_snapshots()))
        self.assertTrue(migration.verify(migration.module_snapshots()))

    def test_repeat_submission_preserves_saved_totals_without_metadata_reads(self):
        user = {
            "data_graph_leetcode_accuracy": {"exam": {
                "easy": {"total_questions": 0, "number_solved": 2, "correct_answered": 1},
                "medium": {"total_questions": 3, "number_solved": 1, "correct_answered": 1},
                "hard": {"total_questions": 4, "number_solved": 1, "correct_answered": 0},
            }},
            "data_graph_modulewise": {"exam": {"module": {
                "total_questions": 10, "correct_answers": 2, "incorrect_answers": 1,
            }}},
        }
        with (
            patch.object(db.ExamTable, "get_item", side_effect=AssertionError("Exam lookup")),
            patch.object(db.ModuleTable, "get_item", side_effect=AssertionError("Module lookup")),
            patch.object(db.QuestionTable, "scan", side_effect=AssertionError("Question scan")),
        ):
            saved = self.submit(user)

        exam = saved["data_graph_leetcode_accuracy"]["exam"]
        self.assertEqual([exam[level]["total_questions"] for level in ("easy", "medium", "hard")], [0, 3, 4])
        self.assertEqual(exam["easy"]["number_solved"], 3)
        self.assertEqual(exam["easy"]["correct_answered"], 2)
        self.assertEqual(saved["data_graph_modulewise"]["exam"]["module"], {
            "total_questions": 10, "correct_answers": 3, "incorrect_answers": 2,
        })
        self.assertEqual(db.QNAHistoryTable.scan()["Count"], 1)

    def test_first_submission_uses_backfilled_counts_and_includes_zero_counts(self):
        self.put_question("module_f_1", "Easy")
        self.put_question("module_p_1", "Medium")
        self.put_question("module_2", "Medium")
        self.put_question("module_f_2", "medium")
        self.put_question("other_f_1", "Hard")
        scan = db.QuestionTable.scan
        with patch.object(db.QuestionTable, "scan", side_effect=lambda **args: scan(Limit=1, **args)):
            self.backfill_and_verify()

        with (
            patch.dict(os.environ, {"USE_STORED_QUESTION_DIFFICULTY_COUNTS": "1"}),
            patch.object(db.QuestionTable, "scan", side_effect=AssertionError("Question scan")),
        ):
            saved = self.submit({})

        exam = saved["data_graph_leetcode_accuracy"]["exam"]
        self.assertEqual([exam[level]["total_questions"] for level in ("easy", "medium", "hard")], [1, 2, 0])
        self.assertEqual(saved["data_graph_modulewise"]["exam"]["module"]["total_questions"], 3)

    def test_verification_detects_a_stale_count_and_default_reader_uses_scans(self):
        self.backfill_and_verify()
        self.put_question("module_f_1", "Hard")
        self.assertFalse(migration.verify(migration.module_snapshots()))
        self.assertEqual(db.get_exam_difficulty_counts("exam"), {"Easy": 0, "Medium": 0, "Hard": 1})

    def test_reader_scans_modules_with_missing_counts(self):
        self.put_question("module_f_1", "Hard")
        db.ModuleTable.update_item(
            Key={"module_id": "empty"},
            UpdateExpression="SET questionDifficultyCounts = :counts",
            ExpressionAttributeValues={":counts": dict.fromkeys(db.QUESTION_DIFFICULTIES, 0)},
        )
        with (
            patch.dict(os.environ, {"USE_STORED_QUESTION_DIFFICULTY_COUNTS": "1"}),
            patch.object(db, "count_questions_by_difficulty", wraps=db.count_questions_by_difficulty) as scans,
        ):
            self.assertEqual(db.get_exam_difficulty_counts("exam"), {"Easy": 0, "Medium": 0, "Hard": 1})
        self.assertEqual([call.args[0] for call in scans.call_args_list], ["module"] * 3)

    def test_import_tracks_new_questions_and_legacy_orphan_replacements(self):
        db.ModuleTable.put_item(Item={
            "module_id": "module", "questions": ["module_f_1"],
            "numberOfQuestions": 1, "numberOfFreeQuestions": 1,
        })
        self.put_question("module_f_1", "Easy")
        self.put_question("module_p_1", "Hard")  # A legacy partial import left this row unlisted.
        self.backfill_and_verify()
        rows = [
            self.row("module_f_1", "Medium", False),  # Existing IDs are skipped.
            self.row("module_p_1", "Easy", True),
            self.row("module_f_2", "Medium", False),
        ]

        result = db.add_questions_to_module("module", rows)
        self.assertEqual(result["numberOfQuestions"], 3)
        self.assertEqual(result["numberOfPaidQuestions"], 1)
        self.assertEqual(result["numberOfFreeQuestions"], 2)
        self.assertEqual(db.add_questions_to_module("module", rows), result)
        module = db.ModuleTable.get_item(Key={"module_id": "module"})["Item"]
        self.assertEqual(db.stored_difficulty_counts(module), {"Easy": 2, "Medium": 1, "Hard": 0})
        self.assertTrue(migration.verify(migration.module_snapshots()))

    def test_concurrent_import_cannot_be_overwritten_by_backfill(self):
        snapshot = migration.module_snapshots()
        db.add_questions_to_module("module", [self.row("module_f_1", "Easy", False)])
        self.assertFalse(migration.backfill(snapshot))
        self.backfill_and_verify()

    def test_failed_import_batch_leaves_counts_consistent_and_can_be_retried(self):
        self.backfill_and_verify()
        rows = [self.row(f"module_f_{i}", "Easy", False) for i in range(1, 10)]
        client = db.ModuleTable.meta.client
        transaction = client.transact_write_items

        def fail_last_batch(**params):
            if len(params["TransactItems"]) == 2:
                raise ClientError({"Error": {"Code": "AccessDeniedException"}}, "TransactWriteItems")
            return transaction(**params)

        with patch.object(client, "transact_write_items", side_effect=fail_last_batch):
            with self.assertRaisesRegex(RuntimeError, "AccessDeniedException"):
                db.add_questions_to_module("module", rows)

        self.assertEqual(db.count_questions_by_difficulty("module", "Easy"), 8)
        self.assertTrue(migration.verify(migration.module_snapshots()))
        db.add_questions_to_module("module", rows)
        self.assertEqual(db.count_questions_by_difficulty("module", "Easy"), 9)
        self.assertTrue(migration.verify(migration.module_snapshots()))

    @staticmethod
    def row(qid, difficulty, paid):
        return {
            "question_id": qid, "Question": "Question?", "Option 1": "A", "Option 2": "B",
            "Option 3": "C", "Option 4": "D", "Correct Answer": "A", "Difficulty": difficulty,
            "is_paid": paid,
        }


if __name__ == "__main__":
    unittest.main()
