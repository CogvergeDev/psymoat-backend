import unittest
from types import SimpleNamespace
import boto3
from moto import mock_aws
from flask import Flask
from lecture_catalog import Catalog, create_catalog_blueprint
import controller


class ExamStatusTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws()
        self.aws.start()
        self.resource = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
        
        # Create Exam and Module tables
        self.resource.create_table(
            TableName='Exam',
            KeySchema=[{'AttributeName': 'exam_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'exam_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        self.resource.create_table(
            TableName='Module',
            KeySchema=[{'AttributeName': 'module_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[
                {'AttributeName': 'module_id', 'AttributeType': 'S'},
                {'AttributeName': 'exam_id', 'AttributeType': 'S'}
            ],
            GlobalSecondaryIndexes=[{
                'IndexName': 'ExamModulesIndex',
                'KeySchema': [{'AttributeName': 'exam_id', 'KeyType': 'HASH'}],
                'Projection': {'ProjectionType': 'ALL'}
            }],
            BillingMode='PAY_PER_REQUEST'
        )

        self.exam_table = self.resource.Table('Exam')
        self.module_table = self.resource.Table('Module')

        # Populate sample exams matching real scenario
        self.exam_table.put_item(Item={'exam_id': 'g4mzja', 'exam_name': 'CUET_PG', 'modules': [], 'is_active': False})
        self.exam_table.put_item(Item={'exam_id': 't8ZB83', 'exam_name': 'MPhil', 'modules': [], 'is_active': False})
        self.exam_table.put_item(Item={'exam_id': 'qjPZtz', 'exam_name': 'UGC NET', 'modules': [], 'is_active': True})

        self.orig_exam_table = controller.ExamTable
        self.orig_module_table = controller.ModuleTable
        controller.ExamTable = self.exam_table
        controller.ModuleTable = self.module_table

        self.db = SimpleNamespace(
            dynamodb_resource=self.resource,
            ExamTable=self.exam_table,
            ModuleTable=self.module_table,
            get_modules_by_exam_id=controller.get_modules_by_exam_id,
            toggle_exam_status=controller.toggle_exam_status,
            initialize_new_exam=controller.initialize_new_exam
        )
        self.catalog = Catalog(self.db)

    def tearDown(self):
        controller.ExamTable = self.orig_exam_table
        controller.ModuleTable = self.orig_module_table
        self.aws.stop()

    def test_get_all_exam_details_filters_inactive(self):
        result = controller.get_all_exam_details()
        self.assertEqual(result['statusCode'], 200)
        exams = result['exams']
        self.assertIn('qjPZtz', exams)
        self.assertNotIn('g4mzja', exams)
        self.assertNotIn('t8ZB83', exams)
        self.assertTrue(exams['qjPZtz']['is_active'])

    def test_get_all_exam_details_admin_returns_all(self):
        result = controller.get_all_exam_details_admin()
        self.assertEqual(result['statusCode'], 200)
        exams = result['exams']
        self.assertIn('qjPZtz', exams)
        self.assertIn('g4mzja', exams)
        self.assertIn('t8ZB83', exams)
        self.assertTrue(exams['qjPZtz']['is_active'])
        self.assertFalse(exams['g4mzja']['is_active'])
        self.assertFalse(exams['t8ZB83']['is_active'])

    def test_toggle_exam_status(self):
        # Enable CUET_PG
        res = controller.toggle_exam_status('g4mzja', True)
        self.assertEqual(res['statusCode'], 200)
        self.assertTrue(res['is_active'])

        public_exams = controller.get_all_exam_details()['exams']
        self.assertIn('g4mzja', public_exams)

        # Disable CUET_PG back
        res2 = controller.toggle_exam_status('g4mzja', False)
        self.assertEqual(res2['statusCode'], 200)
        self.assertFalse(res2['is_active'])

        public_exams_after = controller.get_all_exam_details()['exams']
        self.assertNotIn('g4mzja', public_exams_after)

    def test_toggle_nonexistent_exam(self):
        res = controller.toggle_exam_status('nonexistent', True)
        self.assertEqual(res['statusCode'], 404)

    def test_catalog_exams_filtering(self):
        all_catalog_exams = self.catalog.exams()
        active_ids = [e['id'] for e in all_catalog_exams if e['active']]
        self.assertEqual(active_ids, ['qjPZtz'])

        # After toggling CUET_PG active
        controller.toggle_exam_status('g4mzja', True)
        all_catalog_exams_after = self.catalog.exams()
        active_ids_after = [e['id'] for e in all_catalog_exams_after if e['active']]
        self.assertIn('g4mzja', active_ids_after)
        self.assertIn('qjPZtz', active_ids_after)


if __name__ == '__main__':
    unittest.main()
