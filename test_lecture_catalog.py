"""Run with unittest and moto[dynamodb] installed in an isolated test environment."""
import os
import json
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import boto3
from moto import mock_aws
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token
from botocore.exceptions import ClientError

from lecture_catalog import Catalog, create_catalog_blueprint, number
from import_lecture_catalog import validate_manifest, reconcile
from catalog_workbook_to_manifest import convert


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws(); self.aws.start()
        self.resource = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
        for name, pk in [('Lecture', 'lecture_id'), ('Exam', 'exam_id'), ('Module', 'module_id')]:
            args={'TableName':name, 'KeySchema':[{'AttributeName':pk,'KeyType':'HASH'}],
                'AttributeDefinitions':[{'AttributeName':pk,'AttributeType':'S'}], 'BillingMode':'PAY_PER_REQUEST'}
            if name=='Lecture':
                args['AttributeDefinitions'] += [{'AttributeName':'exam_id','AttributeType':'S'},{'AttributeName':'date_time_of_zoom_lec','AttributeType':'S'}]
                args['GlobalSecondaryIndexes']=[{'IndexName':'ExamUpcomingLecturesIndex','KeySchema':[{'AttributeName':'exam_id','KeyType':'HASH'},{'AttributeName':'date_time_of_zoom_lec','KeyType':'RANGE'}],'Projection':{'ProjectionType':'ALL'}}]
            self.resource.create_table(**args)
        self.resource.create_table(TableName='LectureCatalog', KeySchema=[{'AttributeName':'pk','KeyType':'HASH'},{'AttributeName':'sk','KeyType':'RANGE'}],
            AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'},{'AttributeName':'sk','AttributeType':'S'}], BillingMode='PAY_PER_REQUEST')
        self.db = SimpleNamespace(dynamodb_resource=self.resource, LectureTable=self.resource.Table('Lecture'),
            ExamTable=self.resource.Table('Exam'), ModuleTable=self.resource.Table('Module'), generate_id=lambda:'created', normalize_yt_link_to_key=lambda x:x,
            get_modules_by_exam_id=lambda exam:{'modules':[]})
        self.env = patch.dict(os.environ, {'LECTURE_CATALOG_TABLE':'LectureCatalog', 'CATALOG_ADMIN_EMAILS':'admin@example.test'})
        self.env.start()
        self.catalog = Catalog(self.db)
        self.db.ExamTable.put_item(Item={'exam_id':'exam','exam_name':'Test exam','modules':['legacy']})
        self.db.ModuleTable.put_item(Item={'module_id':'legacy','exam_id':'exam','lectures':[]})
        for folder in ['june','december']:
            self.catalog.save_entity('exam','folders',{'name':folder,'order':0},folder)
        for section in ['paper-1','paper-2']:
            self.catalog.save_entity('exam','sections',{'name':section,'order':1 if section=='paper-1' else 2},section)
        for unit, section in [('research','paper-2'),('statistics','paper-2'),('teaching','paper-1')]:
            self.catalog.save_entity('exam','units',{'name':unit,'section_id':section,'order':1,'syllabus_number':2},unit)

    def tearDown(self):
        self.env.stop(); self.aws.stop()

    def lecture(self, lid='lecture', **updates):
        item={'lecture_id':lid,'exam_id':'exam','title':'Original title','yt_link':'video-key', 'notes_markdown':'Keep my notes',
              'instructor_details':{'name':'Teacher'},'date_time_of_zoom_lec':'2025-01-01T12:00:00','module_id':''}
        item.update(updates); self.db.LectureTable.put_item(Item=item); return item

    def placement(self, folder='june', unit='research', section='paper-2', order=1):
        return {'folder_id':folder,'section_id':section,'unit_id':unit,'display_title':'Sampling','lecture_number':order,'order':order}

    def count(self, folder):
        return self.catalog.entity('exam','folders',folder).get('lecture_count',0)

    def test_assignment_is_additive_and_repeat_does_not_double_count(self):
        original=self.lecture()
        self.catalog.assign('lecture','exam',self.placement())
        self.catalog.assign('lecture','exam',self.placement())
        self.assertEqual(self.count('june'),1)
        self.assertEqual(self.db.LectureTable.get_item(Key={'lecture_id':'lecture'})['Item'],original)

    def test_move_updates_old_and_new_partitions_and_counters(self):
        self.lecture(); self.catalog.assign('lecture','exam',self.placement())
        self.catalog.assign('lecture','exam',self.placement(folder='december',unit='statistics'))
        self.assertEqual((self.count('june'),self.count('december')),(0,1))
        self.assertEqual(self.catalog.query('FOLDER#exam#june'),[])
        self.assertEqual(self.catalog.placement('lecture')['unit_id'],'statistics')

    def test_reordering_and_renaming_folder_preserve_counts(self):
        self.lecture(); self.catalog.assign('lecture','exam',self.placement())
        self.catalog.save_entity('exam','folders',{'name':'Renamed June','order':10},'june')
        self.assertEqual(self.count('june'),1)

    def test_mismatched_section_and_exam_are_rejected_before_writes(self):
        self.lecture()
        with self.assertRaises(ValueError): self.catalog.assign('lecture','exam',self.placement(section='paper-1'))
        self.lecture('foreign',exam_id='other')
        with self.assertRaises(ValueError): self.catalog.assign('foreign','exam',self.placement())
        self.assertEqual(self.count('june'),0)

    def test_failed_optimistic_transaction_leaves_everything_unchanged(self):
        self.lecture(); self.catalog.assign('lecture','exam',self.placement())
        stale=self.catalog.placement('lecture'); stale['version']=0
        with patch.object(self.catalog,'placement',return_value=stale):
            with self.assertRaises(ClientError): self.catalog.assign('lecture','exam',self.placement(folder='december'))
        self.assertEqual((self.count('june'),self.count('december')),(1,0))
        self.assertEqual(self.catalog.query('FOLDER#exam#december'),[])

    def test_folder_query_scope_numeric_order_and_no_video_urls_in_summaries(self):
        for lid, folder, order in [('ten','june',10),('two','june',2),('other','december',1)]:
            self.lecture(lid); self.catalog.assign(lid,'exam',self.placement(folder=folder,order=order))
        with patch.object(self.db.LectureTable,'scan',side_effect=AssertionError('No lecture scans')):
            content=self.catalog.folder_content('exam','june','paper-2')
        self.assertEqual([r['lecture_id'] for r in content['lectures']],['two','ten'])
        self.assertTrue(all('yt_link' not in r and 'video_url' not in r for r in content['lectures']))
        self.assertEqual(self.catalog.folder_content('exam','june',search='does not match')['lectures'],[])

    def test_unitless_lecture_is_listed_directly_in_its_section(self):
        self.lecture('batch-only')
        placement=self.placement(section='paper-1',unit=None)
        self.catalog.assign('batch-only','exam',placement)
        content=self.catalog.folder_content('exam','june','paper-1')
        self.assertEqual([r['lecture_id'] for r in content['lectures']],['batch-only'])
        self.assertIsNone(content['lectures'][0]['unit_id'])
        self.assertEqual(self.count('june'),1)

    def test_hide_folder_and_prevent_deleting_referenced_unit(self):
        self.lecture(); self.catalog.assign('lecture','exam',self.placement())
        with self.assertRaises(ValueError): self.catalog.delete_entity('exam','units','research')
        self.catalog.save_entity('exam','folders',{'name':'June','active':False},'june')
        with self.assertRaises(ValueError): self.catalog.folder_content('exam','june')

    def test_create_and_edit_recording_are_atomic_with_catalog_and_module(self):
        data=self.lecture('template'); self.db.LectureTable.delete_item(Key={'lecture_id':'template'})
        data.update(module_id='legacy', catalog=self.placement())
        lid=self.catalog.save_lecture(data)
        self.assertEqual(lid,'created'); self.assertEqual(self.count('june'),1)
        self.assertEqual(self.db.ModuleTable.get_item(Key={'module_id':'legacy'})['Item']['lectures'],['created'])
        data.update(title='Edited title',catalog=self.placement(folder='december'),module_id='')
        self.catalog.save_lecture(data,lid)
        self.assertEqual((self.count('june'),self.count('december')),(0,1))
        self.assertEqual(self.db.LectureTable.get_item(Key={'lecture_id':lid})['Item']['notes_markdown'],'Keep my notes')
        self.assertEqual(self.db.ModuleTable.get_item(Key={'module_id':'legacy'})['Item']['lectures'],[])

    def test_delete_removes_placement_and_updates_count(self):
        self.lecture(); self.catalog.assign('lecture','exam',self.placement())
        self.catalog.delete_lecture('lecture')
        self.assertEqual(self.count('june'),0)
        self.assertIsNone(self.catalog.placement('lecture'))
        self.assertNotIn('Item',self.db.LectureTable.get_item(Key={'lecture_id':'lecture'}))

    def test_api_admin_requires_server_verified_identity_and_returns_numeric_counts(self):
        app=Flask(__name__); app.config.update(JWT_SECRET_KEY='test-only-secret',JWT_TOKEN_LOCATION=['headers'])
        JWTManager(app); app.register_blueprint(create_catalog_blueprint(self.db))
        client=app.test_client()
        self.assertEqual(client.get('/catalog/admin/exam').status_code,401)
        with app.app_context():
            denied=create_access_token(identity='student@example.test'); allowed=create_access_token(identity='admin@example.test')
        self.assertEqual(client.get('/catalog/admin/exam',headers={'Authorization':f'Bearer {denied}'}).status_code,403)
        self.assertEqual(client.get('/catalog/admin/exam',headers={'Authorization':f'Bearer {allowed}'}).status_code,200)
        self.lecture(); self.catalog.assign('lecture','exam',self.placement())
        folders=client.get('/catalog/exam/folders').json['folders']
        self.assertIsInstance(next(f for f in folders if f['id']=='june')['lecture_count'],int)

    def test_validation_rejects_invalid_numbers_and_duplicate_manifest_ids(self):
        for value in ['abc',-1,1.5,'NaN',True]:
            with self.assertRaises(ValueError): number(value)
        data={'exam_id':'exam','folders':[{'id':'same','name':'A'},{'id':'same','name':'B'}],'sections':[],'units':[],'lectures':[]}
        with self.assertRaises(ValueError): validate_manifest(data)
        unitless={'exam_id':'exam','folders':[{'id':'june','name':'June'}],
                  'sections':[{'id':'other','name':'Other Lectures'}],'units':[],
                  'lectures':[{'lecture_id':'batch-only','exam_id':'exam','folder_id':'june','section_id':'other',
                               'unit_id':None,'display_title':'Live MCQs','order':1}]}
        self.assertEqual(validate_manifest(unitless),'exam')

    def test_reconciliation_reports_conflicts_and_database_only_recordings_without_writes(self):
        self.lecture(); self.lecture('unlisted')
        data={'exam_id':'exam','folders':[{'id':'june','name':'Different proposed name'}],
              'sections':[{'id':'paper-2','name':'paper-2'}],
              'units':[{'id':'research','name':'research','section_id':'paper-2'}],
              'lectures':[dict(self.placement(),lecture_id='lecture',exam_id='exam',approved=False)]}
        report=reconcile(data,self.catalog)
        self.assertEqual(report['conflicting_catalog_entries'],['folders/june'])
        self.assertEqual(report['unresolved_database_only_ids'],['unlisted'])
        self.assertFalse(report['approved']); self.assertEqual(self.count('june'),0)

    def test_workbook_converter_transfers_corrections_and_rejects_pending_approval(self):
        proposal={'exam_id':'exam','folders':[{'id':'june','name':'June'}], 'sections':[{'id':'paper-2','name':'Paper 2'}],
                  'units':[], 'lectures':[{'lecture_id':'lecture'}]}
        sheets={'Proposed':[{'Source row':'2.0','Lecture ID':'lecture','Folder':'June','Section':'Paper 2','Unit key':'research',
                            'Lecture title':'Corrected title','Lecture number':'3.0','Lecture order':'2.0','Approval':'Approved'},{}],
                'Units':[{'Unit key':'research','Unit name':'Research','Section key':'paper-2','Unit order':'1.0','Syllabus number':'2.0','Approval':'Approved'},{}],
                'Decisions':[{'Approval':'Confirmed'},{}]}
        with tempfile.NamedTemporaryFile(mode='w',suffix='.json') as proposal_file:
            json.dump(proposal,proposal_file); proposal_file.flush()
            with patch('catalog_workbook_to_manifest.read_sheets',return_value=sheets):
                result=convert('ignored.xlsx',proposal_file.name)
                self.assertEqual(result['lectures'][0]['display_title'],'Corrected title')
                self.assertEqual(result['lectures'][0]['order'],2)
                self.assertTrue(result['approved'])
                sheets['Proposed'][0]['Approval']='Pending'
                with self.assertRaises(ValueError): convert('ignored.xlsx',proposal_file.name)


if __name__=='__main__': unittest.main()
