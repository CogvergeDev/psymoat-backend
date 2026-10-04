"""Audit actual Flask handlers with mocked DynamoDB; no live requests/writes."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import boto3
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token
from moto import mock_aws

from admin_audit import (AuditContext, AuditStore, AuditUnavailable, KEY_SCHEMA,
                         TABLE_NAME, action_for, install_admin_audit, ip_details,
                         safe_fields)
from provision_admin_audit import provision


class AdminAuditTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws()
        self.aws.start()
        self.env = patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'testing', 'AWS_SECRET_ACCESS_KEY': 'testing',
                                           'REGION_NAME': 'us-east-1', 'ADMIN_AUDIT_TABLE': TABLE_NAME,
                                           'ADMIN_AUDIT_TRUSTED_PROXY_HOPS': '0',
                                           'CATALOG_ADMIN_EMAILS': 'admin@example.test'})
        self.env.start()
        self.resource = boto3.resource('dynamodb', region_name='us-east-1')
        provision(self.resource)
        self.table = self.resource.Table(TABLE_NAME)
        self.store = AuditStore(self.table)
        self.app = Flask(__name__)
        self.app.config.update(TESTING=False, JWT_SECRET_KEY='test-audit-secret-at-least-32-chars',
                               JWT_TOKEN_LOCATION=['headers'], JWT_COOKIE_CSRF_PROTECT=False)
        JWTManager(self.app)
        self.db = SimpleNamespace(dynamodb_resource=self.resource)
        for name, key in [('User', 'email'), ('Lecture', 'lecture_id'), ('Notes', 'note_id'),
                          ('Exam', 'exam_id'), ('Module', 'module_id')]:
            self.resource.create_table(TableName=name, BillingMode='PAY_PER_REQUEST',
                                        KeySchema=[{'AttributeName': key, 'KeyType': 'HASH'}],
                                        AttributeDefinitions=[{'AttributeName': key, 'AttributeType': 'S'}])
            setattr(self.db, name + 'Table', self.resource.Table(name))
        install_admin_audit(self.app, self.db, self.store)
        self.client = self.app.test_client()
        self.patches = []

    def tearDown(self):
        for context in reversed(self.patches):
            context.stop()
        self.env.stop()
        self.aws.stop()

    def patch(self, *args, **kwargs):
        context = patch(*args, **kwargs)
        self.patches.append(context)
        return context.start()

    def patch_object(self, *args, **kwargs):
        context = patch.object(*args, **kwargs)
        self.patches.append(context)
        return context.start()

    def events(self, phase=None):
        rows = self.table.scan()['Items']
        rows.sort(key=lambda row: row['timestamp_utc'])
        return [row for row in rows if phase is None or row['phase'] == phase]

    def actual_handlers(self):
        import app as source
        import controller
        for name in ('UserTable', 'LectureTable', 'NotesTable', 'ExamTable', 'ModuleTable'):
            self.patch('controller.' + name, getattr(self.db, name))
        self.patch('controller.dynamodb_resource', self.resource)
        for rule in source.app.url_map.iter_rules():
            if rule.endpoint != 'static' and not rule.endpoint.startswith('lecture_catalog.'):
                self.app.add_url_rule(rule.rule, endpoint=rule.endpoint,
                                      view_func=source.app.view_functions[rule.endpoint], methods=rule.methods)
        from lecture_catalog import create_catalog_blueprint
        self.app.register_blueprint(create_catalog_blueprint(controller))
        return source

    def token(self, identity='admin@example.test'):
        with self.app.app_context():
            return {'Authorization': 'Bearer ' + create_access_token(identity=identity)}

    def test_real_grant_records_actual_plan_expiry_and_permissions(self):
        self.actual_handlers()
        self.db.UserTable.put_item(Item={'email': 'student@example.test', 'is_paid': False, 'plan_id': 'free',
                                         'password': 'private-hash', 'phone': 'private-phone'})
        response = self.client.post('/grant-paid-access', json={'email': 'student@example.test',
                                   'plan_id': 'ugc_net_full_course_v1', 'months': 3,
                                   'password': 'injected-secret'}, headers={'X-Forwarded-For': '198.51.100.7'})
        self.assertEqual(response.status_code, 200)
        started, done = self.events()
        self.assertEqual(started['request_id'], done['request_id'])
        self.assertEqual(done['action'], 'access.grant')
        self.assertEqual(done['target']['email'], 'student@example.test')
        self.assertEqual(done['details']['before']['plan_id'], 'free')
        state = done['details']['after']
        self.assertEqual(state['plan_id'], 'ugc_net_full_course_v1')
        self.assertGreater(datetime.fromisoformat(state['plan_valid_till']), datetime.now(timezone.utc))
        self.assertIn('qjPZtz_lecs', state['exams_paid_for'])
        self.assertEqual(done['actor']['authentication'], 'unauthenticated')
        raw = json.dumps(self.events(), default=str)
        for secret in ('private-hash', 'private-phone', 'injected-secret'):
            self.assertNotIn(secret, raw)

    def test_password_and_signed_urls_never_logged_even_when_nested(self):
        self.actual_handlers()
        response = self.client.post('/change-password', json={'email': 'student@example.test', 'new_password': 'VerySecret987!'})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('VerySecret987!', json.dumps(self.events(), default=str))
        data = safe_fields({'instructor_details': {'name': 'Teacher', 'password': 'nested-secret', 'token': 'nested-token'},
                            'notes_markdown': 'secret-content', 'video_key': 'https://storage.test/file?X-Amz-Signature=private',
                            'upload_url': 'signed-secret', 'months': 1.5})
        raw = json.dumps(data, default=str)
        for secret in ('nested-secret', 'nested-token', 'secret-content', 'signed-secret', 'X-Amz-Signature'):
            self.assertNotIn(secret, raw)
        self.assertEqual(data['months'], Decimal('1.5'))
        self.assertEqual(data['notes_markdown']['length'], len('secret-content'))

    def test_validation_malformed_body_and_server_failure_are_logged(self):
        self.actual_handlers()
        self.assertEqual(self.client.post('/grant-paid-access', json={}).status_code, 400)
        self.assertEqual(self.client.post('/grant-paid-access', data='{bad', content_type='application/json').status_code, 400)
        with patch('controller.grant_paid_access', side_effect=RuntimeError('secret-token')), patch.object(self.app.logger, 'error'):
            self.assertEqual(self.client.post('/grant-paid-access', json={'email': 'a', 'plan_id': 'b'}).status_code, 500)
        self.assertEqual([row['details']['outcome'] for row in self.events('completed')], ['failed'] * 3)
        self.assertNotIn('secret-token', json.dumps(self.events(), default=str))

    def test_start_failure_prevents_actual_user_mutation(self):
        self.actual_handlers()
        self.db.UserTable.put_item(Item={'email': 'student@example.test', 'plan_id': 'free'})
        self.patch_object(self.store, 'write', side_effect=AuditUnavailable())
        response = self.client.post('/grant-paid-access', json={'email': 'student@example.test', 'plan_id': 'ugc_net_full_course_v1'})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.db.UserTable.get_item(Key={'email': 'student@example.test'})['Item']['plan_id'], 'free')

    def test_outcome_failure_preserves_success_and_started_evidence(self):
        self.actual_handlers()
        self.db.UserTable.put_item(Item={'email': 'student@example.test', 'plan_id': 'free'})
        original = self.store.write
        def write(context, phase, details=None, event_id=None):
            if phase == 'completed':
                raise AuditUnavailable()
            return original(context, phase, details, event_id)
        self.patch_object(self.store, 'write', side_effect=write)
        response = self.client.post('/grant-paid-access', json={'email': 'student@example.test', 'plan_id': 'ugc_net_full_course_v1'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Admin-Audit-Status'], 'incomplete')
        self.assertEqual(len(self.events('started')), 1)
        self.assertEqual(len(self.events('completed')), 0)
        self.assertTrue(self.db.UserTable.get_item(Key={'email': 'student@example.test'})['Item']['is_paid'])

    def test_read_export_and_supporting_reads_do_not_copy_private_response(self):
        self.actual_handlers()
        self.patch('controller.get_users_by_plan', return_value=[{'email': 'private@example.test', 'fullName': 'Private name', 'plan_valid_till': '2027-01-01'}])
        response = self.client.post('/export-users-by-plan', json={'plan_id': 'test_plan'})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'private@example.test', response.data)
        self.assertNotIn('private@example.test', json.dumps(self.events(), default=str))
        self.patch('controller.admin_get_user', return_value={'status': 'success', 'user': {'email': 'account', 'password': 'secret-hash'}})
        self.assertEqual(self.client.post('/admin/get-user', json={'email': 'account'}).status_code, 200)
        self.assertNotIn('secret-hash', json.dumps(self.events(), default=str))

    def test_content_delete_has_projected_before_state(self):
        self.actual_handlers()
        self.db.LectureTable.put_item(Item={'lecture_id': 'lecture', 'title': 'Old title', 'notes_markdown': 'Private full notes'})
        self.patch('controller.delete_lecture_by_id', side_effect=lambda lid: (self.db.LectureTable.delete_item(Key={'lecture_id': lid}), {'status': 'success'})[1])
        response = self.client.delete('/delete-lecture/lecture')
        self.assertEqual(response.status_code, 200)
        done = self.events('completed')[0]
        self.assertEqual(done['details']['before']['title'], 'Old title')
        self.assertFalse(done['details']['after']['exists'])
        self.assertNotIn('Private full notes', json.dumps(done, default=str))

    def test_protected_catalog_logs_auth_denial_and_verified_identity(self):
        self.actual_handlers()
        self.assertEqual(self.client.post('/catalog/admin/exams', json={'name': 'Exam'}).status_code, 401)
        self.assertEqual(self.client.post('/catalog/admin/exams', json={'name': 'Exam'}, headers=self.token('student@example.test')).status_code, 403)
        self.assertEqual(self.client.post('/catalog/admin/exams', json={'name': 'Exam'}, headers=self.token()).status_code, 201)
        done = self.events('completed')
        self.assertEqual([row['details']['http_status'] for row in done], [401, 403, 201])
        self.assertEqual(done[-1]['actor']['identity'], 'admin@example.test')
        self.assertIn('exam_id', done[-1]['target'])

    def test_bulk_cleanup_has_one_pair_per_changed_account(self):
        self.actual_handlers()
        for email in ('one@example.test', 'two@example.test'):
            self.db.UserTable.put_item(Item={'email': email, 'is_paid': True, 'plan_id': 'ugc_net_full_course_v1',
                                             'plan_valid_till': (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                                             'exams_paid_for': ['qjPZtz_lecs'], 'password': 'secret'})
        response = self.client.post('/cleanup-expired-plans')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['count'], 2)
        rows = self.events('account_completed')
        self.assertEqual({row['target']['email'] for row in rows}, {'one@example.test', 'two@example.test'})
        self.assertTrue(all(row['details']['after']['plan_id'] == 'free' for row in rows))
        self.assertEqual(len(self.events('account_started')), 2)
        self.assertEqual(len({row['request_id'] for row in self.events()}), 1)

    def test_background_processing_logs_actual_completion(self):
        source = self.actual_handlers()
        thread = self.patch('app.threading.Thread')
        response = self.client.post('/process-video', json={'video_key': 'video'})
        self.assertEqual(response.status_code, 202)
        self.assertEqual(self.events('completed')[0]['details']['outcome'], 'accepted')
        context = thread.call_args.kwargs['args'][1]
        self.patch('app._read_top_level_atoms', return_value=([{'type': 'moov'}, {'type': 'mdat'}], 10))
        source._do_process_video('video', context)
        done = self.events('background_completed')[0]
        self.assertEqual(done['details']['outcome'], 'already_optimized')
        self.assertEqual(done['request_id'], self.events('started')[0]['request_id'])

    def test_bulk_account_start_failure_prevents_account_update(self):
        self.actual_handlers()
        expiry = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.db.UserTable.put_item(Item={'email': 'student@example.test', 'is_paid': True, 'plan_id': 'paid', 'plan_valid_till': expiry})
        original = self.store.write
        def write(context, phase, details=None, event_id=None):
            if phase == 'account_started':
                raise AuditUnavailable()
            return original(context, phase, details, event_id)
        self.patch_object(self.store, 'write', side_effect=write)
        self.assertEqual(self.client.post('/cleanup-expired-plans').status_code, 500)
        self.assertEqual(self.db.UserTable.get_item(Key={'email': 'student@example.test'})['Item']['plan_valid_till'], expiry)
        self.assertEqual(self.events('completed')[0]['details']['outcome'], 'failed')

    def test_catalog_folder_create_edit_delete_tracks_entity_and_state(self):
        self.actual_handlers()
        self.resource.create_table(TableName='LectureCatalog', BillingMode='PAY_PER_REQUEST', KeySchema=KEY_SCHEMA,
                                   AttributeDefinitions=[{'AttributeName': name, 'AttributeType': 'S'} for name in ('pk', 'sk')])
        self.db.ExamTable.put_item(Item={'exam_id': 'exam', 'exam_name': 'Test', 'modules': []})
        response = self.client.post('/catalog/admin/exam/folders', json={'name': 'Folder'}, headers=self.token())
        self.assertEqual(response.status_code, 201)
        entity_id = response.get_json()['entity']['id']
        self.assertEqual(self.events('completed')[-1]['target']['entity_id'], entity_id)
        self.assertEqual(self.events('completed')[-1]['details']['after']['name'], 'Folder')
        self.assertEqual(self.client.put('/catalog/admin/exam/folders/' + entity_id, json={'name': 'Renamed'}, headers=self.token()).status_code, 200)
        done = self.events('completed')[-1]
        self.assertEqual(done['details']['before']['name'], 'Folder')
        self.assertEqual(done['details']['after']['name'], 'Renamed')
        self.assertEqual(self.client.delete('/catalog/admin/exam/folders/' + entity_id, headers=self.token()).status_code, 200)
        self.assertFalse(self.events('completed')[-1]['details']['after']['exists'])

    def test_graph_reset_records_partial_failure_without_changing_response_contract(self):
        self.actual_handlers()
        for email in ('one@example.test', 'two@example.test'):
            self.db.UserTable.put_item(Item={'email': email, 'solved_wrong': [1]})
        original = self.db.UserTable.update_item
        def update(**kwargs):
            if kwargs['Key']['email'] == 'two@example.test':
                raise RuntimeError('failure')
            return original(**kwargs)
        self.patch_object(self.db.UserTable, 'update_item', side_effect=update)
        response = self.client.post('/remove-graphs-all-users')
        self.assertEqual(response.status_code, 200)
        done = self.events('completed')[0]
        self.assertEqual(done['details']['outcome'], 'partial_success')
        self.assertEqual(done['details']['result']['failed_count'], 1)
        self.assertEqual({row['details']['outcome'] for row in self.events('account_completed')}, {'succeeded', 'failed'})

    def test_read_can_proceed_during_audit_outage_without_mutation(self):
        self.actual_handlers()
        self.patch('controller.admin_get_user', return_value={'status': 'success', 'user': {'email': 'account'}})
        self.patch_object(self.store, 'write', side_effect=AuditUnavailable())
        response = self.client.post('/admin/get-user', json={'email': 'account'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Admin-Audit-Status'], 'incomplete')

    def test_proxy_chain_is_untrusted_by_default(self):
        req = SimpleNamespace(remote_addr='192.0.2.1', headers={'X-Forwarded-For': '203.0.113.10, 198.51.100.1'})
        self.assertEqual(ip_details(req)['ip'], '192.0.2.1')
        self.assertEqual(ip_details(req, 1)['ip'], '198.51.100.1')
        self.assertEqual(ip_details(req, 2)['ip'], '203.0.113.10')
        req.headers['X-Forwarded-For'] = 'spoof, 198.51.100.1'
        self.assertEqual(ip_details(req, 2)['ip_source'], 'peer')
        req.headers['X-Forwarded-For'] = '2001:db8::1'
        self.assertEqual(ip_details(req, 1)['ip'], '2001:db8::1')
        req.headers['X-Forwarded-For'] = ', '.join(['203.0.113.99'] * 30 + ['198.51.100.1'])
        self.assertEqual(ip_details(req, 1)['ip'], '198.51.100.1')

    def test_retry_after_ambiguous_write_is_idempotent(self):
        context = AuditContext(self.store, 'test', 'POST', '/test', {}, {}, {})
        original = self.table.put_item
        calls = []
        def put(**kwargs):
            calls.append(kwargs['Item'])
            result = original(**kwargs)
            if len(calls) == 1:
                raise TimeoutError()
            return result
        self.patch_object(self.table, 'put_item', side_effect=put)
        self.store.write(context, 'started')
        self.assertEqual(len(self.events()), 1)
        self.assertEqual(calls[0]['sk'], calls[1]['sk'])

    def test_schema_is_idempotent_and_incompatible_table_is_not_changed(self):
        provision(self.resource)
        self.assertEqual(self.table.key_schema, KEY_SCHEMA)
        self.resource.create_table(TableName='WrongAudit', BillingMode='PAY_PER_REQUEST',
                                  KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
                                  AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}])
        with self.assertRaises(RuntimeError):
            provision(self.resource, 'WrongAudit')
        self.assertEqual(self.resource.Table('WrongAudit').key_schema[0]['AttributeName'], 'id')

    def test_all_god_mode_route_patterns_are_registered_and_audited(self):
        source = self.actual_handlers()
        expected = [('/grant-paid-access', 'POST'), ('/change-password', 'POST'), ('/export-users-by-plan', 'POST'),
                    ('/add-new-lecture', 'POST'), ('/update-lecture/<string:lecture_id>', 'PUT'),
                    ('/delete-lecture/<string:lecture_id>', 'DELETE'), ('/add-standalone-note', 'POST'),
                    ('/update-standalone-note/<string:note_id>', 'PUT'), ('/delete-standalone-note/<string:note_id>', 'DELETE'),
                    ('/generate-video-upload-url', 'POST'), ('/process-video', 'POST'), ('/delete-lecture-video', 'DELETE'),
                    ('/get-all-exam-details', 'GET'), ('/get-all-lectures/<string:exam_id>', 'GET'),
                    ('/get-standalone-notes/<string:exam_id>', 'GET'), ('/catalog/exams', 'GET'),
                    ('/catalog/admin/<exam>', 'GET'), ('/catalog/lectures/<lecture_id>/placement', 'GET'),
                    ('/catalog/admin/exams', 'POST'), ('/catalog/admin/exams/<exam>', 'PUT'),
                    ('/catalog/admin/<exam>/<kind>', 'POST'), ('/catalog/admin/<exam>/<kind>/<entity_id>', 'PUT'),
                    ('/catalog/admin/<exam>/<kind>/<entity_id>', 'DELETE'), ('/admin/exams/<string:exam_id>/toggle-status', 'PUT'),
                    ('/catalog/admin/lectures', 'POST'), ('/catalog/admin/lectures/<lecture_id>', 'PUT'),
                    ('/catalog/admin/lectures/<lecture_id>', 'DELETE')]
        rules = {(rule.rule, method): rule.endpoint for rule in source.app.url_map.iter_rules() for method in rule.methods}
        for rule, method in expected:
            self.assertIn((rule, method), rules)
            self.assertIsNotNone(action_for(rule, method, rules[(rule, method)]))
        for rule, method in [('/login', 'POST'), ('/submit-questions', 'POST'), ('/razorpay/order/complete', 'POST')]:
            self.assertIsNone(action_for(rule, method))
        self.assertIsNone(action_for('/grant-paid-access', 'OPTIONS'))

    def test_large_nested_metadata_is_bounded(self):
        metadata = {'instructor_details': {'placement': [{'placement': [{'name': 'a' * 2000} for _ in range(200)]} for _ in range(200)]}}
        safe = safe_fields(metadata)
        self.assertLess(len(json.dumps(safe)), 64000)


if __name__ == '__main__':
    unittest.main()
