"""Real account handlers/transactions with mocked AWS and mocked Resend only."""
import json
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, get_jwt, jwt_required
from moto import mock_aws
from requests.exceptions import Timeout

import account_mail
from account_security import install_account_security
from api_errors import install_auth_errors
from provision_account_operations import provision


class AccountSecurityTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws(); self.aws.start()
        self.env = patch.dict(os.environ, {
            'AWS_ACCESS_KEY_ID': 'testing', 'AWS_SECRET_ACCESS_KEY': 'testing',
            'RESEND_API_KEY': 're_fake-never-used-live', 'EMAIL_FROM': 'Psymoat <developer@example.test>',
            'FRONTEND_URL': 'https://frontend.example.test', 'ACCOUNT_OPERATIONS_TABLE': 'AccountOperations',
            'ACCOUNT_TOKEN_SECRET': 'test-account-token-secret-with-32-characters',
            'EMAIL_RETRY_SECRET': 'test-email-retry-secret-with-32-characters', 'ACCOUNT_TRUSTED_PROXY_HOPS': '0',
        }); self.env.start()
        self.resource = boto3.resource('dynamodb', region_name='us-east-1')
        self.resource.create_table(TableName='User', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}], AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}])
        provision(self.resource)
        self.users = self.resource.Table('User'); self.jobs = self.resource.Table('AccountOperations')
        import controller
        import app as source
        self.db = controller
        self.patches = [patch.object(controller, 'UserTable', self.users),
                        patch.object(controller, 'dynamodb_resource', self.resource),
                        patch('account_mail.requests.post')]
        for context in self.patches: context.start()
        self.http = account_mail.requests.post
        self.http.return_value = MagicMock(status_code=200)
        self.http.return_value.json.return_value = {'id': 'email_mock'}
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, JWT_SECRET_KEY='test-session-secret-with-at-least-32-characters', JWT_TOKEN_LOCATION=['headers'], JWT_COOKIE_CSRF_PROTECT=False)
        jwt = JWTManager(self.app); install_auth_errors(jwt); install_account_security(self.app, self.db)
        for path in ('login', 'register', 'get-user', 'admin-change-password'):
            view = source.app.view_functions['change_password_route' if path == 'admin-change-password' else path.replace('-', '_')]
            self.app.add_url_rule('/' + path, endpoint=path, view_func=view, methods=['GET'] if path == 'get-user' else ['POST'])
        @self.app.get('/protected')
        @jwt_required()
        def protected():
            return jsonify(ok=True)
        @self.app.get('/refresh-protected')
        @jwt_required(refresh=True)
        def refresh_protected():
            return jsonify(ok=True)
        @self.app.get('/mint-during-reset')
        @jwt_required()
        def mint_during_reset():
            self.users.update_item(Key={'email': self.email}, UpdateExpression='SET password = :pw',
                ExpressionAttributeValues={':pw': self.db.bcrypt.generate_password_hash('race-password').decode()})
            return jsonify(token=create_access_token(identity=self.email))
        self.client = self.app.test_client()
        self.email = 'student@example.test'; self.password = 'old-password-123'
        self.users.put_item(Item={'email': self.email, 'user_id': 'student1', 'fullName': 'Student',
            'password': self.db.bcrypt.generate_password_hash(self.password).decode(), 'is_paid': False})

    def tearDown(self):
        for context in reversed(self.patches): context.stop()
        self.env.stop(); self.aws.stop()

    def headers(self, email=None, refresh=False, legacy=False):
        with self.app.app_context():
            jwt = self.app.extensions['flask-jwt-extended']
            with patch.object(jwt, '_user_claims_callback', return_value={}) if legacy else patch.object(jwt, '_user_claims_callback', wraps=jwt._user_claims_callback):
                token = (create_refresh_token if refresh else create_access_token)(identity=email or self.email)
        return {'Authorization': 'Bearer ' + token}

    def user(self, email=None):
        return self.users.get_item(Key={'email': email or self.email}, ConsistentRead=True).get('Item')

    def mails(self, kind=None):
        rows = [row for row in self.jobs.scan()['Items'] if row['pk'].startswith('MAIL#')]
        return [row for row in rows if kind is None or row['kind'] == kind]

    def forgot(self, email=None, **kwargs):
        return self.client.post('/forgot-password', json={'email': email or self.email}, **kwargs)

    def issue(self):
        response = self.forgot(); self.assertEqual(response.status_code, 200)
        row = self.mails('password_reset')[-1]
        with self.app.app_context(): token = account_mail.reset_token(row)
        return token, row

    def reset(self, token, password='new-password-456', **changes):
        return self.client.post('/reset-password', json={'token': token, 'new_password': password, 'confirm_password': password, **changes})

    def change(self, headers=None, **changes):
        return self.client.post('/account/change-password', headers=headers or self.headers(),
            json={'current_password': self.password, 'new_password': 'new-password-456', 'confirm_password': 'new-password-456', **changes})

    def test_welcome_is_atomic_and_contains_no_password(self):
        response = self.client.post('/register', json={'email': 'new@example.test', 'password': 'welcome-password', 'fullName': '<Student>'})
        self.assertEqual(response.status_code, 201)
        rows = self.mails('welcome'); self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['status'], 'accepted')
        payload = self.http.call_args.kwargs['json']
        self.assertIn('&lt;Student&gt;', payload['html']); self.assertNotIn('<Student>', payload['html'])
        self.assertNotIn('welcome-password', json.dumps(payload)); self.assertNotIn('password', rows[0])

    def test_welcome_provider_outage_does_not_fail_signup(self):
        self.http.side_effect = Timeout('private provider exception')
        response = self.client.post('/register', json={'email': 'new@example.test', 'password': 'welcome-password', 'fullName': 'Student'})
        self.assertEqual(response.status_code, 201); self.assertEqual(response.json['email_status'], 'queued')
        self.assertIsNotNone(self.user('new@example.test'))
        row = self.mails('welcome')[0]; self.assertEqual(row['status'], 'pending'); self.assertIn('uncertain_since', row)
        self.assertNotIn('private provider exception', json.dumps(row, default=str))

    def test_signup_outbox_missing_never_leaves_partial_account(self):
        self.jobs.delete()
        response = self.client.post('/register', json={'email': 'new@example.test', 'password': 'welcome-password', 'fullName': 'Student'})
        self.assertEqual(response.status_code, 503); self.assertIsNone(self.user('new@example.test'))

    def test_forgot_has_same_response_for_existing_unknown_and_provider_outage(self):
        self.http.side_effect = Timeout()
        unknown = self.forgot('unknown@example.test')
        self.assertEqual(self.mails('password_reset'), [])
        self.http.assert_not_called()
        known = self.forgot()
        self.assertEqual(known.status_code, 200); self.assertEqual(known.json, unknown.json)
        self.assertEqual(self.http.call_count, 1)

    def test_bad_link_configuration_has_same_error_for_every_email(self):
        with patch.dict(os.environ, {'FRONTEND_URL': 'http://untrusted.example.test'}):
            known = self.forgot(); unknown = self.forgot('unknown@example.test')
        self.assertEqual(known.status_code, 503); self.assertEqual(known.json, unknown.json)
        self.assertEqual(self.http.call_count, 0)

    def test_missing_mail_configuration_keeps_welcome_retryable(self):
        with patch.dict(self.app.config, {'JWT_SECRET_KEY': 'short'}), patch.dict(os.environ, {'ACCOUNT_TOKEN_SECRET': '', 'RESEND_API_KEY': ''}):
            response = self.client.post('/register', json={'email': 'new@example.test', 'password': 'welcome-password', 'fullName': 'Student'})
        self.assertEqual(response.status_code, 201); self.assertEqual(response.json['email_status'], 'queued')
        self.assertEqual(self.http.call_count, 0)
        row = self.mails('welcome')[0]
        self.assertEqual(row['error_category'], 'configuration'); self.assertNotIn('uncertain_since', row)

    def test_reset_token_not_stored_in_database_or_returned_to_browser(self):
        token, job = self.issue()
        raw = json.dumps(self.jobs.scan()['Items'], default=str)
        self.assertNotIn(token, raw); self.assertNotIn(token, json.dumps(self.forgot().json))
        self.assertEqual(self.user()['password_reset_digest'], account_mail.token_digest(token))
        payload = self.http.call_args.kwargs['json']
        self.assertIn('/reset-password#token=', payload['text'])
        self.assertEqual(int(job['expires_at'] - job['created_at']), 1800)

    def test_profile_and_admin_read_hide_reset_state(self):
        self.issue()
        response = self.client.get('/get-user', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        for value in (response.json, self.db.admin_get_user(self.email)['user']):
            self.assertNotIn('password', value)
            self.assertFalse(any(key.startswith('password_reset_') for key in value))

    def test_reset_single_use_sends_confirmation_and_expires_cookies(self):
        token, _ = self.issue()
        response = self.reset(token)
        self.assertEqual(response.status_code, 200)
        self.assertIn('Expires=Thu, 01 Jan 1970', str(response.headers.getlist('Set-Cookie')))
        self.assertTrue(self.db.bcrypt.check_password_hash(self.user()['password'], 'new-password-456'))
        self.assertNotIn('password_reset_digest', self.user())
        self.assertEqual(len(self.mails('password_changed')), 1)
        self.assertEqual(self.reset(token).status_code, 400)
        self.assertEqual(len(self.mails('password_changed')), 1)

    def test_reset_invalidates_access_refresh_and_legacy_sessions(self):
        access = self.headers(); refresh = self.headers(refresh=True); legacy = self.headers(legacy=True)
        self.assertEqual(self.client.get('/protected', headers=access).status_code, 200)
        token, _ = self.issue(); self.assertEqual(self.reset(token).status_code, 200)
        self.assertEqual(self.client.get('/protected', headers=access).status_code, 401)
        self.assertEqual(self.client.get('/refresh-protected', headers=refresh).status_code, 401)
        self.assertEqual(self.client.get('/protected', headers=legacy).status_code, 401)
        self.assertEqual(self.client.get('/protected', headers=self.headers()).status_code, 200)

    def test_new_login_works_immediately_after_password_change(self):
        token, _ = self.issue(); self.reset(token)
        for password, status in [(self.password, 401), ('new-password-456', 200)]:
            response = self.client.post('/login', json={'email': self.email, 'password': password})
            self.assertEqual(response.status_code, status)

    def test_expired_and_tampered_links_fail_without_mutation(self):
        token, _ = self.issue(); before = self.user()['password']
        self.assertEqual(self.reset(token[:-1] + ('a' if token[-1] != 'a' else 'b')).status_code, 400)
        with patch('account_security.time.time', return_value=time.time() + 1801):
            self.assertEqual(self.reset(token).status_code, 400)
        self.assertEqual(self.user()['password'], before)

    def test_requesting_a_new_link_invalidates_previous_link(self):
        token, _ = self.issue()
        with patch('account_security.time.time', return_value=time.time() + 61):
            self.assertEqual(self.forgot().status_code, 200)
        self.assertEqual(self.reset(token).status_code, 400)
        self.assertEqual(len(self.mails('password_reset')), 2)

    def test_repeat_requests_are_durable_and_do_not_send_again(self):
        with patch('account_mail.time.time', return_value=time.time()):
            first = self.forgot()
            # A fresh browser still uses the same persisted cooldown.
            response = self.app.test_client().post('/forgot-password', json={'email': self.email})
        self.assertEqual(first.json, response.json); self.assertEqual(len(self.mails('password_reset')), 1)
        self.assertEqual(self.http.call_count, 1)

    def test_reset_cooldown_and_hourly_cap_are_identical_for_every_address(self):
        start = int(time.time())
        for offset, retry_after, remaining in [
            (0, 60, 4), (59, 1, 4), (60, 120, 3), (180, 180, 2),
            (360, 240, 1), (600, 3000, 0), (601, 2999, 0), (3600, 60, 4),
        ]:
            with self.subTest(offset=offset), patch('account_mail.time.time', return_value=start + offset):
                known = self.forgot(environ_overrides={'REMOTE_ADDR': '192.0.2.1'})
                unknown = self.forgot('unknown@example.test', environ_overrides={'REMOTE_ADDR': '192.0.2.2'})
                self.assertEqual(known.status_code, 200)
                self.assertEqual(known.json, unknown.json)
                self.assertEqual(known.json['retry_after'], retry_after)
                self.assertEqual(known.json['attempts_remaining'], remaining)
        self.assertEqual(len(self.mails('password_reset')), 6)
        self.assertEqual(self.http.call_count, 6)

    def test_branded_templates_keep_the_logo_separate_from_reset_links(self):
        with self.app.app_context():
            for kind, route in [('welcome', '/login'), ('password_reset', '/reset-password#token='),
                                ('password_changed', '/forgot-password')]:
                job = account_mail.new_job(kind, self.email, name='Student')
                branded = account_mail.render_job(job)
                previous = account_mail.render_job({**job, 'template_version': 1})
                self.assertIn('src="https://frontend.example.test/images/logo.jpeg"', branded['html'])
                self.assertNotIn('<img ', previous['html'])
                self.assertIn('href="https://frontend.example.test' + route, branded['html'])
                self.assertIn('https://frontend.example.test' + route, branded['text'])
                self.assertEqual(branded['subject'], previous['subject'])

    def test_forgot_ip_limit_ignores_spoofed_forwarded_headers(self):
        for i in range(10):
            self.assertEqual(self.forgot(f'unknown{i}@example.test', headers={'X-Forwarded-For': str(i)}).status_code, 200)
        self.assertEqual(self.forgot('unknown11@example.test', headers={'X-Forwarded-For': 'different'}).status_code, 429)

    def test_reset_rate_limit(self):
        for _ in range(20): self.assertEqual(self.reset('invalid').status_code, 400)
        self.assertEqual(self.reset('invalid').status_code, 429)

    def test_password_validation_is_backend_enforced(self):
        token, _ = self.issue(); before = self.user()['password']
        for password in ('short', 'é' * 37, ' ' * 10):
            self.assertEqual(self.reset(token, password=password).status_code, 400)
        self.assertEqual(self.reset(token, confirm_password='different').status_code, 400)
        self.assertEqual(self.reset(token, password=self.password).status_code, 400)
        self.assertEqual(self.user()['password'], before); self.assertEqual(len(self.mails('password_changed')), 0)

    def test_change_requires_session_and_current_password(self):
        self.assertEqual(self.client.post('/account/change-password', json={}).status_code, 401)
        before = self.user()['password']
        self.assertEqual(self.change(current_password='wrong').status_code, 400)
        self.assertEqual(self.user()['password'], before)

    def test_profile_changes_only_authenticated_account_and_revokes_sessions(self):
        self.users.put_item(Item={'email': 'other@example.test', 'password': 'unchanged'})
        headers = self.headers(); self.issue()
        self.assertEqual(self.change(headers, email='other@example.test').status_code, 200)
        self.assertEqual(self.user('other@example.test')['password'], 'unchanged')
        self.assertNotIn('password_reset_digest', self.user())
        self.assertEqual(self.client.get('/protected', headers=headers).status_code, 401)

    def test_wrong_current_password_is_rate_limited(self):
        headers = self.headers()
        for _ in range(5): self.assertEqual(self.change(headers, current_password='wrong').status_code, 400)
        self.assertEqual(self.change(headers, current_password='wrong').status_code, 429)

    def test_concurrent_password_change_cannot_commit_partial_confirmation(self):
        token, _ = self.issue()
        client = self.users.meta.client; original = client.transact_write_items
        def race(**kwargs):
            self.users.update_item(Key={'email': self.email}, UpdateExpression='SET password = :pw', ExpressionAttributeValues={':pw': 'concurrently-changed'})
            return original(**kwargs)
        with patch.object(client, 'transact_write_items', side_effect=race):
            self.assertEqual(self.reset(token).status_code, 400)
        self.assertEqual(self.user()['password'], 'concurrently-changed')
        self.assertEqual(len(self.mails('password_changed')), 0)

    def test_confirmation_failure_does_not_undo_password_change(self):
        token, _ = self.issue(); self.http.side_effect = Timeout()
        response = self.reset(token)
        self.assertEqual(response.status_code, 200); self.assertEqual(response.json['email_status'], 'queued')
        self.assertTrue(self.db.bcrypt.check_password_hash(self.user()['password'], 'new-password-456'))
        self.assertEqual(self.mails('password_changed')[0]['status'], 'pending')

    def test_interrupted_acknowledgement_retries_same_provider_payload_and_key(self):
        job = account_mail.new_job('welcome', self.email, name='Student')
        self.jobs.put_item(Item=job)
        with patch('account_mail.finish', side_effect=RuntimeError('ack lost')):
            self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'queued')
        before = self.http.call_args.kwargs
        with patch('account_mail.time.time', return_value=time.time() + 91):
            self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'accepted')
        self.assertEqual(before['headers']['Idempotency-Key'], self.http.call_args.kwargs['headers']['Idempotency-Key'])
        self.assertEqual(before['json'], self.http.call_args.kwargs['json'])

    def test_concurrent_dispatchers_cannot_send_twice(self):
        job = account_mail.new_job('welcome', self.email, name='Student'); self.jobs.put_item(Item=job)
        response = MagicMock(status_code=200); response.json.return_value = {'id': 'email_mock'}
        def during_send(*args, **kwargs):
            self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'pending')
            return response
        self.http.side_effect = during_send
        self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'accepted')
        self.assertEqual(self.http.call_count, 1)

    def test_ambiguous_delivery_is_never_retried_outside_deduplication_window(self):
        job = account_mail.new_job('welcome', self.email); self.jobs.put_item(Item=job)
        self.http.side_effect = Timeout(); account_mail.try_deliver(self.db, job['pk'])
        with patch('account_mail.time.time', return_value=time.time() + 23 * 3600 + 1):
            self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'needs_review')
        self.assertEqual(self.http.call_count, 1)

    def test_explicit_provider_rejection_can_retry_after_window(self):
        job = account_mail.new_job('welcome', self.email); self.jobs.put_item(Item=job)
        self.http.return_value.status_code = 429
        account_mail.try_deliver(self.db, job['pk'])
        self.assertNotIn('uncertain_since', self.jobs.get_item(Key={'pk': job['pk']})['Item'])
        self.http.return_value.status_code = 200
        with patch('account_mail.time.time', return_value=time.time() + 2 * 86400):
            self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'accepted')

    def test_superseded_reset_job_is_not_sent(self):
        self.http.side_effect = Timeout()
        token, job = self.issue(); self.http.side_effect = None
        self.assertEqual(self.reset(token).status_code, 200)
        before = self.http.call_count
        with patch('account_mail.time.time', return_value=time.time() + 61):
            self.assertEqual(account_mail.try_deliver(self.db, job['pk']), 'superseded')
        self.assertEqual(self.http.call_count, before)

    def test_retry_endpoint_is_secret_protected(self):
        self.assertEqual(self.client.post('/internal/retry-account-emails').status_code, 401)
        self.assertEqual(self.client.post('/internal/retry-account-emails', headers={'Authorization': 'Bearer ñ'}).status_code, 401)
        self.assertEqual(self.client.post('/internal/retry-account-emails', headers={'Authorization': os.environ['EMAIL_RETRY_SECRET']}).status_code, 401)
        response = self.client.post('/internal/retry-account-emails', headers={'Authorization': 'Bearer ' + os.environ['EMAIL_RETRY_SECRET']})
        self.assertEqual(response.status_code, 200); self.assertEqual(response.json, {'checked': 0, 'accepted': 0})

    def test_session_minted_during_password_reset_is_still_revoked(self):
        response = self.client.get('/mint-during-reset', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get('/protected', headers={'Authorization': 'Bearer ' + response.json['token']}).status_code, 401)

    def test_session_database_outage_is_retryable_not_logout(self):
        headers = self.headers()
        with patch.object(self.users, 'get_item', side_effect=ClientError({'Error': {'Code': 'Unavailable'}}, 'GetItem')):
            self.assertEqual(self.client.get('/protected', headers=headers).status_code, 503)

    def test_real_cookie_sign_in_change_and_sign_in_again(self):
        self.app.config.update(JWT_TOKEN_LOCATION=['cookies'], JWT_COOKIE_SECURE=False)
        response = self.client.post('/login', json={'email': self.email, 'password': self.password})
        self.assertEqual(response.status_code, 200)
        cookie = self.client.get_cookie('access_token_cookie').value
        self.assertEqual(self.client.get('/protected').status_code, 200)
        response = self.client.post('/account/change-password', json={
            'current_password': self.password, 'new_password': 'cookie-password-456', 'confirm_password': 'cookie-password-456'})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(self.client.get_cookie('access_token_cookie'))
        other = self.app.test_client(); other.set_cookie('access_token_cookie', cookie)
        self.assertEqual(other.get('/protected').status_code, 401)
        response = self.client.post('/login', json={'email': self.email, 'password': 'cookie-password-456'})
        self.assertEqual(response.status_code, 200); self.assertEqual(self.client.get('/protected').status_code, 200)

    def test_configured_proxy_uses_the_trusted_rightmost_address(self):
        with patch.dict(os.environ, {'ACCOUNT_TRUSTED_PROXY_HOPS': '1'}):
            for i in range(11):
                response = self.forgot(f'unknown{i}@example.test', headers={'X-Forwarded-For': f'203.0.113.1, 198.51.100.{i}'})
                self.assertEqual(response.status_code, 200)

    def test_admin_endpoint_is_renamed_with_existing_behavior_preserved(self):
        self.assertEqual(self.client.post('/change-password', json={}).status_code, 404)
        self.assertEqual(self.client.post('/admin-change-password', json={'email': self.email, 'new_password': 'admin-new-password'}).status_code, 200)

    def test_provisioning_is_idempotent(self):
        self.assertEqual(provision(self.resource)['TableName'], 'AccountOperations')
        self.assertEqual(self.resource.meta.client.describe_time_to_live(TableName='AccountOperations')['TimeToLiveDescription']['AttributeName'], 'ttl')


if __name__ == '__main__':
    unittest.main()
