"""Public auth/checkout errors against real handlers and mocked AWS only."""
from datetime import timedelta
import os
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import boto3
from botocore.exceptions import ClientError
from flask import Flask, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from moto import mock_aws
from requests.exceptions import Timeout

from api_errors import install_auth_errors
from payment_routes import create_payment_blueprint
from provision_payment_orders import provision


class PublicErrorTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws(); self.aws.start()
        self.env = patch.dict(os.environ, {'AWS_ACCESS_KEY_ID': 'testing', 'AWS_SECRET_ACCESS_KEY': 'testing'})
        self.env.start()
        import controller
        import app as source
        self.db = controller
        self.resource = boto3.resource('dynamodb', region_name='us-east-1')
        self.resource.create_table(TableName='User', BillingMode='PAY_PER_REQUEST',
            KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}])
        self.users = self.resource.Table('User')
        self.user_patch = patch.object(controller, 'UserTable', self.users); self.user_patch.start()
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, JWT_SECRET_KEY='test-public-error-secret-with-32-characters', JWT_TOKEN_LOCATION=['headers'])
        jwt = JWTManager(self.app); install_auth_errors(jwt)
        for path in ('login', 'register'):
            self.app.add_url_rule('/' + path, path, source.app.view_functions[path], methods=['POST'])
        @self.app.get('/protected')
        @jwt_required()
        def protected():
            return jsonify(ok=True)
        provision(self.resource)
        self.gateway = MagicMock()
        self.app.register_blueprint(create_payment_blueprint(SimpleNamespace(UserTable=self.users, dynamodb_resource=self.resource), self.gateway))
        self.client = self.app.test_client()

    def tearDown(self):
        self.user_patch.stop(); self.env.stop(); self.aws.stop()

    def assert_error(self, response, status, code):
        self.assertEqual(response.status_code, status)
        self.assertEqual(response.json['status'], 'error')
        self.assertEqual(response.json['code'], code)
        self.assertIsInstance(response.json['message'], str)
        self.assertTrue(response.json['message'])
        self.assertEqual(response.json['message'], response.json['msg'])
        self.assertEqual(response.json['message'], response.json['error'])

    def register(self, **changes):
        return self.client.post('/register', json=dict(email='student@example.test', password='test-password', fullName='Student', **changes))

    def headers(self, **options):
        with self.app.app_context():
            token = create_access_token(identity='student@example.test', **options)
        return {'Authorization': 'Bearer ' + token}

    def test_missing_wrong_type_and_malformed_payloads(self):
        for path in ('/login', '/register'):
            for body in (None, [], 'text', 3, {}, {'email': [], 'password': {}}, {'email': 'bad', 'password': 'pw'}, {'email': 'a@b.test', 'password': ''}):
                with self.subTest(path=path, body=body):
                    self.assert_error(self.client.post(path, json=body), 400, 'INVALID_INPUT')
            self.assert_error(self.client.post(path, data='{bad', content_type='application/json'), 400, 'INVALID_INPUT')
        self.assertEqual(self.users.scan()['Count'], 0)

    def test_successful_signup_and_login_keep_legacy_success_fields(self):
        response = self.register()
        self.assertEqual(response.status_code, 201); self.assertIn('message', response.json); self.assertIn('msg', response.json)
        response = self.client.post('/login', json={'email': 'student@example.test', 'password': 'test-password'})
        self.assertEqual(response.status_code, 200); self.assertIn('access_token_cookie', response.headers['Set-Cookie'])

    def test_duplicate_signup_never_overwrites_account(self):
        self.register(); before = self.users.get_item(Key={'email': 'student@example.test'})['Item']
        self.assert_error(self.register(), 409, 'ACCOUNT_EXISTS')
        self.assertEqual(self.users.get_item(Key={'email': 'student@example.test'})['Item'], before)

    def test_concurrent_signup_returns_existing_account_error(self):
        self.register()
        with patch.object(self.users, 'get_item', return_value={}):
            self.assert_error(self.register(), 409, 'ACCOUNT_EXISTS')

    def test_wrong_password_and_unknown_email_have_same_error(self):
        self.register()
        responses = [self.client.post('/login', json={'email': email, 'password': 'wrong'}) for email in ('student@example.test', 'missing@example.test')]
        for response in responses: self.assert_error(response, 401, 'INVALID_CREDENTIALS')
        self.assertEqual(responses[0].json, responses[1].json)

    def test_registration_validation(self):
        for changes in ({'fullName': '   '}, {'fullName': 123}, {'fullName': 'x' * 201}, {'password': 'é' * 37}):
            data = {'email': 'student@example.test', 'password': 'pw', 'fullName': 'Student', **changes}
            self.assert_error(self.client.post('/register', json=data), 400, 'INVALID_INPUT')

    def test_service_and_unexpected_errors_hide_internal_details(self):
        secret = 'private-database-credentials-and-details'
        for path in ('/register', '/login'):
            for error, status, code in [(ClientError({'Error': {'Code': 'ServiceUnavailable', 'Message': secret}}, 'GetItem'), 503, 'SERVICE_UNAVAILABLE'), (RuntimeError(secret), 500, 'INTERNAL_ERROR')]:
                with self.subTest(path=path, status=status), patch.object(self.users, 'get_item', side_effect=error):
                    response = self.client.post(path, json={'email': 'student@example.test', 'password': 'pw', 'fullName': 'Student'})
                    self.assert_error(response, status, code)
                    self.assertNotIn(secret, response.get_data(as_text=True))

    def test_session_errors_use_same_contract(self):
        self.assert_error(self.client.get('/protected'), 401, 'AUTH_REQUIRED')
        self.assert_error(self.client.get('/protected', headers=self.headers(expires_delta=timedelta(seconds=-10))), 401, 'SESSION_EXPIRED')
        self.assert_error(self.client.get('/protected', headers={'Authorization': 'Bearer bad'}), 401, 'SESSION_INVALID')
        self.assert_error(self.client.post('/razorpay/order/create', json={}), 401, 'AUTH_REQUIRED')

    def test_checkout_validation_and_missing_order_are_readable(self):
        self.assert_error(self.client.post('/razorpay/order/create', json={}, headers=self.headers()), 400, 'INVALID_PAYMENT_INPUT')
        self.assert_error(self.client.post('/razorpay/order/reconcile', json={'order_id': 'order_missing'}, headers=self.headers()), 404, 'PAYMENT_ORDER_NOT_FOUND')

    def test_checkout_outage_is_not_a_confirmed_payment_failure(self):
        self.register()
        self.gateway.order.create.side_effect = Timeout('private-gateway-details')
        response = self.client.post('/razorpay/order/create', json={'plan_id': 'ugc_net_full_course_v1', 'amount': 6500, 'months': 3}, headers=self.headers())
        self.assert_error(response, 503, 'PAYMENT_SERVICE_UNAVAILABLE')
        self.assertNotIn('private-gateway-details', response.get_data(as_text=True))

    def test_pending_payment_is_not_reported_as_failure(self):
        self.resource.Table('PaymentOrders').put_item(Item={'order_id': 'order_pending', 'user_email': 'student@example.test', 'status': 'pending'})
        self.gateway.order.payments.return_value = {'items': []}
        response = self.client.post('/razorpay/order/reconcile', json={'order_id': 'order_pending'}, headers=self.headers())
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json['status'], 'pending')
        self.assertIn('do not pay again', response.json['message'])


if __name__ == '__main__':
    unittest.main()
