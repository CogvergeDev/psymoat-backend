import unittest
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from dateutil import parser
from dateutil.relativedelta import relativedelta
import boto3
from moto import mock_aws
from flask import Flask
from flask_jwt_extended import JWTManager, decode_token
import controller

IST = ZoneInfo("Asia/Kolkata")


class PaymentEntitlementTests(unittest.TestCase):
    def setUp(self):
        self.aws = mock_aws()
        self.aws.start()
        self.resource = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')

        # Create User table
        self.resource.create_table(
            TableName='User',
            KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )

        # Create PaymentHistory table
        self.resource.create_table(
            TableName='PaymentHistory',
            KeySchema=[{'AttributeName': 'payment_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'payment_id', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )

        self.user_table = self.resource.Table('User')
        self.payment_table = self.resource.Table('PaymentHistory')

        self.orig_user_table = controller.UserTable
        self.orig_payment_table = controller.PaymentHistoryTable
        controller.UserTable = self.user_table
        controller.PaymentHistoryTable = self.payment_table

        # Setup Flask App context for JWT
        self.app = Flask(__name__)
        self.app.config['JWT_SECRET_KEY'] = 'test-secret-key-12345'
        self.jwt = JWTManager(self.app)
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()
        controller.UserTable = self.orig_user_table
        controller.PaymentHistoryTable = self.orig_payment_table
        self.aws.stop()

    def _create_user(self, email, **kwargs):
        item = {
            'email': email,
            'fullName': 'Test Student',
            'is_paid': False,
            'plan_id': 'free',
            'plan_valid_till': '',
            'exams_paid_for': [],
            'units_paid_for': []
        }
        item.update(kwargs)
        self.user_table.put_item(Item=item)
        return item

    def test_ugc_net_full_course_payment(self):
        email = "fullcourse@example.com"
        self._create_user(email)

        payment_data = {
            'payment_id': 'pay_full_123',
            'order_id': 'order_full_123',
            'amount': 500000,
            'signature': 'sig123',
            'created_at': datetime.now(IST).isoformat(),
            'user_email': email,
            'plan_id': 'ugc_net_full_course_v1',
            'months': 3
        }

        resp, status = controller.save_successful_payment(payment_data)
        self.assertEqual(status, 200)

        # Verify DynamoDB User Record
        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertTrue(user['is_paid'])
        self.assertEqual(user['plan_id'], 'ugc_net_full_course_v1')
        self.assertIn('qjPZtz_lecs', user['exams_paid_for'])
        self.assertIn('qjPZtz_mocks', user['exams_paid_for'])

        # Verify plan_valid_till ~ 3 months ahead
        valid_till = parser.parse(user['plan_valid_till'])
        expected_min = datetime.now(IST) + relativedelta(months=2, days=25)
        self.assertGreater(valid_till, expected_min)

    def test_ugc_net_units_payment(self):
        email = "units@example.com"
        self._create_user(email)

        payment_data = {
            'payment_id': 'pay_units_123',
            'order_id': 'order_units_123',
            'amount': 100000,
            'signature': 'sig123',
            'created_at': datetime.now(IST).isoformat(),
            'user_email': email,
            'plan_id': 'ugc_net_units_v1',
            'unit_ids': ['paper-2-emergence-of-psychology', 'paper-1-communication'],
            'months': 3
        }

        resp, status = controller.save_successful_payment(payment_data)
        self.assertEqual(status, 200)

        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertTrue(user['is_paid'])
        self.assertEqual(user['plan_id'], 'ugc_net_units_v1')
        self.assertEqual(set(user['units_paid_for']), {'paper-2-emergence-of-psychology', 'paper-1-communication'})
        # Verify mock tests are NOT granted
        exams = user.get('exams_paid_for', [])
        self.assertNotIn('qjPZtz_mocks', exams)

    def test_ugc_net_units_incremental_accumulation(self):
        email = "accumulate@example.com"
        self._create_user(email)

        # First purchase: Unit 1 and Unit 2
        controller.save_successful_payment({
            'payment_id': 'pay_1',
            'order_id': 'order_1',
            'amount': 100000,
            'signature': 'sig1',
            'created_at': datetime.now(IST).isoformat(),
            'user_email': email,
            'plan_id': 'ugc_net_units_v1',
            'unit_ids': ['paper-2-emergence-of-psychology', 'paper-2-research-methodology-and-statistics'],
            'months': 3
        })

        # Second purchase: Unit 2 and Unit 3 (Unit 2 is duplicate)
        controller.save_successful_payment({
            'payment_id': 'pay_2',
            'order_id': 'order_2',
            'amount': 100000,
            'signature': 'sig2',
            'created_at': datetime.now(IST).isoformat(),
            'user_email': email,
            'plan_id': 'ugc_net_units_v1',
            'unit_ids': ['paper-2-research-methodology-and-statistics', 'paper-2-psychological-testing'],
            'months': 3
        })

        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertEqual(len(user['units_paid_for']), 3)
        self.assertEqual(
            set(user['units_paid_for']),
            {
                'paper-2-emergence-of-psychology',
                'paper-2-research-methodology-and-statistics',
                'paper-2-psychological-testing'
            }
        )

    def test_grant_paid_access_full_course(self):
        email = "admin_full@example.com"
        self._create_user(email)

        valid_till = (datetime.now(IST) + relativedelta(months=3)).isoformat()
        res = controller.grant_paid_access(
            email=email,
            plan_id='ugc_net_full_course_v1',
            plan_valid_till=valid_till
        )
        self.assertEqual(res['status'], 'success')
        self.assertIn('qjPZtz_lecs', res['exams_paid_for'])
        self.assertIn('qjPZtz_mocks', res['exams_paid_for'])

        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertTrue(user['is_paid'])
        self.assertIn('qjPZtz_lecs', user['exams_paid_for'])
        self.assertIn('qjPZtz_mocks', user['exams_paid_for'])

    def test_grant_paid_access_modular_units(self):
        email = "admin_units@example.com"
        self._create_user(email)

        valid_till = (datetime.now(IST) + relativedelta(months=3)).isoformat()
        res = controller.grant_paid_access(
            email=email,
            plan_id='ugc_net_units_v1',
            plan_valid_till=valid_till,
            unit_ids=['paper-1-teaching-aptitude', 'paper-2-social-psychology']
        )
        self.assertEqual(res['status'], 'success')
        self.assertEqual(set(res['units_paid_for']), {'paper-1-teaching-aptitude', 'paper-2-social-psychology'})

        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertTrue(user['is_paid'])
        self.assertEqual(set(user['units_paid_for']), {'paper-1-teaching-aptitude', 'paper-2-social-psychology'})
        self.assertNotIn('qjPZtz_mocks', user.get('exams_paid_for', []))

    def test_delete_user_payment_fields(self):
        email = "delete_me@example.com"
        self._create_user(
            email,
            is_paid=True,
            plan_id='ugc_net_units_v1',
            plan_valid_till='2026-12-31T00:00:00',
            exams_paid_for=['some_exam'],
            units_paid_for=['paper-1-teaching-aptitude']
        )

        res = controller.delete_user_payment_fields(email)
        self.assertEqual(res['status'], 'success')

        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertIs(user['is_paid'], False)
        self.assertEqual(user['plan_id'], 'free')
        self.assertEqual(user['plan_valid_till'], '')
        self.assertEqual(user['exams_paid_for'], [])
        self.assertEqual(user['units_paid_for'], [])
        self.assertEqual(user['last_subscription_plan_id'], 'ugc_net_units_v1')
        self.assertEqual(user['last_subscription_valid_till'], '2026-12-31T00:00:00')

    def test_downgrade_preserves_credentials_payments_and_other_profile_fields(self):
        email = 'preserve@example.com'
        before = self._create_user(email, password='original-hash', fullName='Student',
                                  examsTaken=['exam1'], is_paid=True,
                                  plan_id='ugc_net_full_course_v1', plan_valid_till='2027-01-01T00:00:00+05:30')
        payment = {'payment_id': 'pay_preserved', 'user_email': email,
                   'status': 'captured', 'entitlement_applied': True, 'amount': 5000}
        self.payment_table.put_item(Item=payment)
        controller.delete_user_payment_fields(email)
        after = self.user_table.get_item(Key={'email': email})['Item']
        for key in ('password', 'fullName', 'examsTaken'):
            self.assertEqual(after[key], before[key])
        self.assertEqual(self.payment_table.get_item(Key={'payment_id': 'pay_preserved'})['Item'], payment)

    def test_downgrade_recreates_previously_deleted_fields_and_is_repeatable(self):
        email = 'missing-fields@example.com'
        self.user_table.put_item(Item={'email': email, 'password': 'original-hash',
                                      'last_subscription_plan_id': 'ugc_net_full_course_v1',
                                      'last_subscription_valid_till': '2027-01-06'})
        controller.delete_user_payment_fields(email)
        first = self.user_table.get_item(Key={'email': email})['Item']
        controller.delete_user_payment_fields(email)
        self.assertEqual(self.user_table.get_item(Key={'email': email})['Item'], first)
        self.assertEqual(first['last_subscription_valid_till'], '2027-01-06')
        self.assertIs(first['is_paid'], False)
        self.assertEqual(first['plan_id'], 'free')

    def test_cleanup_expired_user_plans(self):
        email = "expired@example.com"
        past_iso = (datetime.now(IST) - timedelta(days=10)).isoformat()
        self._create_user(
            email,
            is_paid=True,
            plan_id='ugc_net_units_v1',
            plan_valid_till=past_iso,
            exams_paid_for=['some_exam'],
            units_paid_for=['paper-1-teaching-aptitude']
        )

        res = controller.cleanup_expired_user_plans()
        self.assertEqual(res['status'], 'success')
        self.assertIn(email, res['cleaned_users'])

        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertIs(user['is_paid'], False)
        self.assertEqual(user['plan_id'], 'free')
        self.assertEqual(user['plan_valid_till'], '')
        self.assertEqual(user['last_subscription_plan_id'], 'ugc_net_units_v1')
        self.assertEqual(user['last_subscription_valid_till'], past_iso)
        self.assertEqual(user['exams_paid_for'], [])
        self.assertEqual(user['units_paid_for'], [])
        self.assertEqual(controller.cleanup_expired_user_plans()['count'], 0)

    def test_expired_free_account_can_purchase_again(self):
        email = 'renew_expired@example.com'
        past_iso = (datetime.now(IST) - timedelta(days=10)).isoformat()
        self._create_user(
            email, is_paid=True, plan_id='ugc_net_full_course_v1',
            plan_valid_till=past_iso, exams_paid_for=['qjPZtz_lecs', 'qjPZtz_mocks'],
        )
        controller.cleanup_expired_user_plans()
        response, status = controller.save_successful_payment({
            'payment_id': 'pay_renew', 'order_id': 'order_renew', 'amount': 500,
            'signature': 'signature', 'created_at': datetime.now(IST).isoformat(),
            'user_email': email, 'plan_id': 'ugc_net_units_v1', 'months': 3,
            'unit_ids': ['paper-1-teaching-aptitude'],
        })
        self.assertEqual(status, 200)
        user = self.user_table.get_item(Key={'email': email})['Item']
        self.assertTrue(user['is_paid'])
        self.assertEqual(user['plan_id'], 'ugc_net_units_v1')
        self.assertGreater(parser.parse(user['plan_valid_till']), datetime.now(IST) + timedelta(days=80))
        self.assertEqual(user['exams_paid_for'], [])
        self.assertEqual(user['units_paid_for'], ['paper-1-teaching-aptitude'])
        self.assertEqual(user['last_subscription_valid_till'], past_iso)

    def test_cleanup_keeps_active_subscription_unchanged(self):
        email = 'active@example.com'
        future = (datetime.now(IST) + timedelta(days=10)).isoformat()
        self._create_user(
            email, is_paid=True, plan_id='ugc_net_full_course_v1',
            plan_valid_till=future, exams_paid_for=['qjPZtz_lecs', 'qjPZtz_mocks'],
        )
        before = self.user_table.get_item(Key={'email': email})['Item']
        self.assertEqual(controller.cleanup_expired_user_plans()['count'], 0)
        self.assertEqual(self.user_table.get_item(Key={'email': email})['Item'], before)

    def test_get_user_defaults(self):
        email = "bare_user@example.com"
        # Item with no exams_paid_for or units_paid_for
        self.user_table.put_item(Item={
            'email': email,
            'fullName': 'Bare User',
            'password': 'hashed_pw'
        })

        user = controller.get_user(email)
        self.assertEqual(user['exams_paid_for'], [])
        self.assertEqual(user['units_paid_for'], [])
        self.assertNotIn('password', user)


if __name__ == '__main__':
    unittest.main()
