import unittest
from datetime import datetime

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

import subscription_reconciliation as reconciliation


NOW = datetime(2026, 10, 4, 22, tzinfo=reconciliation.IST)


def payment(**overrides):
    value = {
        'payment_id': 'pay_one', 'user_email': 'student@example.com',
        'created_at': '2026-04-23T20:09:30+05:30', 'status': 'captured',
        'plan_id': 'ugc_net_advanced_monthly_v1', 'months': 1,
    }
    value.update(overrides)
    return value


class SubscriptionDecisionTests(unittest.TestCase):
    def test_expired_payment_restores_free_and_purchase_history(self):
        user = {'email': 'student@example.com', 'exams_paid_for': ['qjPZtz_lecs']}
        result = reconciliation.missing_subscription_decision(user, [payment()], NOW)
        fields = result['changes']
        self.assertFalse(fields['is_paid'])
        self.assertEqual(fields['plan_id'], 'free')
        self.assertEqual(fields['plan_valid_till'], '')
        self.assertEqual(fields['last_subscription_valid_till'], '2026-05-23T20:09:30+05:30')
        self.assertEqual(fields['last_subscription_plan_id'], 'ugc_net_advanced_monthly_v1')
        self.assertEqual(fields['exams_paid_for'], [])
        self.assertEqual(fields['units_paid_for'], [])

    def test_failed_payment_does_not_extend_expiry(self):
        failed = payment(payment_id='pay_failed', status='failed', created_at='2026-10-03T10:00:00+05:30')
        result = reconciliation.reconstruct_expiry([payment(), failed])
        self.assertEqual(result['expiry'].month, 5)

    def test_legacy_missing_duration_uses_six_month_default(self):
        old = payment(plan_id='netjrf_advanced_v1', created_at='2025-08-26T13:09:03+05:30')
        del old['months']
        result = reconciliation.reconstruct_expiry([old])
        self.assertEqual(result['expiry'].isoformat(), '2026-02-26T13:09:03+05:30')
        self.assertEqual(result['source'], 'payment_history_legacy_duration')

    def test_active_recorded_subscription_is_never_downgraded(self):
        active = payment(created_at='2026-10-03T13:32:12+05:30', months=3, plan_id='ugc_net_full_course_v1')
        result = reconciliation.missing_subscription_decision({'email': 'student@example.com'}, [active], NOW)
        self.assertEqual(result['changes'], {})
        self.assertEqual(result['reason'], 'active_subscription_requires_review')

    def test_future_manual_expiry_is_preserved_over_old_payment(self):
        user = {'email': 'student@example.com', 'plan_valid_till': '2027-01-03T13:32:12+05:30'}
        self.assertEqual(reconciliation.missing_subscription_decision(user, [payment()], NOW)['changes'], {})

    def test_no_history_with_no_permissions_gets_free_defaults(self):
        result = reconciliation.missing_subscription_decision({'email': 'student@example.com'}, [], NOW)
        self.assertEqual(result['changes'], {
            'is_paid': False, 'plan_id': 'free', 'plan_valid_till': '',
            'exams_paid_for': [], 'units_paid_for': [],
        })

    def test_undocumented_manual_permissions_remain_unchanged(self):
        user = {'email': 'student@example.com', 'exams_paid_for': ['qjPZtz_lecs']}
        result = reconciliation.missing_subscription_decision(user, [], NOW)
        self.assertEqual(result['changes'], {})
        self.assertEqual(result['reason'], 'permissions_without_expiry_or_payment')

    def test_bad_dates_and_duration_require_review(self):
        for overrides in [{'created_at': 'broken'}, {'months': 'invalid'}, {'months': '1.5'}, {'months': 0}, {'months': -1}]:
            with self.subTest(overrides=overrides):
                result = reconciliation.missing_subscription_decision({'email': 'student@example.com'}, [payment(**overrides)], NOW)
                self.assertEqual(result['changes'], {})
                self.assertEqual(result['reason'], 'unreadable_payment_or_expiry')

    def test_renewals_extend_since_august_and_reset_before_it(self):
        first = payment(created_at='2026-08-11T10:00:00+05:30', months=3)
        second = payment(payment_id='pay_two', created_at='2026-09-11T10:00:00+05:30', months=3)
        result = reconciliation.reconstruct_expiry([second, first])
        self.assertEqual(result['expiry'].isoformat(), '2027-02-11T10:00:00+05:30')
        first['created_at'], second['created_at'] = '2026-04-11T10:00:00+05:30', '2026-05-11T10:00:00+05:30'
        self.assertEqual(reconciliation.reconstruct_expiry([first, second])['expiry'].month, 8)

    def test_repeated_payment_id_does_not_extend_twice(self):
        purchase = payment(created_at='2026-08-11T10:00:00+05:30', months=3)
        self.assertEqual(reconciliation.reconstruct_expiry([purchase, purchase])['expiry'].month, 11)

    def test_utc_and_legacy_offset_z_dates(self):
        self.assertEqual(reconciliation.parse_expiry('2026-05-23T14:39:30Z').isoformat(), '2026-05-23T20:09:30+05:30')
        self.assertEqual(reconciliation.parse_expiry('2026-05-23T20:09:30+05:30Z').hour, 20)


@mock_aws
class SubscriptionDatabaseTests(unittest.TestCase):
    def setUp(self):
        resource = boto3.resource('dynamodb', region_name='us-east-1', aws_access_key_id='testing', aws_secret_access_key='testing')
        self.users = resource.create_table(
            TableName='User', KeySchema=[{'AttributeName': 'email', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'email', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST',
        )
        self.payments = resource.create_table(
            TableName='PaymentHistoryTable', KeySchema=[{'AttributeName': 'payment_id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'payment_id', 'AttributeType': 'S'}], BillingMode='PAY_PER_REQUEST',
        )

    def test_update_preserves_credentials_and_test_history_and_is_idempotent(self):
        original = {'email': 'student@example.com', 'user_id': 'one', 'password': 'opaque-hash', 'examsTaken': ['test1'], 'exams_paid_for': ['qjPZtz_lecs']}
        self.users.put_item(Item=original)
        self.payments.put_item(Item=payment())
        _, affected, decisions = reconciliation.reconciliation_preview(self.users, self.payments, NOW)
        reconciliation.conditional_state_update(self.users, affected[0], decisions[0]['changes'])
        updated = self.users.get_item(Key={'email': original['email']})['Item']
        self.assertEqual(updated['password'], 'opaque-hash')
        self.assertEqual(updated['examsTaken'], ['test1'])
        self.assertEqual(self.payments.get_item(Key={'payment_id': 'pay_one'})['Item']['status'], 'captured')
        self.assertEqual(reconciliation.reconciliation_preview(self.users, self.payments, NOW)[1], [])

    def test_concurrent_purchase_is_not_overwritten(self):
        original = {'email': 'student@example.com', 'user_id': 'one'}
        self.users.put_item(Item=original)
        self.users.update_item(Key={'email': original['email']}, UpdateExpression='SET is_paid = :paid', ExpressionAttributeValues={':paid': True})
        with self.assertRaises(ClientError) as error:
            reconciliation.conditional_state_update(self.users, original, reconciliation.free_subscription_fields(original))
        self.assertEqual(error.exception.response['Error']['Code'], 'ConditionalCheckFailedException')

    def test_deleted_account_is_not_recreated(self):
        original = {'email': 'student@example.com'}
        with self.assertRaises(ClientError):
            reconciliation.conditional_state_update(self.users, original, reconciliation.free_subscription_fields(original))
        self.assertNotIn('Item', self.users.get_item(Key={'email': original['email']}))

    def test_capitalization_in_payment_email_is_reconciled_without_merging_users(self):
        self.users.put_item(Item={'email': 'Student@example.com'})
        self.payments.put_item(Item=payment())
        _, users, decisions = reconciliation.reconciliation_preview(self.users, self.payments, NOW)
        self.assertEqual(users[0]['email'], 'Student@example.com')
        self.assertEqual(decisions[0]['reason'], 'expired_subscription')

    def test_scan_reads_every_page(self):
        class PaginatedTable:
            def scan(self, **args):
                if 'ExclusiveStartKey' not in args:
                    return {'Items': [{'email': 'first@example.com'}], 'LastEvaluatedKey': {'email': 'first@example.com'}}
                return {'Items': [{'email': 'second@example.com'}]}
        self.assertEqual(len(reconciliation.scan_fields(PaginatedTable(), ('email',))), 2)


if __name__ == '__main__':
    unittest.main()
