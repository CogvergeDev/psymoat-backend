"""Exercise real payment HTTP handlers and DynamoDB transactions; no live writes."""
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch
import boto3
from flask import Flask
from flask_jwt_extended import JWTManager, create_access_token
from moto import mock_aws
from admin_audit import AuditStore, install_admin_audit
from payment_routes import create_payment_blueprint, ORDER_TABLE
from payment_settlement import settle_payment, SettlementConflict
from provision_payment_orders import provision
from provision_admin_audit import provision as provision_audit

class PaymentRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.aws=mock_aws(); self.aws.start()
        self.env=patch.dict(os.environ,{'RAZORPAY_WEBHOOK_SECRET':'webhook-test-secret','AWS_ACCESS_KEY_ID':'testing','AWS_SECRET_ACCESS_KEY':'testing'}); self.env.start()
        self.resource=boto3.resource('dynamodb',region_name='us-east-1')
        for name,key in [('User','email'),('PaymentHistory','payment_id')]:
            self.resource.create_table(TableName=name,BillingMode='PAY_PER_REQUEST',KeySchema=[{'AttributeName':key,'KeyType':'HASH'}],AttributeDefinitions=[{'AttributeName':key,'AttributeType':'S'}])
        provision(self.resource); provision_audit(self.resource)
        self.users=self.resource.Table('User'); self.payments=self.resource.Table('PaymentHistory'); self.orders=self.resource.Table(ORDER_TABLE)
        db=SimpleNamespace(UserTable=self.users,PaymentHistoryTable=self.payments,dynamodb_resource=self.resource)
        self.gateway=MagicMock()
        self.gateway.order.create.return_value={'id':'order_test','amount':500000,'currency':'INR'}
        self.payment={'id':'pay_test','order_id':'order_test','amount':500000,'currency':'INR','status':'captured','amount_refunded':0,'created_at':int(datetime.now(timezone.utc).timestamp())}
        self.gateway.payment.fetch.return_value=self.payment
        self.gateway.order.payments.return_value={'items':[self.payment]}
        self.gateway.order.fetch.return_value={'amount':500000,'currency':'INR','notes':{}}
        self.app=Flask(__name__); self.app.config.update(TESTING=True,JWT_SECRET_KEY='test-payment-secret-with-32-characters',JWT_TOKEN_LOCATION=['headers']); JWTManager(self.app)
        install_admin_audit(self.app,db,AuditStore(self.resource.Table('AdminAuditLogs')))
        self.app.register_blueprint(create_payment_blueprint(db,self.gateway)); self.client=self.app.test_client(); self.email='student@test.com'
        for email in [self.email,'other@test.com']:
            self.users.put_item(Item={'email':email,'password':'private-unchanged-hash','is_paid':False,'plan_id':'free','plan_valid_till':'','exams_paid_for':[],'units_paid_for':[]})
    def tearDown(self):
        self.env.stop(); self.aws.stop()
    def post(self,path,data=None,email=None):
        with self.app.app_context(): token=create_access_token(identity=email or self.email)
        return self.client.post('/razorpay/'+path,json=data or {},headers={'Authorization':'Bearer '+token})
    def create(self,**changes):
        return self.post('order/create',dict({'plan_id':'ugc_net_full_course_v1','amount':5000,'months':3},**changes))
    def complete(self,**changes):
        return self.post('order/complete',dict({'payment_id':'pay_test','order_id':'order_test','signature':'secret-signature','plan_id':'ugc_net_full_course_v1','amount':5000,'months':3},**changes))
    def webhook(self,event='payment.captured'):
        raw=json.dumps({'event':event,'payload':{'payment':{'entity':self.payment}}},indent=2).encode()
        signature=hmac.new(b'webhook-test-secret',raw,hashlib.sha256).hexdigest()
        return self.client.post('/razorpay/webhook',data=raw,content_type='application/json',headers={'X-Razorpay-Signature':signature})
    def user(self):
        return self.users.get_item(Key={'email':self.email},ConsistentRead=True)['Item']
    def data(self,**changes):
        return dict({'user_email':self.email,'payment_id':'pay_test','order_id':'order_test','plan_id':'ugc_net_full_course_v1','amount':5000,'months':3,'created_at':datetime.now(timezone.utc).isoformat()},**changes)
    def test_order_intent_is_durable_before_checkout(self):
        self.assertEqual(self.create().status_code,200)
        row=self.orders.get_item(Key={'order_id':'order_test'})['Item']
        self.assertEqual(row['user_email'],self.email); self.assertEqual(row['amount_paise'],500000); self.assertEqual(row['months'],3); self.assertFalse(self.user()['is_paid'])
    def test_lost_callback_recovers_on_login(self):
        self.create(); r=self.post('orders/reconcile'); self.assertEqual(r.status_code,200); self.assertEqual(r.json['count'],1)
        self.assertTrue(self.user()['is_paid']); self.assertEqual(set(self.user()['exams_paid_for']),{'qjPZtz_lecs','qjPZtz_mocks'}); self.assertEqual(self.user()['password'],'private-unchanged-hash')
        self.assertTrue(self.payments.get_item(Key={'payment_id':'pay_test'})['Item']['entitlement_applied']); self.assertNotIn('pending_user',self.orders.get_item(Key={'order_id':'order_test'})['Item'])
    def test_callback_and_webhook_replays_extend_only_once(self):
        self.create(); self.assertEqual(self.complete().status_code,200); expiry=self.user()['plan_valid_till']
        for r in [self.complete(),self.webhook(),self.webhook('order.paid')]:
            self.assertEqual(r.status_code,200); self.assertFalse(r.json['applied'])
        self.assertEqual(self.user()['plan_valid_till'],expiry); self.assertEqual(self.payments.scan()['Count'],1)
    def test_webhook_can_arrive_before_callback(self):
        self.create(); self.assertEqual(self.webhook().status_code,200); expiry=self.user()['plan_valid_till']; self.assertFalse(self.complete().json['applied']); self.assertEqual(self.user()['plan_valid_till'],expiry)
    def test_failed_transaction_cannot_leave_partial_payment_or_access(self):
        before=self.user()
        with self.assertRaises(SettlementConflict): settle_payment(self.users,self.payments,self.data(),orders=self.orders)
        self.assertEqual(self.user(),before); self.assertEqual(self.payments.scan()['Count'],0)
    def test_concurrent_access_change_is_preserved_on_retry(self):
        client=self.users.meta.client; original=client.transact_write_items; seen=[]
        def race(**kw):
            if not seen:
                seen.append(True)
                self.users.update_item(Key={'email':self.email},UpdateExpression='SET units_paid_for = :u, is_paid = :p, plan_valid_till = :e',ExpressionAttributeValues={':u':['paper-1-communication'],':p':True,':e':(datetime.now(timezone.utc)+timedelta(days=10)).isoformat()})
            return original(**kw)
        with patch.object(client,'transact_write_items',side_effect=race): after,_=settle_payment(self.users,self.payments,self.data())
        self.assertIn('paper-1-communication',after['units_paid_for']); self.assertEqual(self.payments.scan()['Count'],1)
    def test_other_account_cannot_recover_or_complete_order(self):
        self.create()
        for path,data in [('order/reconcile',{'order_id':'order_test'}),('order/complete',{'order_id':'order_test','payment_id':'pay_test','signature':'sig'})]: self.assertEqual(self.post(path,data,'other@test.com').status_code,409)
        self.gateway.payment.fetch.assert_not_called(); self.assertFalse(self.user()['is_paid'])
    def test_payment_amount_order_currency_refund_checked(self):
        self.create()
        for key,value in [('amount',100),('order_id','order_wrong'),('currency','USD'),('amount_refunded',500000)]:
            with self.subTest(key=key):
                self.gateway.payment.fetch.return_value={**self.payment,key:value}; self.assertEqual(self.complete().status_code,409); self.assertFalse(self.user()['is_paid'])
        self.assertEqual(self.payments.scan()['Count'],0)
    def test_uncaptured_payment_stays_pending(self):
        self.create(); self.gateway.payment.fetch.return_value={**self.payment,'status':'authorized'}; self.assertEqual(self.complete().status_code,202); self.assertFalse(self.user()['is_paid']); self.assertEqual(self.payments.scan()['Count'],0)
    def test_browser_cannot_change_saved_terms(self):
        self.create(); self.assertEqual(self.complete(months=120,amount=1,plan_id='made-up',exam_ids=['unauthorized']).status_code,200); self.assertEqual(self.user()['plan_id'],'ugc_net_full_course_v1'); self.assertNotIn('unauthorized',self.user()['exams_paid_for']); self.assertEqual(self.payments.get_item(Key={'payment_id':'pay_test'})['Item']['months'],3)
    def test_price_duration_currency_and_units_validated_before_create(self):
        for changes in [{'amount':1},{'months':120},{'currency':'USD'},{'plan_id':'free'},{'plan_id':'ugc_net_units_v1','unit_ids':['unknown']},{'unit_ids':'wrong'},{'amount':True}]:
            with self.subTest(changes=changes): self.assertEqual(self.create(**changes).status_code,400)
        self.gateway.order.create.assert_not_called()
    def test_modular_grants_only_selected_units(self):
        self.gateway.order.create.return_value={'id':'order_test','amount':100000,'currency':'INR'}; self.payment.update(amount=100000)
        self.assertEqual(self.create(plan_id='ugc_net_units_v1',amount=1000,unit_ids=['paper-1-communication','paper-2-social-psychology']).status_code,200); self.assertEqual(self.webhook().status_code,200); self.assertEqual(set(self.user()['units_paid_for']),{'paper-1-communication','paper-2-social-psychology'}); self.assertEqual(self.user()['exams_paid_for'],[])
    def test_missing_user_never_creates_partial_account(self):
        self.users.delete_item(Key={'email':self.email})
        with self.assertRaises(SettlementConflict): settle_payment(self.users,self.payments,self.data())
        self.assertEqual(self.payments.scan()['Count'],0); self.assertNotIn('Item',self.users.get_item(Key={'email':self.email}))
    def test_invalid_signatures_never_fetch_payment(self):
        from razorpay.errors import SignatureVerificationError
        self.create(); r=self.client.post('/razorpay/webhook',json={},headers={'X-Razorpay-Signature':'invalid'}); self.assertEqual(r.status_code,400)
        self.gateway.utility.verify_payment_signature.side_effect=SignatureVerificationError('invalid'); self.assertEqual(self.complete().status_code,400); self.gateway.payment.fetch.assert_not_called(); self.assertFalse(self.user()['is_paid'])
    def test_webhook_unconfigured_and_gateway_outage_request_retry(self):
        self.create()
        with patch.dict(os.environ,{'RAZORPAY_WEBHOOK_SECRET':''}): self.assertEqual(self.webhook().status_code,503)
        self.gateway.payment.fetch.side_effect=RuntimeError('unavailable'); self.assertEqual(self.webhook().status_code,503); self.assertEqual(self.payments.scan()['Count'],0)
    def test_unknown_legacy_webhook_does_not_guess_account(self):
        r=self.webhook(); self.assertEqual(r.status_code,200); self.assertEqual(r.json['status'],'ignored'); self.assertFalse(self.user()['is_paid']); self.gateway.payment.fetch.assert_not_called()
    def test_existing_signed_checkout_completes_after_rollout(self):
        self.assertEqual(self.complete().status_code,200); self.assertTrue(self.user()['is_paid']); self.assertFalse(self.complete().json['applied'])
    def test_legacy_order_gateway_amount_must_match(self):
        self.gateway.order.fetch.return_value={'amount':1,'currency':'INR'}; self.assertEqual(self.complete().status_code,409); self.assertFalse(self.user()['is_paid'])
    def test_repaired_payment_does_not_grant_again(self):
        settle_payment(self.users,self.payments,self.data(recovery_source='owner_verified_gateway_recovery')); expiry=self.user()['plan_valid_till']; self.assertFalse(self.complete().json['applied']); self.assertEqual(self.user()['plan_valid_till'],expiry)
    def test_payment_cannot_be_reassigned(self):
        settle_payment(self.users,self.payments,self.data())
        with self.assertRaises(SettlementConflict): settle_payment(self.users,self.payments,self.data(user_email='other@test.com'))
        self.assertFalse(self.users.get_item(Key={'email':'other@test.com'})['Item']['is_paid'])
    def test_second_payment_for_same_order_cannot_double_grant(self):
        self.create(); self.complete(); expiry=self.user()['plan_valid_till']; self.gateway.payment.fetch.return_value={**self.payment,'id':'pay_second'}; self.assertEqual(self.complete(payment_id='pay_second').status_code,409); self.assertEqual(self.user()['plan_valid_till'],expiry); self.assertEqual(self.payments.scan()['Count'],1)
    def test_recovery_and_creation_need_authentication(self):
        for route in ['order/create','order/complete','order/reconcile','orders/reconcile']: self.assertEqual(self.client.post('/razorpay/'+route,json={}).status_code,401)
    def test_audit_contains_payment_plan_account_but_no_secrets(self):
        self.create(); self.complete(); rows=self.resource.Table('AdminAuditLogs').scan()['Items']; raw=json.dumps(rows,default=str); self.assertNotIn('secret-signature',raw); self.assertNotIn('private-unchanged-hash',raw)
        completed=[r for r in rows if r['action']=='payment.complete' and r['phase']=='completed'][0]; result=completed['details']['result']; self.assertEqual(result['payment_id'],'pay_test'); self.assertEqual(result['email'],self.email); self.assertEqual(result['months'],3); self.assertEqual(completed['details']['after']['plan_id'],'ugc_net_full_course_v1'); self.assertIn('network',completed)
    def test_failed_payment_update_cannot_overwrite_capture(self):
        import controller
        settle_payment(self.users,self.payments,self.data())
        with patch.object(controller,'PaymentHistoryTable',self.payments): controller.save_failed_payment_history(self.data(status='failed'))
        self.assertTrue(self.payments.get_item(Key={'payment_id':'pay_test'})['Item']['entitlement_applied'])
    def test_pending_checks_throttle_and_completed_orders_disappear(self):
        self.create(); self.gateway.order.payments.return_value={'items':[]}
        for _ in range(2): self.assertEqual(self.post('orders/reconcile').status_code,200)
        self.assertEqual(self.gateway.order.payments.call_count,1); self.gateway.order.payments.return_value={'items':[self.payment]}; self.assertEqual(self.post('order/reconcile',{'order_id':'order_test'}).status_code,200)
        self.gateway.order.payments.reset_mock(); self.assertEqual(self.post('orders/reconcile').json['count'],0); self.gateway.order.payments.assert_not_called()
    def test_actual_app_registers_all_payment_routes(self):
        import app
        rules={r.rule for r in app.app.url_map.iter_rules()}; self.assertTrue({'/razorpay/order/create','/razorpay/order/complete','/razorpay/order/reconcile','/razorpay/orders/reconcile','/razorpay/webhook'}<=rules)

if __name__=='__main__': unittest.main()
