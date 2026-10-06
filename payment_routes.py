"""Server-owned checkout intents, authenticated recovery and signed webhooks."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import hmac
import json
import logging
import os
from uuid import uuid4

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError, BotoCoreError
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token, set_access_cookies
from razorpay.errors import SignatureVerificationError, BadRequestError, ServerError, GatewayError
from requests.exceptions import RequestException

from admin_audit import audit_state, current_audit
from payment_settlement import SettlementConflict, settle_payment

ORDER_TABLE = 'PaymentOrders'
ORDER_INDEX = 'PendingUserOrders'
UNIT_IDS = set('''
paper-2-emergence-of-psychology
paper-2-research-methodology-and-statistics
paper-2-psychological-testing
paper-2-biological-basis-of-behaviour
paper-2-attention-perception-learning-memory-and-forgetting
paper-2-thinking-intelligence-and-creativity
paper-2-personality-motivation-emotion-stress-and-coping
paper-2-social-psychology
paper-2-human-development-and-interventions
paper-2-emerging-areas
paper-1-teaching-aptitude
paper-1-reading-comprehension
paper-1-communication
paper-1-mathematical-reasoning-and-aptitude
paper-1-logical-reasoning
paper-1-data-interpretation
paper-1-indian-logic-systems
'''.split())
logger = logging.getLogger(__name__)


def checkout_terms(data):
    """Prices, duration and permissions are selected on the server."""
    plan = data.get('plan_id')
    units = data.get('unit_ids') or []
    if not isinstance(units, list) or any(not isinstance(unit, str) for unit in units):
        raise ValueError('Invalid unit selection')
    units = sorted(set(units))
    if plan == 'ugc_net_full_course_v1':
        if units:
            raise ValueError('Full course does not need unit selection')
        amount = 5000
    elif plan == 'ugc_net_units_v1':
        if not units or not set(units) <= UNIT_IDS:
            raise ValueError('Select valid course units')
        amount = 500 * len(units)
    else:
        raise ValueError('Unsupported checkout plan')
    try:
        if Decimal(str(data.get('amount'))) != amount or Decimal(str(data.get('months', 3))) != 3:
            raise ValueError('Checkout price or duration does not match the plan')
    except InvalidOperation:
        raise ValueError('Invalid checkout price or duration') from None
    if data.get('currency', 'INR') != 'INR':
        raise ValueError('Only INR is supported')
    return {'plan_id': plan, 'months': 3, 'unit_ids': units,
            'amount': amount, 'amount_paise': amount * 100, 'currency': 'INR'}


def create_payment_blueprint(db, gateway):
    bp = Blueprint('payments', __name__)

    def orders():
        return db.dynamodb_resource.Table(ORDER_TABLE)

    def intent_for(order_id, email=None):
        if not isinstance(order_id, str) or not order_id.startswith('order_') or len(order_id) > 80:
            raise ValueError('Invalid order ID')
        intent = orders().get_item(Key={'order_id': order_id}, ConsistentRead=True).get('Item')
        if intent and email is not None and intent['user_email'] != email:
            raise SettlementConflict('Order belongs to another account')
        return intent

    def apply(intent, payment, source, *, stored=True):
        if payment.get('order_id') != intent['order_id'] or payment.get('currency') != intent['currency'] or payment.get('amount') != intent['amount_paise']:
            raise SettlementConflict('Gateway payment does not match the checkout order')
        if payment.get('status') != 'captured':
            return {'status': 'pending', 'order_id': intent['order_id']}, 202
        if payment.get('amount_refunded', 0) or payment.get('refund_status'):
            raise SettlementConflict('Refunded payment cannot activate access')
        after, applied = settle_payment(db.UserTable, db.PaymentHistoryTable, {
            'payment_id': payment['id'], 'order_id': intent['order_id'],
            'user_email': intent['user_email'], 'amount': intent['amount'],
            'currency': intent['currency'], 'plan_id': intent['plan_id'],
            'months': int(intent['months']), 'unit_ids': intent.get('unit_ids', []),
            'created_at': datetime.fromtimestamp(payment['created_at'], timezone.utc).isoformat(),
            'recovery_source': source,
        }, orders=orders() if stored else None)
        return {'status': 'success', 'applied': applied, 'order_id': intent['order_id'],
                'payment_id': payment['id'], 'user_update': after}, 200

    def reconcile(intent, source):
        # Completed orders do not need another gateway fetch on every login.
        if intent.get('status') == 'completed':
            user = db.UserTable.get_item(Key={'email': intent['user_email']}, ConsistentRead=True).get('Item', {})
            return {'status': 'success', 'applied': False, 'order_id': intent['order_id'],
                    'payment_id': intent['payment_id'], 'user_update': {
                        key: user.get(key) for key in ('is_paid', 'plan_id', 'exams_paid_for', 'units_paid_for', 'plan_valid_till')}}, 200
        payment_list = gateway.order.payments(intent['order_id'], timeout=(3, 10))
        for payment in payment_list.get('items', []):
            if payment.get('status') == 'captured':
                # Re-fetch by ID rather than trusting browser/webhook fields.
                return apply(intent, gateway.payment.fetch(payment['id'], timeout=(3, 10)), source)
        audit_state(result={'order_id': intent['order_id'], 'email': intent['user_email'], 'outcome': 'pending'})
        return {'status': 'pending', 'order_id': intent['order_id']}, 202

    def success_response(result, code):
        response = jsonify(result)
        if code == 200 and result.get('user_update'):
            user = result['user_update']
            token = create_access_token(identity=get_jwt_identity(), additional_claims={
                'is_paid': 'true' if user.get('is_paid') in (True, 'true', 'True', 1) else 'false',
                'plan_id': user.get('plan_id'), 'exams_paid_for': user.get('exams_paid_for') or [],
                'units_paid_for': user.get('units_paid_for') or []})
            set_access_cookies(response, token)
        return response, code

    @bp.errorhandler(ValueError)
    def invalid(error):
        code = 409 if isinstance(error, SettlementConflict) else 400
        return jsonify(error=str(error)), code

    @bp.errorhandler(ClientError)
    @bp.errorhandler(BotoCoreError)
    @bp.errorhandler(RequestException)
    @bp.errorhandler(BadRequestError)
    @bp.errorhandler(ServerError)
    @bp.errorhandler(GatewayError)
    @bp.errorhandler(RuntimeError)
    def unavailable(error):
        # No raw gateway responses, secrets or account records in stdout.
        logger.error('PAYMENT_PROCESSING_UNAVAILABLE category=%s', type(error).__name__)
        audit_state(result={'error_category': type(error).__name__})
        return jsonify(error='Payment processing is temporarily unavailable. Retry safely.'), 503

    @bp.route('/razorpay/order/create', methods=['POST'])
    @jwt_required()
    def create_order():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError('Invalid checkout payload')
        terms = checkout_terms(data)
        email = get_jwt_identity()
        if not db.UserTable.get_item(Key={'email': email}, ConsistentRead=True).get('Item'):
            raise SettlementConflict('Account no longer exists')
        order = gateway.order.create({'amount': terms['amount_paise'], 'currency': 'INR',
            'payment_capture': 1, 'receipt': uuid4().hex,
            'notes': {'user_email': email, 'plan_id': terms['plan_id'], 'months': '3'}}, timeout=(3, 10))
        if order.get('amount') != terms['amount_paise'] or order.get('currency') != 'INR':
            raise SettlementConflict('Gateway created an unexpected order')
        intent = {**terms, 'order_id': order['id'], 'user_email': email, 'pending_user': email,
                  'status': 'pending', 'created_at': datetime.now(timezone.utc).isoformat()}
        # Checkout opens only after durable account/plan association exists.
        orders().put_item(Item=intent, ConditionExpression='attribute_not_exists(order_id)')
        audit_state(result={**terms, 'order_id': order['id'], 'email': email})
        return jsonify(data={'id': order['id'], 'amount': terms['amount_paise'], 'currency': 'INR'}), 200

    @bp.route('/razorpay/order/complete', methods=['POST'])
    @jwt_required()
    def complete_order():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict) or any(not isinstance(data.get(key), str) or not data[key] for key in ('order_id', 'payment_id', 'signature')):
            raise ValueError('Payment, order and signature are required')
        try:
            gateway.utility.verify_payment_signature({'razorpay_order_id': data['order_id'],
                'razorpay_payment_id': data['payment_id'], 'razorpay_signature': data['signature']})
        except SignatureVerificationError:
            raise ValueError('Invalid payment signature') from None
        email = get_jwt_identity()
        intent = intent_for(data['order_id'], email)
        payment = gateway.payment.fetch(data['payment_id'], timeout=(3, 10))
        if intent is None:
            # Compatibility for checkouts opened before this deployment. The
            # verified checkout signature and server-priced terms are required.
            terms = checkout_terms(data)
            intent = {**terms, 'order_id': data['order_id'], 'user_email': email}
            gateway_order = gateway.order.fetch(data['order_id'], timeout=(3, 10))
            notes = gateway_order.get('notes') or {}
            if notes.get('user_email') and notes['user_email'] != email:
                raise SettlementConflict('Order belongs to another account')
            if gateway_order.get('amount') != terms['amount_paise'] or gateway_order.get('currency') != terms['currency']:
                raise SettlementConflict('Legacy order does not match the selected plan')
        return success_response(*apply(intent, payment, 'checkout_callback', stored='created_at' in intent))

    @bp.route('/razorpay/order/reconcile', methods=['POST'])
    @jwt_required()
    def reconcile_order():
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            raise ValueError('Invalid recovery payload')
        intent = intent_for(data.get('order_id'), get_jwt_identity())
        if not intent:
            return jsonify(error='Order has no saved checkout association'), 404
        return success_response(*reconcile(intent, 'authenticated_recovery'))

    @bp.route('/razorpay/orders/reconcile', methods=['POST'])
    @jwt_required()
    def reconcile_pending():
        email = get_jwt_identity()
        # Only this user's pending orders, no global payment/user scans.
        recent = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        pending = orders().query(IndexName=ORDER_INDEX,
            KeyConditionExpression=Key('pending_user').eq(email) & Key('created_at').gte(recent),
            ScanIndexForward=False, Limit=20).get('Items', [])
        recovered = 0
        checked = 0
        for row in pending:
            if checked >= 5:
                break
            # Throttle gateway lookups across browser tabs/logins. Direct order
            # recovery remains immediate after a checkout callback timeout.
            now = datetime.now(timezone.utc)
            try:
                orders().update_item(Key={'order_id': row['order_id']},
                    UpdateExpression='SET last_checked = :now',
                    ConditionExpression='#status = :pending AND (attribute_not_exists(last_checked) OR last_checked < :cutoff)',
                    ExpressionAttributeNames={'#status': 'status'}, ExpressionAttributeValues={
                        ':pending': 'pending', ':now': now.isoformat(), ':cutoff': (now-timedelta(minutes=1)).isoformat()})
            except ClientError as error:
                if error.response['Error']['Code'] == 'ConditionalCheckFailedException':
                    continue
                raise
            checked += 1
            _, code = reconcile(intent_for(row['order_id'], email), 'login_recovery')
            if code == 200:
                recovered += 1
        return jsonify(status='success', count=recovered), 200

    @bp.route('/razorpay/webhook', methods=['POST'])
    def webhook():
        secret = os.getenv('RAZORPAY_WEBHOOK_SECRET')
        if not secret:
            return jsonify(error='Payment webhook is not configured'), 503
        raw = request.get_data(cache=True)
        expected = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, request.headers.get('X-Razorpay-Signature', '')):
            return jsonify(error='Invalid webhook signature'), 400
        context = current_audit()
        if context:
            context.actor = {'authentication': 'verified_webhook', 'identity': 'razorpay'}
        try:
            event = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise ValueError('Invalid webhook payload') from None
        if not isinstance(event, dict):
            raise ValueError('Invalid webhook payload')
        if event.get('event') not in ('payment.captured', 'order.paid'):
            return jsonify(status='ignored'), 200
        entity = event.get('payload', {}).get('payment', {}).get('entity', {})
        intent = intent_for(entity.get('order_id'))
        if not intent:
            audit_state(result={'order_id': entity.get('order_id'), 'payment_id': entity.get('id'), 'outcome': 'unassociated_legacy_order'})
            return jsonify(status='ignored', reason='Order predates saved checkout associations'), 200
        payment = gateway.payment.fetch(entity['id'], timeout=(3, 10))
        result, code = apply(intent, payment, 'signed_webhook')
        # Retry any eventual gateway state lag; 202 would acknowledge it.
        if code == 202:
            return jsonify(error='Gateway capture is not visible yet'), 503
        return jsonify(status=result['status'], applied=result['applied']), code

    return bp
