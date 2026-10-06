"""Atomic, replay-safe entitlement settlement for gateway-verified payments.

Gateway authentication/ownership checks belong to payment_routes. This module
also supports explicitly verified legacy recoveries without creating accounts.
"""
from datetime import datetime
from zoneinfo import ZoneInfo

from botocore.exceptions import ClientError
from dateutil.relativedelta import relativedelta

from admin_audit import audit_state, audit_child_start, audit_child_finish
from subscription_reconciliation import parse_expiry

IST = ZoneInfo('Asia/Kolkata')
ACCESS_FIELDS = ('is_paid', 'plan_id', 'plan_valid_till', 'exams_paid_for', 'units_paid_for')


class SettlementConflict(ValueError):
    pass


def settle_payment(users, payments, data, *, orders=None, now=None):
    """Commit payment + subscription + optional order in one transaction.

    A captured legacy record without the new applied marker is considered
    already processed: older records cannot safely distinguish an old grant
    from a partial failure. Repair those only after an explicit investigation.
    """
    email, payment_id = data['user_email'], data['payment_id']
    months = int(data.get('months') or 3)
    if months <= 0:
        raise ValueError('Payment duration must be positive')
    now = now or datetime.now(IST)
    child = None
    for _ in range(4):
        previous = payments.get_item(Key={'payment_id': payment_id}, ConsistentRead=True).get('Item')
        user = users.get_item(Key={'email': email}, ConsistentRead=True).get('Item')
        if not user:
            raise SettlementConflict('Payment account no longer exists')
        if previous:
            if previous.get('user_email') != email or previous.get('order_id') != data['order_id']:
                raise SettlementConflict('Payment belongs to another account or order')
            if previous.get('status') == 'captured' or previous.get('entitlement_applied'):
                audit_child_finish(child, 'already_applied', after=user)
                audit_state(result={'payment_id': payment_id, 'order_id': data['order_id'],
                                    'email': email, 'outcome': 'already_applied'})
                return {key: user.get(key) for key in ACCESS_FIELDS}, False

        base = now
        active = False
        if user.get('is_paid') in (True, 'true', 'True', 1) and user.get('plan_valid_till'):
            try:
                expiry = parse_expiry(user['plan_valid_till'])
                active = expiry > now
                if active:
                    base = expiry
            except (ValueError, TypeError, OverflowError):
                pass
        # Stale permissions must not be resurrected by a new modular purchase.
        exams = list(user.get('exams_paid_for') or []) if active else []
        units = list(user.get('units_paid_for') or []) if active else []
        plan = data['plan_id']
        if plan == 'ugc_net_full_course_v1':
            exam_additions = ['qjPZtz_lecs', 'qjPZtz_mocks']
        elif plan == 'ugc_net_units_v1':
            exam_additions = []
        else:
            exam_additions = list(data.get('exam_ids') or [])
            if plan == 'cuet_pg_trainer_v1':
                exam_additions = exam_additions[:1]
        for exam in exam_additions:
            if exam not in exams:
                exams.append(exam)
        for unit in data.get('unit_ids') or []:
            if unit not in units:
                units.append(unit)
        after = {'is_paid': True, 'plan_id': plan,
                 'plan_valid_till': (base + relativedelta(months=months)).isoformat(),
                 'exams_paid_for': exams, 'units_paid_for': units}
        record = {key: data[key] for key in
                  ('payment_id', 'order_id', 'amount', 'currency', 'created_at',
                   'user_email', 'plan_id', 'unit_ids', 'exam_ids', 'recovery_source') if key in data}
        record.update(months=months, status='captured', entitlement_applied=True,
                      applied_at=now.isoformat(), plan_valid_till=after['plan_valid_till'])

        names = {'#email': 'email'}
        values = {}
        updates, conditions = [], ['attribute_exists(#email)']
        for i, key in enumerate(ACCESS_FIELDS):
            alias = '#f' + str(i)
            names[alias] = key
            updates.append(alias + ' = :new' + str(i))
            values[':new' + str(i)] = after[key]
            if key in user:
                conditions.append(alias + ' = :old' + str(i))
                values[':old' + str(i)] = user[key]
            else:
                conditions.append('attribute_not_exists(' + alias + ')')
        transaction = [
            {'Put': {'TableName': payments.name, 'Item': record,
                     'ConditionExpression': 'attribute_not_exists(payment_id) OR (#status <> :captured AND attribute_not_exists(entitlement_applied) AND user_email = :email AND order_id = :order)',
                     'ExpressionAttributeNames': {'#status': 'status'},
                     'ExpressionAttributeValues': {':captured': 'captured', ':email': email, ':order': data['order_id']}}},
            {'Update': {'TableName': users.name, 'Key': {'email': email},
                        'UpdateExpression': 'SET ' + ', '.join(updates),
                        'ConditionExpression': ' AND '.join(conditions),
                        'ExpressionAttributeNames': names, 'ExpressionAttributeValues': values}},
        ]
        if orders is not None:
            transaction.append({'Update': {'TableName': orders.name,
                'Key': {'order_id': data['order_id']},
                'UpdateExpression': 'SET #status = :done, payment_id = :payment, applied_at = :now REMOVE pending_user',
                'ConditionExpression': 'user_email = :email AND #status = :pending',
                'ExpressionAttributeNames': {'#status': 'status'},
                'ExpressionAttributeValues': {':done': 'completed', ':pending': 'pending',
                    ':email': email, ':payment': payment_id, ':now': now.isoformat()}}})
        if child is None:
            child = audit_child_start(email, user, record)
        try:
            # Resource clients serialize Python values (including Decimal) here.
            users.meta.client.transact_write_items(TransactItems=transaction)
            audit_state(before=user, after=after,
                        result={**record, 'email': email, 'outcome': 'applied'})
            audit_child_finish(child, 'succeeded', after=after)
            return after, True
        except ClientError as error:
            if error.response['Error']['Code'] != 'TransactionCanceledException':
                audit_child_finish(child, 'failed', error=error)
                raise
            # A completed order with a different payment must never double-grant.
            if orders is not None:
                order = orders.get_item(Key={'order_id': data['order_id']}, ConsistentRead=True).get('Item', {})
                if order.get('status') == 'completed' and order.get('payment_id') != payment_id:
                    audit_child_finish(child, 'failed', error=error)
                    raise SettlementConflict('Order has already been settled') from None
    audit_child_finish(child, 'failed', error=SettlementConflict())
    raise SettlementConflict('Subscription changed during settlement; retry safely')
