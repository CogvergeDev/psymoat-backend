"""Reconcile missing subscription fields without changing account credentials.

Historical purchases without a duration used a six-month default. Expiry rebuilt
from a payment is an estimate, not recovery of a deleted or manually extended date.
"""

from datetime import datetime
from decimal import Decimal, InvalidOperation
import re
from zoneinfo import ZoneInfo

from dateutil import parser
from dateutil.relativedelta import relativedelta

IST = ZoneInfo("Asia/Kolkata")
CORE_FIELDS = ("is_paid", "plan_id", "plan_valid_till")
STATE_FIELDS = CORE_FIELDS + (
    "exams_paid_for", "units_paid_for", "last_subscription_plan_id",
    "last_subscription_valid_till", "subscription_expiry_source",
)
USER_FIELDS = ("email", "user_id") + STATE_FIELDS
PAYMENT_FIELDS = ("payment_id", "user_email", "created_at", "status", "plan_id", "months")
LEGACY_PLANS = {
    "interactive_850_v1", "trainer_700_v1", "cuet_pg_trainer_v1",
    "cuet_pg_advanced_v1", "netjrf_trainer_v1", "netjrf_advanced_v1",
}


def parse_expiry(value):
    # Some legacy records append Z to an already offset-aware timestamp.
    cleaned = re.sub(r"([+-]\d{2}:\d{2})Z$", r"\1", str(value))
    result = parser.parse(cleaned)
    return (result.replace(tzinfo=IST) if result.tzinfo is None else result.astimezone(IST))


def free_subscription_fields(user, expiry="", previous_plan=None):
    """Keep expiry in history; a Free plan has no active subscription expiry."""
    fields = {
        # The hosted legacy cleanup removes fields whenever plan_valid_till is
        # past. A blank Free expiry prevents recurrence before code deployment.
        "is_paid": False, "plan_id": "free", "plan_valid_till": "",
        "exams_paid_for": [], "units_paid_for": [],
    }
    plan = previous_plan or user.get("plan_id")
    if plan and plan != "free":
        fields["last_subscription_plan_id"] = plan
    if expiry:
        fields["last_subscription_valid_till"] = expiry
    return fields


def reconstruct_expiry(payments):
    """Use captured payments only; never turn a failed payment into a renewal."""
    purchases = []
    for payment in payments:
        if payment.get("status") != "captured":
            continue
        paid_at = parse_expiry(payment["created_at"])
        value = payment.get("months")
        inferred = value is None
        if inferred:
            plan = payment.get("plan_id")
            if plan in LEGACY_PLANS:
                value = 6
            elif plan == "ugc_net_advanced_monthly_v1":
                value = 1
            else:
                raise ValueError("No recorded duration or known historical default")
        months = Decimal(str(value))
        if not months.is_finite() or months != int(months) or months <= 0:
            raise ValueError("Invalid payment duration")
        purchases.append((paid_at, int(months), payment, inferred))
    if not purchases:
        return None
    purchases.sort(key=lambda purchase: purchase[0])
    expiry = None
    # Earlier code replaced the expiry on every purchase. The August change
    # extended active subscriptions; using the extension is conservative when
    # the exact deployment time is unknown (it cannot shorten paid access).
    extension_change = datetime(2026, 8, 10, tzinfo=IST)
    seen = set()
    for paid_at, months, payment, inferred in purchases:
        payment_id = payment.get("payment_id")
        if payment_id and payment_id in seen:
            continue
        if payment_id:
            seen.add(payment_id)
        base = max(paid_at, expiry) if expiry and paid_at >= extension_change else paid_at
        expiry = base + relativedelta(months=months)
        latest = payment
        duration_inferred = inferred
    return {
        "expiry": expiry, "plan_id": latest.get("plan_id"),
        "payment_id": latest.get("payment_id"),
        "source": "payment_history_legacy_duration" if duration_inferred else "payment_history",
    }


def missing_subscription_decision(user, payments, now, *, allow_unverified_free=False):
    """Return a reviewable field patch; never downgrade a known future expiry."""
    email = user["email"]
    result = {"email": email, "changes": {}, "reason": "already_complete"}
    if all(field in user for field in CORE_FIELDS):
        return result
    captured = [payment for payment in payments if payment.get("status") == "captured"]
    try:
        reconstructed = reconstruct_expiry(captured)
        stored = parse_expiry(user["plan_valid_till"]) if user.get("plan_valid_till") else None
    except (KeyError, ValueError, TypeError, OverflowError, InvalidOperation):
        result["reason"] = "unreadable_payment_or_expiry"
        return result
    # A saved expiry may encode a manual extension. Keep the later date.
    expiry = max(stored, reconstructed["expiry"]) if stored and reconstructed else (
        stored or (reconstructed["expiry"] if reconstructed else None)
    )
    if expiry and expiry > now:
        result["reason"] = "active_subscription_requires_review"
        result["expiry"] = expiry.isoformat()
        return result
    if not expiry and (
        user.get("is_paid") in (True, "true", "True", 1)
        or user.get("plan_id") not in (None, "", "free")
        or user.get("exams_paid_for") or user.get("units_paid_for")
    ) and not allow_unverified_free:
        result["reason"] = "permissions_without_expiry_or_payment"
        return result
    previous_plan = reconstructed["plan_id"] if reconstructed else None
    result["changes"] = free_subscription_fields(
        user, expiry.isoformat() if expiry else "", previous_plan
    )
    if expiry:
        source = "stored_expiry" if stored and stored == expiry else reconstructed["source"]
        result["changes"]["subscription_expiry_source"] = source
    result["reason"] = "expired_subscription" if expiry else "no_recorded_subscription"
    if reconstructed:
        result["payment_id"] = reconstructed["payment_id"]
    return result


def scan_fields(table, fields):
    args = {
        "ConsistentRead": True,
        "ProjectionExpression": ", ".join(f"#f{i}" for i in range(len(fields))),
        "ExpressionAttributeNames": {f"#f{i}": field for i, field in enumerate(fields)},
    }
    items = []
    while True:
        response = table.scan(**args)
        items.extend(response.get("Items", []))
        if not response.get("LastEvaluatedKey"):
            return items
        args["ExclusiveStartKey"] = response["LastEvaluatedKey"]


def conditional_state_update(table, user, changes):
    """Do not overwrite a purchase, grant, or account deletion after the scan."""
    names = {"#email": "email"}
    values = {}
    conditions = ["attribute_exists(#email)"]
    for index, field in enumerate(("user_id",) + STATE_FIELDS):
        name = f"#old{index}"
        names[name] = field
        if field in user:
            value = f":old{index}"
            values[value] = user[field]
            conditions.append(f"{name} = {value}")
        else:
            conditions.append(f"attribute_not_exists({name})")
    assignments = []
    for index, (field, value) in enumerate(changes.items()):
        name, placeholder = f"#new{index}", f":new{index}"
        names[name], values[placeholder] = field, value
        assignments.append(f"{name} = {placeholder}")
    return table.update_item(
        Key={"email": user["email"]},
        UpdateExpression="SET " + ", ".join(assignments),
        ConditionExpression=" AND ".join(conditions),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
        ReturnValues="UPDATED_NEW", ReturnConsumedCapacity="TOTAL",
    )


def reconciliation_preview(user_table, payment_table, now, *, allow_unverified_free=False):
    users = scan_fields(user_table, USER_FIELDS)
    payments = scan_fields(payment_table, PAYMENT_FIELDS)
    by_email = {}
    for payment in payments:
        email = str(payment.get("user_email", "")).strip().lower()
        by_email.setdefault(email, []).append(payment)
    affected = [user for user in users if any(field not in user for field in CORE_FIELDS)]
    decisions = [missing_subscription_decision(
        user, by_email.get(user["email"].strip().lower(), []), now,
        allow_unverified_free=allow_unverified_free,
    ) for user in affected]
    return users, affected, decisions
