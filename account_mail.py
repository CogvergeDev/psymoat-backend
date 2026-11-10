"""Durable transactional email jobs, sent through Resend HTTPS without threads.

Jobs are committed with the account mutation. A lease and Resend idempotency key
make interrupted sends retryable. Ambiguous sends stop before Resend's 24-hour
deduplication window expires; they are never automatically replayed after that.
"""
import hashlib
import hmac
from html import escape
import logging
import os
import re
import secrets
import time
from urllib.parse import quote, urlsplit

from boto3.dynamodb.conditions import Key
from botocore.exceptions import BotoCoreError, ClientError
from flask import current_app, has_app_context
import requests

TABLE_NAME = 'AccountOperations'
QUEUE_INDEX = 'PendingEmails'
RESET_SECONDS = 1800
RESET_REQUEST_MAX = 5
RESET_REQUEST_WINDOW = 3600
AMBIGUOUS_RETRY_SECONDS = 23 * 3600
logger = logging.getLogger(__name__)


class MailConfigurationError(RuntimeError):
    pass


def table(db):
    return db.dynamodb_resource.Table(os.getenv('ACCOUNT_OPERATIONS_TABLE', TABLE_NAME))


def secret():
    value = os.getenv('ACCOUNT_TOKEN_SECRET')
    if not value and has_app_context():
        value = current_app.config.get('JWT_SECRET_KEY')
    value = value or os.getenv('JWT_SECRET_KEY')
    if not value or len(value) < 32:
        raise MailConfigurationError('A stable account token secret of at least 32 characters is required')
    return value.encode()


def frontend_url():
    value = os.getenv('FRONTEND_URL', 'https://www.psymoat.in').rstrip('/')
    url = urlsplit(value)
    if not url.netloc or url.username or url.query or url.fragment or url.path not in ('', '/'):
        raise MailConfigurationError('Invalid frontend URL')
    if url.scheme != 'https' and not (url.scheme == 'http' and url.hostname in ('localhost', '127.0.0.1')):
        raise MailConfigurationError('Frontend URL must use HTTPS')
    return value


def sender():
    value = os.getenv('EMAIL_FROM', 'Psymoat <developer@psymoat.in>').strip()
    if '\n' in value or '\r' in value or not re.fullmatch(r'(?:[^<>]+<)?[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+>?', value):
        raise MailConfigurationError('Invalid sender address')
    return value


def new_job(kind, email, *, name='', job_id=None):
    now = int(time.time())
    return {'pk': 'MAIL#' + (job_id or secrets.token_urlsafe(32)), 'kind': kind,
            'email': email, 'name': name, 'created_at': now, 'sender': sender(),
            'frontend_url': frontend_url(), 'status': 'pending', 'queue': 'pending',
            'next_attempt': now, 'attempts': 0,
            'expires_at': now + (RESET_SECONDS if kind == 'password_reset' else 7 * 86400),
            'ttl': now + 30 * 86400, 'template_version': 2}


def put_job(job, db):
    return {'Put': {'TableName': table(db).name, 'Item': job,
                    'ConditionExpression': 'attribute_not_exists(pk)'}}


def reset_token(job):
    # Reconstructable for delivery retries without storing the bearer token or
    # reset link in DynamoDB. A table read alone cannot recover the token.
    job_id = job['pk'].removeprefix('MAIL#')
    payload = f"reset-v1|{job_id}|{job['email']}|{job['created_at']}"
    signature = hmac.new(secret(), payload.encode(), hashlib.sha256).hexdigest()
    return job_id + '.' + signature


def token_digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def render_job(job):
    base = job['frontend_url']
    if job['kind'] == 'password_reset':
        subject = 'Reset your Psymoat password'
        link = base + '/reset-password#token=' + quote(reset_token(job), safe='')
        paragraphs = ['We received a request to reset your Psymoat password.',
                      'This link expires 30 minutes after your request and can be used once.',
                      'If you did not request this, you can ignore this email. Your password has not changed.']
        action = 'Choose a new password'
    elif job['kind'] == 'password_changed':
        subject = 'Your Psymoat password has changed'
        link = base + '/forgot-password'
        paragraphs = ['Your Psymoat password was changed successfully.',
                      'You have been signed out of your existing sessions. Sign in using your new password.',
                      'If you did not make this change, reset your password immediately or contact developer@psymoat.in.']
        action = 'Reset your password'
    elif job['kind'] == 'welcome':
        subject = 'Welcome to Psymoat!'
        link = base + '/login'
        paragraphs = [f"Hi {job['name']},", 'Welcome to Psymoat! Your account is ready.',
                      'Sign in to start preparing and continue your learning journey.']
        action = 'Start learning'
    else:
        raise ValueError('Unknown account email type')
    if job.get('template_version', 1) == 1:
        # Resend retries must use the same payload as the first attempt.
        text = '\n\n'.join(paragraphs + [action + ': ' + link, 'The Psymoat team'])
        html = ('<div style="font-family:Arial,sans-serif;line-height:1.6;max-width:560px;margin:auto;padding:24px">'
                '<h1>Psymoat</h1>' + ''.join('<p>' + escape(p) + '</p>' for p in paragraphs)
                + '<p><a href="' + escape(link, quote=True) + '" style="background:#58cc02;color:#111;padding:12px 18px;display:inline-block;border-radius:8px">'
                + action + '</a></p><p>The Psymoat team</p></div>')
    else:
        note = ''
        if job['kind'] == 'welcome':
            heading = 'Welcome to Psymoat'
            greeting = f"Hi {job['name'].strip()}," if job['name'].strip() else 'Hi there,'
            paragraphs = [greeting, 'Your account is ready. Sign in whenever you’d like to start studying.']
            action = 'Sign in'
        elif job['kind'] == 'password_reset':
            heading = 'Reset your password'
            paragraphs = ['Use the link below to choose a new password. The link works once and expires in 30 minutes.']
            action = 'Reset my password'
            note = 'If you didn’t request a reset, you can ignore this email.'
        else:
            heading = 'Your password was changed'
            paragraphs = ['We signed you out of Psymoat on all devices. Use your new password the next time you sign in.',
                          'If you didn’t make this change, reset your password now or email developer@psymoat.in.']
        text = '\n\n'.join(paragraphs + [action + ': ' + link] + ([note] if note else []) + ['The Psymoat team'])
        html = branded_email(base, heading, paragraphs, link, action, note)
    return {'from': job['sender'], 'to': [job['email']], 'subject': subject, 'text': text, 'html': html}


def branded_email(base, heading, paragraphs, link, action, note):
    content = ''.join(f'<p style="margin:0 0 16px">{escape(paragraph)}</p>' for paragraph in paragraphs)
    logo = escape(base + '/images/logo.jpeg', quote=True)
    href = escape(link, quote=True)
    if note:
        # Keep the reset action easy to find in the security email.
        cta = f"""<table role="presentation" cellspacing="0" cellpadding="0"><tr>
<td bgcolor="#286321" style="border-radius:5px;mso-padding-alt:10px 16px">
<a href="{href}" style="display:inline-block;padding:10px 16px;color:#fff;font-size:15px;font-weight:bold;text-decoration:none;mso-padding-alt:0">{escape(action)}</a>
</td></tr></table>"""
        follow_up = f'<p class="email-muted" style="margin:18px 0 0;color:#555b55">{escape(note)}</p>'
    else:
        cta = f'<p style="margin:0"><a class="email-link" href="{href}" style="color:#276323;text-decoration:underline;font-weight:bold">{escape(action)}</a></p>'
        follow_up = ''
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<style>
@media only screen and (max-width:480px) {{
  .email-frame {{padding:26px 22px 32px!important}}
}}
@media (prefers-color-scheme:dark) {{
  .email-bg {{background:#191a19!important}}
  .email-copy {{color:#f0f1ef!important}}
  .email-muted {{color:#bfc3be!important}}
  .email-rule {{border-color:#3b3e3b!important}}
  .email-link {{color:#a5d39a!important}}
}}
</style></head>
<body class="email-bg" style="margin:0;padding:0;background:#fff">
<table role="presentation" class="email-bg" width="100%" cellspacing="0" cellpadding="0" style="background:#fff">
<tr><td class="email-frame" align="center" style="padding:34px 24px 38px">
<!--[if mso]><table role="presentation" width="520" cellspacing="0" cellpadding="0"><tr><td><![endif]-->
<table role="presentation" class="email-content" width="100%" cellspacing="0" cellpadding="0"
  style="max-width:520px;text-align:left;font-family:Arial,sans-serif">
<tr><td class="email-rule" style="padding:0 0 16px;border-bottom:1px solid #e3e6e2">
<table role="presentation" cellspacing="0" cellpadding="0"><tr>
<td valign="middle"><img src="{logo}" width="28" height="28" alt="" style="display:block;border-radius:6px"></td>
<td valign="middle" class="email-copy" style="padding-left:9px;font-size:16px;font-weight:bold;color:#202320">Psymoat</td>
</tr></table></td></tr>
<tr><td class="email-copy" style="padding-top:23px;color:#202320;font-size:16px;line-height:1.55">
<h1 style="margin:0 0 15px;font-size:23px;line-height:1.25;font-weight:bold">{escape(heading)}</h1>
{content}
{cta}
{follow_up}
<p class="email-muted" style="margin:22px 0 0;color:#555b55">The Psymoat team</p>
</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr></table>
</body></html>"""


def finish(db, job, owner, status, **fields):
    names = {'#status': 'status'}
    values = {':owner': owner, ':status': status}
    assignments = ['#status = :status']
    for i, (key, value) in enumerate(fields.items()):
        names['#f' + str(i)] = key; values[':f' + str(i)] = value
        assignments.append('#f' + str(i) + ' = :f' + str(i))
    table(db).update_item(Key={'pk': job['pk']},
        ConditionExpression='lease_owner = :owner',
        UpdateExpression='SET ' + ', '.join(assignments) + ' REMOVE queue, lease_owner',
        ExpressionAttributeNames=names, ExpressionAttributeValues=values)


def deliver(db, job_id):
    """Try one durable job; failures leave it queued. Return accepted/queued/etc."""
    jobs = table(db)
    job = jobs.get_item(Key={'pk': job_id}, ConsistentRead=True).get('Item')
    now = int(time.time())
    if not job or job.get('status') != 'pending' or job.get('next_attempt', 0) > now:
        return job.get('status', 'missing') if job else 'missing'
    owner = secrets.token_hex(16)
    try:
        jobs.update_item(Key={'pk': job_id},
            ConditionExpression='#status = :pending AND next_attempt <= :now',
            UpdateExpression='SET lease_owner = :owner, next_attempt = :lease, uncertain_since = if_not_exists(uncertain_since, :now) ADD attempts :one',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={':pending': 'pending', ':now': now, ':owner': owner, ':lease': now + 90, ':one': 1})
    except ClientError as error:
        if error.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return 'queued'
        raise
    if job['expires_at'] <= now:
        finish(db, job, owner, 'expired'); return 'expired'
    if job.get('uncertain_since') and now - job['uncertain_since'] >= AMBIGUOUS_RETRY_SECONDS:
        finish(db, job, owner, 'needs_review', error_category='deduplication_window'); return 'needs_review'
    if job['kind'] == 'password_reset':
        user = db.UserTable.get_item(Key={'email': job['email']}, ConsistentRead=True).get('Item', {})
        if user.get('password_reset_digest') != token_digest(reset_token(job)) or user.get('password_reset_expires', 0) <= now:
            finish(db, job, owner, 'superseded'); return 'superseded'
    category, delay, uncertain = 'unavailable', 60, True
    try:
        # Gate across processes so opportunistic retries cannot flood the provider.
        if not take_limit(db, 'provider-send', 'global', 5, 1):
            retry(db, job, owner, 'rate_limited', now + 2, uncertain=False); return 'queued'
        key = os.getenv('RESEND_API_KEY', '').strip()
        if not key:
            raise MailConfigurationError('Resend is not configured')
        response = requests.post('https://api.resend.com/emails',
            headers={'Authorization': 'Bearer ' + key, 'Idempotency-Key': 'psymoat/' + job_id},
            json=render_job(job), timeout=(2, 6))
        if response.status_code == 200:
            provider_id = response.json().get('id')
            if not isinstance(provider_id, str) or not provider_id:
                raise ValueError('Missing provider ID')
            finish(db, job, owner, 'accepted', provider_id=provider_id, accepted_at=now)
            return 'accepted'
        category = 'provider_' + str(response.status_code)
        if response.status_code in (400, 401, 403, 404, 422):
            # Explicit rejection has not sent the message. Configuration can be
            # repaired while retaining the original idempotency key/payload.
            uncertain, delay = False, 3600
        elif response.status_code == 429:
            uncertain, delay = False, 3600
        elif response.status_code == 409:
            # Never change the payload or idempotency key to evade a conflict.
            category = 'provider_conflict'
    except MailConfigurationError:
        category, delay, uncertain = 'configuration', 300, False
    except (requests.RequestException, ValueError, TypeError):
        category = 'delivery_unknown'
    retry(db, job, owner, category, now + delay, uncertain=uncertain)
    logger.warning('ACCOUNT_EMAIL_QUEUED category=%s', category)
    return 'queued'


def retry(db, job, owner, category, due, *, uncertain):
    remove = 'lease_owner'
    if not uncertain and not job.get('uncertain_since'):
        remove += ', uncertain_since'
    table(db).update_item(Key={'pk': job['pk']}, ConditionExpression='lease_owner = :owner',
        UpdateExpression='SET next_attempt = :due, error_category = :category REMOVE ' + remove,
        ExpressionAttributeValues={':owner': owner, ':due': due, ':category': category})


def try_deliver(db, job_id):
    # Once an account change has committed, even a broken provider or outbox
    # acknowledgement must not turn a successful change into a false failure.
    try:
        return deliver(db, job_id)
    except Exception as error:
        logger.error('ACCOUNT_EMAIL_ATTEMPT_INTERRUPTED category=%s', type(error).__name__)
        return 'queued'


def drain(db, limit=1):
    rows = table(db).query(IndexName=QUEUE_INDEX,
        KeyConditionExpression=Key('queue').eq('pending') & Key('next_attempt').lte(int(time.time())),
        Limit=limit).get('Items', [])
    counts = {'checked': 0, 'accepted': 0}
    for row in rows:
        status = try_deliver(db, row['pk'])
        counts['checked'] += 1
        counts['accepted'] += status == 'accepted'
    return counts


def limit_digest(scope, value):
    # HMAC prevents leaked rate-limit rows revealing email/IP addresses.
    return hmac.new(secret(), (scope + '|' + value).encode(), hashlib.sha256).hexdigest()


def reserve_reset_request(db, email):
    """Reserve a request before looking up the user, for any supplied address."""
    jobs = table(db)
    key = {'pk': 'RESET_LIMIT#' + limit_digest('forgot-email', email.casefold())}
    while True:
        now = int(time.time())
        current = jobs.get_item(Key=key, ConsistentRead=True).get('Item')
        if current and current['retry_at'] > now:
            return False, int(current['retry_at']) - now, RESET_REQUEST_MAX - int(current['attempts'])

        if current and current['window_end'] > now:
            window_end = int(current['window_end'])
            attempts = int(current['attempts']) + 1
        else:
            window_end = now + RESET_REQUEST_WINDOW
            attempts = 1
        remaining = RESET_REQUEST_MAX - attempts
        retry_at = now + attempts * 60 if remaining else window_end
        try:
            jobs.put_item(
                Item={**key, 'attempts': attempts, 'retry_at': retry_at,
                      'window_end': window_end, 'ttl': max(window_end, retry_at) + RESET_REQUEST_WINDOW},
                ConditionExpression='attribute_not_exists(pk) OR retry_at <= :now',
                ExpressionAttributeValues={':now': now},
            )
            return True, retry_at - now, remaining
        except ClientError as error:
            if error.response['Error']['Code'] != 'ConditionalCheckFailedException':
                raise


def take_limit(db, scope, value, maximum, window):
    digest = limit_digest(scope, value)
    now = int(time.time()); bucket = now // window
    key = f'LIMIT#{scope}#{digest}#{bucket}'
    try:
        table(db).update_item(Key={'pk': key},
            ConditionExpression='attribute_not_exists(attempts) OR attempts < :maximum',
            UpdateExpression='SET #ttl = :ttl ADD attempts :one',
            ExpressionAttributeNames={'#ttl': 'ttl'},
            ExpressionAttributeValues={':ttl': (bucket + 2) * window, ':one': 1, ':maximum': maximum})
        return True
    except ClientError as error:
        if error.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return False
        raise
