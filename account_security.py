"""Account password recovery, authenticated changes, and session invalidation."""
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import time

from botocore.exceptions import BotoCoreError, ClientError
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt, get_jwt_identity, jwt_required, unset_jwt_cookies

from api_errors import api_error
from account_mail import (MailConfigurationError, RESET_SECONDS, drain, new_job,
                          put_job, reset_token, secret, table, take_limit,
                          token_digest, try_deliver)

logger = logging.getLogger(__name__)
RESET_MESSAGE = 'If an account exists for that email, we will send a password reset link. Check your inbox and spam folder. Please wait one minute before requesting another link.'


def password_version(user):
    # Password hashes never appear in the JWT, public profile, logs or email.
    key = current_app.config['JWT_SECRET_KEY'].encode()
    return hmac.new(key, ('account-session-v1|' + user['password']).encode(), hashlib.sha256).hexdigest()


def public_user(user):
    return {k: v for k, v in user.items() if k != 'password' and not k.startswith('password_reset_') and k != 'password_changed_at'}


def valid_new_password(password):
    if not isinstance(password, str) or len(password) < 8 or not password.strip():
        raise ValueError('Use at least 8 characters for your new password.')
    if len(password.encode('utf-8')) > 72:
        raise ValueError('Your password is too long. Use at most 72 bytes (some characters use more than one byte).')
    return password


def install_account_security(app, db):
    jwt = app.extensions['flask-jwt-extended']

    @jwt.additional_claims_loader
    def session_claims(identity):
        try:
            claims = get_jwt()
        except RuntimeError:
            claims = {}
        if claims.get('sub') == identity:
            if 'auth_version' in claims:
                return {'auth_version': claims['auth_version']}
            # A refreshed legacy token must retain the original authentication
            # time; otherwise a concurrent reset could resurrect the session.
            return {'auth_issued_at': claims.get('auth_issued_at', claims['iat'])}
        user = db.UserTable.get_item(Key={'email': identity}, ConsistentRead=True).get('Item')
        return {'auth_version': password_version(user)} if user and user.get('password') else {}

    @jwt.token_in_blocklist_loader
    def ended(_header, claims):
        try:
            user = db.UserTable.get_item(Key={'email': claims['sub']}, ConsistentRead=True).get('Item')
            if not user or not user.get('password'):
                return True
            if 'auth_version' in claims:
                return not hmac.compare_digest(str(claims['auth_version']), password_version(user))
            return bool(user.get('password_changed_at') and claims.get('auth_issued_at', claims.get('iat', 0)) <= user['password_changed_at'])
        except (ClientError, BotoCoreError):
            # Fail closed with a retryable service error, rather than pretending
            # a valid user has been signed out during a database outage.
            raise SessionStoreUnavailable() from None

    bp = Blueprint('account', __name__)

    @app.errorhandler(SessionStoreUnavailable)
    def session_unavailable(_error):
        return api_error('We could not verify your session right now. Please try again shortly.', 'SERVICE_UNAVAILABLE', 503)

    @bp.after_request
    def private_response(response):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
        return response

    @bp.errorhandler(ValueError)
    def invalid(error):
        return api_error(str(error), 'INVALID_INPUT', 400)

    @bp.errorhandler(ClientError)
    @bp.errorhandler(BotoCoreError)
    @bp.errorhandler(MailConfigurationError)
    def unavailable(error):
        logger.error('ACCOUNT_REQUEST_UNAVAILABLE category=%s', type(error).__name__)
        return api_error('We could not complete your request right now. Please try again shortly.', 'SERVICE_UNAVAILABLE', 503)

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError('Please provide the required form details.')
        return data

    def new_password(data):
        password = valid_new_password(data.get('new_password'))
        if password != data.get('confirm_password'):
            raise ValueError('The new passwords do not match. Please enter the same password twice.')
        return password

    def limit(scope, value, maximum, window):
        return take_limit(db, scope, value, maximum, window)

    def peer():
        # Render's proxy configuration must be explicit. Never trust arbitrary
        # client-supplied X-Forwarded-For entries by default.
        try:
            hops = int(os.getenv('ACCOUNT_TRUSTED_PROXY_HOPS', '0'))
            if not 0 <= hops <= 20:
                raise ValueError()
        except ValueError:
            raise MailConfigurationError('Invalid trusted proxy hop count') from None
        chain = request.headers.get('X-Forwarded-For', '').split(',')[-20:]
        if hops > 0 and len(chain) >= hops:
            try:
                return str(ipaddress.ip_address(chain[-hops].strip()))
            except ValueError:
                pass
        return request.remote_addr or 'unknown'

    @bp.post('/forgot-password')
    def forgot_password():
        data = body(); email = data.get('email')
        if not isinstance(email, str) or len(email.strip()) > 254 or not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email.strip()):
            raise ValueError('Enter a valid email address.')
        email = email.strip()
        secret()  # Same configuration checks apply to existing/unknown users.
        if not limit('forgot-ip', peer(), 10, 900):
            return api_error('Too many reset requests. Please wait 15 minutes before trying again.', 'RATE_LIMITED', 429)
        if not limit('forgot-email', email.casefold(), 1, 60):
            return jsonify(message=RESET_MESSAGE), 200
        if not limit('forgot-email-hour', email.casefold(), 5, 3600):
            return jsonify(message=RESET_MESSAGE), 200
        # Validate sender/link configuration equally for every supplied address.
        job = new_job('password_reset', email)
        user = db.UserTable.get_item(Key={'email': email}, ConsistentRead=True).get('Item')
        if not user or not user.get('password'):
            return jsonify(message=RESET_MESSAGE), 200
        now = int(time.time())
        digest = token_digest(reset_token(job))
        transaction = [put_job(job, db), {'Update': {
            'TableName': db.UserTable.name, 'Key': {'email': email},
            'ConditionExpression': 'attribute_exists(email) AND password = :old AND (attribute_not_exists(password_reset_requested_at) OR password_reset_requested_at <= :cutoff)',
            'UpdateExpression': 'SET password_reset_digest = :digest, password_reset_expires = :expires, password_reset_requested_at = :now',
            'ExpressionAttributeValues': {':old': user['password'], ':cutoff': now - 60, ':digest': digest, ':expires': now + RESET_SECONDS, ':now': now}}}]
        try:
            db.UserTable.meta.client.transact_write_items(TransactItems=transaction, ClientRequestToken=secrets.token_hex(16))
        except ClientError as error:
            if error.response['Error']['Code'] == 'TransactionCanceledException':
                reasons = error.response.get('CancellationReasons', [])
                if any(r.get('Code') == 'ConditionalCheckFailed' for r in reasons):
                    return jsonify(message=RESET_MESSAGE), 200
            raise
        try_deliver(db, job['pk'])
        return jsonify(message=RESET_MESSAGE), 200

    def save_password(user, password, *, digest=None):
        if db.bcrypt.check_password_hash(user['password'], password):
            raise ValueError('Choose a new password different from your current password.')
        now = int(time.time())
        job = new_job('password_changed', user['email'])
        values = {':old': user['password'], ':new': db.bcrypt.generate_password_hash(password).decode(), ':now': now}
        condition = 'attribute_exists(email) AND password = :old'
        if digest:
            condition += ' AND password_reset_digest = :digest AND password_reset_expires > :now'
            values[':digest'] = digest
        transaction = [put_job(job, db), {'Update': {
            'TableName': db.UserTable.name, 'Key': {'email': user['email']},
            'ConditionExpression': condition,
            'UpdateExpression': 'SET password = :new, password_changed_at = :now REMOVE password_reset_digest, password_reset_expires',
            'ExpressionAttributeValues': values}}]
        try:
            db.UserTable.meta.client.transact_write_items(TransactItems=transaction, ClientRequestToken=secrets.token_hex(16))
        except ClientError as error:
            if error.response['Error']['Code'] == 'TransactionCanceledException' and any(r.get('Code') == 'ConditionalCheckFailed' for r in error.response.get('CancellationReasons', [])):
                raise ValueError('This request is no longer valid. Please start again.') from None
            raise
        status = try_deliver(db, job['pk'])
        response = jsonify(message='Your password has changed. Please sign in with your new password.',
                           email_status='sent' if status == 'accepted' else 'queued')
        unset_jwt_cookies(response)
        return response, 200

    @bp.post('/reset-password')
    def reset_password():
        data = body(); password = new_password(data)
        if not limit('reset-ip', peer(), 20, 900):
            return api_error('Too many attempts. Please wait 15 minutes before trying again.', 'RATE_LIMITED', 429)
        token = data.get('token')
        invalid_message = 'This reset link is invalid or expired. Please request a new link.'
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}\.[a-f0-9]{64}', token):
            raise ValueError(invalid_message)
        job_id = 'MAIL#' + token.split('.')[0]
        job = table(db).get_item(Key={'pk': job_id}, ConsistentRead=True).get('Item')
        if not job or job.get('kind') != 'password_reset' or job['expires_at'] <= int(time.time()) or not hmac.compare_digest(reset_token(job), token):
            raise ValueError(invalid_message)
        user = db.UserTable.get_item(Key={'email': job['email']}, ConsistentRead=True).get('Item', {})
        digest = token_digest(token)
        if not user.get('password_reset_digest') or not hmac.compare_digest(user['password_reset_digest'], digest) or user.get('password_reset_expires', 0) <= int(time.time()):
            raise ValueError(invalid_message)
        return save_password(user, password, digest=digest)

    @bp.post('/account/change-password')
    @jwt_required()
    def change_password():
        data = body(); password = new_password(data)
        email = get_jwt_identity()
        if not limit('change-password', email, 5, 900):
            return api_error('Too many attempts. Please wait 15 minutes before trying again.', 'RATE_LIMITED', 429)
        current = data.get('current_password')
        if not isinstance(current, str) or not current or len(current.encode()) > 1024:
            raise ValueError('Enter your current password.')
        user = db.UserTable.get_item(Key={'email': email}, ConsistentRead=True).get('Item')
        if not user or not db.bcrypt.check_password_hash(user['password'], current):
            raise ValueError('Your current password is incorrect.')
        # Ignore any client-supplied email; only the JWT account may be changed.
        return save_password(user, password)

    @bp.post('/internal/retry-account-emails')
    def retry_emails():
        expected = os.getenv('EMAIL_RETRY_SECRET', '')
        authorization = request.headers.get('Authorization', '')
        supplied = authorization.removeprefix('Bearer ')
        if len(expected) < 32:
            return api_error('Email retry is not configured.', 'SERVICE_UNAVAILABLE', 503)
        if not authorization.startswith('Bearer ') or not hmac.compare_digest(supplied.encode(), expected.encode()):
            return api_error('Unauthorized.', 'AUTH_REQUIRED', 401)
        return jsonify(drain(db, limit=2)), 200

    @app.after_request
    def retry_on_account_traffic(response):
        # Run a bounded attempt in the request worker, never a daemon thread.
        # Password mutation routes attempt their own committed email instead.
        if request.path in ('/login', '/get-user', '/test') and response.status_code == 200:
            try:
                if take_limit(db, 'outbox-drain', 'global', 1, 15):
                    drain(db, limit=1)
            except Exception as error:
                logger.warning('ACCOUNT_EMAIL_RETRY_DEFERRED category=%s', type(error).__name__)
        return response

    app.register_blueprint(bp)


class SessionStoreUnavailable(RuntimeError):
    pass
