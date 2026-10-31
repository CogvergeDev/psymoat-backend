"""Public error responses for authentication and checkout. Never expose exceptions."""
from flask import jsonify


def api_error(message, code, status):
    # Keep aliases during rollout so older deployed clients continue to work.
    return jsonify(status='error', code=code, message=message, msg=message, error=message), status


def install_auth_errors(jwt):
    @jwt.unauthorized_loader
    def missing_session(_reason):
        return api_error('Please sign in to continue.', 'AUTH_REQUIRED', 401)

    @jwt.expired_token_loader
    def expired_session(_header, _payload):
        return api_error('Your session has expired. Please sign in again.', 'SESSION_EXPIRED', 401)

    @jwt.invalid_token_loader
    def invalid_session(_reason):
        return api_error('Your session is invalid. Please sign in again.', 'SESSION_INVALID', 401)

    @jwt.revoked_token_loader
    def revoked_session(_header, _payload):
        return api_error('Your session has ended. Please sign in again.', 'SESSION_ENDED', 401)
