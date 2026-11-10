# Account passwords and transactional emails

## Backend environment

Set these on the Render backend (and separately in the local backend `.env`):

```dotenv
RESEND_API_KEY=re_your_private_sending_key
EMAIL_FROM=Psymoat <developer@psymoat.in>
FRONTEND_URL=https://www.psymoat.in
ACCOUNT_TOKEN_SECRET=your_independent_random_secret_at_least_32_characters
EMAIL_RETRY_SECRET=another_independent_random_secret_at_least_32_characters
ACCOUNT_OPERATIONS_TABLE=AccountOperations
ACCOUNT_TRUSTED_PROXY_HOPS=0
REGION_NAME=us-east-1
```

Generate each new secret separately with:

```sh
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Keep these values private and stable across deploys. Changing `ACCOUNT_TOKEN_SECRET`
invalidates outstanding reset links. `JWT_SECRET_KEY` must keep its existing value;
changing it signs out every user. `ACCOUNT_TOKEN_SECRET` falls back to
`JWT_SECRET_KEY` only when the latter is at least 32 characters, but a separate
secret is recommended. The sender and frontend URL shown above are defaults.

Use `FRONTEND_URL=http://localhost:3000` locally and a separate
`ACCOUNT_OPERATIONS_TABLE=AccountOperationsDev` when using a development database.
Frontend API configuration continues to use `NEXT_PUBLIC_BASE_URL` as before.
No Resend key or account secret belongs in the frontend or a `NEXT_PUBLIC_*` value.

`ACCOUNT_TRUSTED_PROXY_HOPS=0` uses the socket peer for request limits. Behind a
proxy this may group visitors together. Set it to the verified number of trusted
proxy hops in the actual deployment path before launch. For a direct Render
request with one trusted proxy appending the client address, use `1`; a frontend
proxy can add another hop. Check the actual chain rather than guessing. Only
rightmost proxy-appended addresses should be trusted.

## One-time DynamoDB setup

From `psymoat-backend`, after selecting the correct AWS account/region and table:

```sh
./venv/bin/python provision_account_operations.py
```

The command creates only the configured account operations table if absent,
validates its schema when present, and enables TTL on `ttl`:

- Partition key: `pk` (String).
- GSI: `PendingEmails`, partition `queue` (String), sort `next_attempt` (Number),
  projection `ALL`.
- Billing: on demand.
- Expired rate-limit entries and email history are cleaned up by TTL. Reset
  expiration is enforced in application code and never depends on TTL timing.
- No migration or TTL is added to the existing `User` table.

The provisioning identity needs `DescribeTable`, `CreateTable`,
`DescribeTimeToLive`, and `UpdateTimeToLive` on that table. Runtime credentials
need `GetItem`, `PutItem`, and `UpdateItem` on `User` and the account operations
table, plus `Query` on the account operations table and its `PendingEmails`
index. Policies must allow those underlying actions inside DynamoDB transactions.
Do not add an IAM condition denying transactional operations. Existing payment
and other application permissions remain necessary.

The existing backend uses `us-east-1`; provision this table in that same region.

Provision the table before deploying the backend. An unavailable outbox makes a
new signup/password mutation fail atomically rather than losing its email job.
Once the mutation is committed, provider failures return success with
`email_status: "queued"` and keep the job for retry.

## Resend

Verify `psymoat.in` and restrict the sending API key to that domain. Keep click
tracking disabled for the sending domain so reset links are not rewritten through
tracking redirects. Send one test to an inbox you control and confirm inbox/spam
placement before launch. This implementation uses HTTPS, not SMTP.

Email status `accepted` means Resend accepted the message, not that the recipient
received it. Check Resend's dashboard for delivery/bounce results. No bulk or
historical welcome emails are sent: only newly created accounts receive one.

## Retry delivery on Render Free

Each new account/password mutation attempts its own committed email with a
2-second connect timeout and 6-second read timeout. Successful login, auth checks,
and profile requests also attempt one due email at most once per 15 seconds
across processes. No background thread, local disk queue, or always-running
worker is used.

For timely retries during quiet periods, configure an external scheduler to POST
once per minute to:

```text
https://YOUR-BACKEND.onrender.com/internal/retry-account-emails
Authorization: Bearer YOUR_EMAIL_RETRY_SECRET
```

It processes at most two jobs per invocation. Allow approximately 90 seconds for
Render cold starts; the next invocation can retry if a request times out. Use a
scheduler with a private header/secret facility. Keep the bearer secret out of
query strings and logs. This endpoint is not protected by user session cookies.

You can also run a bounded retry manually from an environment with the backend's
AWS, Resend, token secret, and table configuration:

```sh
./venv/bin/python retry_account_emails.py --limit 2
```

If no external scheduler is configured, queued mail resumes when eligible user
traffic returns; a sleeping service cannot guarantee timely retries by itself.

Every job keeps a stable Resend idempotency key and payload. A lease prevents
concurrent dispatchers from sending the same job. Definitive provider rejections
(including quotas/configuration) remain queued for retry. A timeout, interrupted
acknowledgement, or uncertain provider response is only retried within 23 hours
of the first uncertain attempt. After that the job becomes `needs_review`, so a
message already accepted by Resend is not sent again after its 24-hour deduplication
window. Check Resend before any manual resolution; do not blindly reset these
rows to pending. Reset emails expire after 30 minutes; stale links are never sent.

## Routes and security behavior

- `POST /forgot-password`: same public response for existing and unknown emails,
  cooldown of at least 60 seconds, at most five requests per email/hour and ten
  requests per IP/15 minutes. Limits are persisted with HMAC-protected keys.
- `POST /reset-password`: token, `new_password`, and `confirm_password`; new
  password needs at least 8 characters and at most 72 UTF-8 bytes. Twenty reset
  attempts per IP/15 minutes. Links expire after 30 minutes, are single use, and
  are superseded by a newer request or password change. The token is carried in
  the URL fragment, read into memory, and removed from browser history. Refreshing
  the form requires reopening the email link.
- `POST /account/change-password`: authenticated user only; `current_password`,
  `new_password`, `confirm_password`; five attempts per account/15 minutes. Any
  client-supplied email is ignored. This does not call the legacy admin utility.
- Both password changes atomically update the password and enqueue the confirmation
  email, clear reset state, revoke access/refresh sessions, and clear auth cookies.
  Existing sessions without the new version claim remain valid until the user
  changes their password. New sessions are bound to the current password hash
  through a keyed fingerprint, including tokens refreshed after payment.

Reset bearer tokens, links and password hashes are not stored in email jobs or
returned in profiles. The reset link is reconstructed from job metadata and the
private token secret for retries. Logs contain error categories, not raw provider
responses, credentials, request bodies, or reset links.

## Validation and rollout

```sh
./venv/bin/python -m unittest test_account_security test_auth_errors test_payment_recovery test_payment_entitlements test_admin_audit
```

Tests mock AWS and Resend. They never send real mail. Frontend browser checks are
documented in `psymoat-frontend/tests/README.md`.

After setting environment variables, provisioning, and scheduling retries, deploy
the backend first and then the frontend. Verify signup welcome mail, forgot/reset
mail, password confirmation mail, and old-session revocation against a dedicated
test account before general use.
