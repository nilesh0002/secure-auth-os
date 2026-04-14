# SentinelAuth OS

[![CI](https://github.com/nilesh0002/secure-auth-os/actions/workflows/ci.yml/badge.svg)](https://github.com/nilesh0002/secure-auth-os/actions/workflows/ci.yml)
[![Release](https://github.com/nilesh0002/secure-auth-os/actions/workflows/release.yml/badge.svg)](https://github.com/nilesh0002/secure-auth-os/actions/workflows/release.yml)

SentinelAuth OS is a modular authentication service built with FastAPI, SQLAlchemy, Argon2 password hashing, TOTP-based MFA, JWT session handling, RBAC, audit logging, and a Linux-friendly OS-auth abstraction.

## Features

- User registration and login
- Argon2 password hashing with automatic salting
- Configurable MFA: TOTP app (QR enrollment) or email OTP
- Strong password policy enforcement
- Password history tracking for reuse prevention
- Password expiry support
- Short-lived access tokens and rotating refresh tokens
- Login rate limiting and account lockout
- RBAC for `admin` and `user`
- Audit logging to database and rotating log file
- Modular OS authentication abstraction for PAM-style integration
- CLI helper for database bootstrap and manual user creation

## Setup

1. Create and activate the virtual environment if needed.
2. Install dependencies:

```bash
pip install -e .[dev]
```

3. Copy `.env.example` to `.env` and set secure values:

- `SECRET_KEY` must be long and random
- `DATA_ENCRYPTION_KEY` must be a 32-byte urlsafe base64 value
- `DATABASE_URL` can point to SQLite for local development or PostgreSQL for deployment

4. Initialize the database:

```bash
python cli.py init-db
```

5. Run the API:

```bash
uvicorn app.main:app --reload
```

## Deploying To Vercel

Vercel should use a managed PostgreSQL database such as Neon, Supabase, or Vercel Postgres. Do not use local SQLite for production on Vercel because serverless instances do not keep a durable writable filesystem.

1. Set these environment variables in Vercel:

- `DATABASE_URL` pointing to PostgreSQL
- `SECRET_KEY`
- `DATA_ENCRYPTION_KEY`
- `ENVIRONMENT=production`

2. Deploy the repository with the included `vercel.json`.

3. The Vercel entrypoint is [api/index.py](api/index.py), which exposes the FastAPI app.

4. If you want the API at the root domain, the included rewrite routes all traffic to the Python function.

5. Run database migrations or table creation against the managed database before production use.

## API Endpoints

- `GET /` (public landing page)
- `GET /health` (public health check)
- `POST /api/register`
- `POST /api/login`
- `POST /api/verify-mfa`
- `POST /api/change-password`
- `POST /api/forgot-password`
- `POST /api/reset-password`
- `POST /api/refresh`
- `POST /api/logout`
- `GET /api/me`
- `GET /api/admin/health`

## Security Notes

- Passwords are hashed with Argon2 and never stored in plaintext.
- TOTP secrets are encrypted at rest with AES-GCM.
- Refresh tokens are rotated and hashed before storage.
- Failed logins increase a lockout counter and are rate-limited per account and IP.
- JWT validation rejects wrong token types and expired tokens.
- RBAC checks are enforced through dependencies, not client-side logic.
- Audit events are stored in the database and also written to a rotating log file.

## MFA Flow

1. Register a user.
2. If `MFA_METHOD=totp`, the API returns a provisioning URI and QR-code data URI.
3. If `MFA_METHOD=email`, no authenticator app is needed; login issues a one-time email OTP challenge.
4. Log in with username and password.
5. Submit the MFA token and OTP code to `/api/verify-mfa`.
6. Receive access and refresh tokens.

### Email OTP Mode (Optional)

- Set `MFA_METHOD=email` to replace authenticator-app OTP with email OTP.
- For local/testing only, you can set `EXPOSE_EMAIL_OTP_IN_RESPONSE=true` to include the OTP in the login response.
- Keep `EXPOSE_EMAIL_OTP_IN_RESPONSE=false` in production.
- Configure SMTP for real delivery: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USE_STARTTLS`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`.
- If SMTP is not configured and OTP exposure is disabled, login will return `503` for email OTP requests.
- Password reset uses a separate reset token with `PASSWORD_RESET_TTL_MINUTES` and optional `PASSWORD_RESET_URL_BASE`.

## CLI

Create a user manually:

```bash
python cli.py create-user alice alice@example.com --role admin
```

## Vercel Notes

- Audit logs go to stdout on Vercel instead of a local file.
- Refresh tokens and password history are stored in the configured database.
- For production, prefer PostgreSQL over SQLite so sessions and audit records survive deploys.

## Tests

Run the sample test cases with:

```bash
pytest
```
