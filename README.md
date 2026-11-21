# Secure 2FA Login (TOTP + AES-256-GCM)

Node.js / Express / PostgreSQL. Password login + RFC 6238 TOTP, TOTP secrets encrypted at rest, replay protection.

## Run
```
cp .env.example .env   # optional; compose has safe dev defaults
docker-compose up -d --build
```
Both services expose healthchecks; `app` waits for `db` to be healthy. Migrations (`migrations/*.sql`) and seeding of the test user from `submission.json` run on app startup.

## Endpoints
| Method | Path | Auth |
|---|---|---|
| POST | /api/auth/register | – |
| POST | /api/auth/login | – (returns `token` or `requires_2fa` + `challenge_token`) |
| POST | /api/auth/2fa/setup | access token |
| POST | /api/auth/2fa/verify | access token |
| POST | /api/auth/2fa/login | challenge token (+ `code`) |
| GET | /health | – |

## Security notes
- TOTP secret encrypted with AES-256-GCM (random 12-byte IV per encryption); IV, tag and ciphertext in separate columns.
- Challenge JWT (`scope: 2fa_challenge`, 5 min) is rejected on every route except `/2fa/login`; access routes require `scope: access`.
- Replay protection: matched window stored in `last_totp_window`; read-compare-update runs in one transaction with `SELECT ... FOR UPDATE`. The matched window (T-1/T/T+1) is stored, not the server's current one.
- Codes compared with `crypto.timingSafeEqual`; bcrypt (cost 12) for passwords.
- Not implemented (out of scope): rate limiting / lockout.

## Tests
`npm install && npm run test:totp` (RFC 6238 vectors, drift windows, AES-GCM tamper test).
