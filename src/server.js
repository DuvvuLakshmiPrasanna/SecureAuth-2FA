'use strict';
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { pool, waitForDb, migrate, seed } = require('./db');
const { encrypt, decrypt } = require('./crypto_module');
const totp = require('./totp');

const JWT_SECRET = process.env.JWT_SECRET;
const ISSUER = process.env.TOTP_ISSUER || 'SecureAuthApp';
const PORT = process.env.PORT || 3000;
if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

const app = express();
app.use(express.json());

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_RE = /^\d{6}$/;
// Used to equalize timing when the email does not exist.
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12);

const signAccess = (userId) =>
  jwt.sign({ sub: userId, scope: 'access' }, JWT_SECRET, { expiresIn: '1h' });
const signChallenge = (userId) =>
  jwt.sign({ sub: userId, scope: '2fa_challenge' }, JWT_SECRET, { expiresIn: '5m' });

function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

// Only full-access tokens pass; challenge tokens are rejected here.
function requireAccess(req, res, next) {
  const token = bearer(req);
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    const p = jwt.verify(token, JWT_SECRET);
    if (p.scope !== 'access') return res.status(403).json({ error: 'Insufficient scope' });
    req.userId = p.sub;
    next();
  } catch (e) {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ error: 'Internal server error' });
  });

app.get('/health', wrap(async (req, res) => {
  await pool.query('SELECT 1');
  res.json({ status: 'ok' });
}));

app.post('/api/auth/register', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || !EMAIL_RE.test(email))
    return res.status(400).json({ error: 'Valid email required' });
  if (typeof password !== 'string' || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email.toLowerCase(), hash]
    );
    res.status(201).json({ id: rows[0].id, email: rows[0].email });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    throw e;
  }
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== 'string' || typeof password !== 'string')
    return res.status(400).json({ error: 'email and password required' });
  const { rows } = await pool.query(
    'SELECT id, password_hash, totp_enabled FROM users WHERE email = $1',
    [email.toLowerCase()]
  );
  const user = rows[0];
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.totp_enabled) {
    // Never issue a full token here when 2FA is on.
    return res.json({ requires_2fa: true, challenge_token: signChallenge(user.id) });
  }
  res.json({ token: signAccess(user.id) });
}));

app.post('/api/auth/2fa/setup', requireAccess, wrap(async (req, res) => {
  const { rows } = await pool.query('SELECT email, totp_enabled FROM users WHERE id = $1', [req.userId]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Unknown user' });
  if (user.totp_enabled) return res.status(409).json({ error: '2FA already enabled' });
  const secret = totp.generateSecret(20);
  const enc = encrypt(secret);
  await pool.query(
    `UPDATE users SET totp_secret_encrypted = $1, totp_iv = $2, totp_tag = $3,
       totp_enabled = false, last_totp_window = NULL WHERE id = $4`,
    [enc.ciphertext, enc.iv, enc.authTag, req.userId]
  );
  res.json({ secret, uri: totp.otpauthUri(secret, user.email, ISSUER) });
}));

app.post('/api/auth/2fa/verify', requireAccess, wrap(async (req, res) => {
  const { code } = req.body || {};
  if (typeof code !== 'string' || !CODE_RE.test(code))
    return res.status(400).json({ error: 'code must be a 6-digit string' });
  const { rows } = await pool.query(
    'SELECT totp_enabled, totp_secret_encrypted, totp_iv, totp_tag FROM users WHERE id = $1',
    [req.userId]
  );
  const u = rows[0];
  if (!u || !u.totp_secret_encrypted)
    return res.status(400).json({ error: 'Run /api/auth/2fa/setup first' });
  const secret = decrypt(u.totp_iv, u.totp_secret_encrypted, u.totp_tag);
  if (totp.verify(secret, code) === null) return res.status(401).json({ error: 'Invalid code' });
  await pool.query('UPDATE users SET totp_enabled = true WHERE id = $1', [req.userId]);
  res.json({ message: '2FA successfully enabled' });
}));

app.post('/api/auth/2fa/login', wrap(async (req, res) => {
  const { challenge_token, code } = req.body || {};
  if (typeof challenge_token !== 'string' || typeof code !== 'string' || !CODE_RE.test(code))
    return res.status(400).json({ error: 'challenge_token and 6-digit code required' });

  let payload;
  try {
    payload = jwt.verify(challenge_token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired challenge token' });
  }
  if (payload.scope !== '2fa_challenge')
    return res.status(401).json({ error: 'Invalid challenge token' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Row lock serializes concurrent attempts -> no replay race.
    const { rows } = await client.query(
      `SELECT totp_enabled, totp_secret_encrypted, totp_iv, totp_tag, last_totp_window
         FROM users WHERE id = $1 FOR UPDATE`,
      [payload.sub]
    );
    const u = rows[0];
    if (!u || !u.totp_enabled || !u.totp_secret_encrypted) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Invalid code' });
    }
    const secret = decrypt(u.totp_iv, u.totp_secret_encrypted, u.totp_tag);
    const matched = totp.verify(secret, code);
    if (matched === null || (u.last_totp_window !== null && matched <= u.last_totp_window)) {
      await client.query('ROLLBACK');
      return res.status(401).json({ error: 'Invalid or already used code' });
    }
    await client.query('UPDATE users SET last_totp_window = $1 WHERE id = $2', [matched, payload.sub]);
    await client.query('COMMIT');
    res.json({ token: signAccess(payload.sub) });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}));

(async () => {
  await waitForDb();
  await migrate();
  await seed();
  app.listen(PORT, () => console.log(`[server] listening on ${PORT}`));
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
