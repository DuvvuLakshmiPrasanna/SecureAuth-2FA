'use strict';
const fs = require('fs');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { encrypt } = require('./crypto_module');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForDb(retries = 30) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (e) {
      await sleep(1000);
    }
  }
  throw new Error('Database not reachable');
}

async function migrate() {
  const dir = path.join(__dirname, '..', 'migrations');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.sql')).sort();
  for (const f of files) {
    await pool.query(fs.readFileSync(path.join(dir, f), 'utf8'));
    console.log(`[migrate] applied ${f}`);
  }
}

// Seeds the evaluator's 2FA user from submission.json (idempotent).
async function seed() {
  const file = path.join(__dirname, '..', 'submission.json');
  if (!fs.existsSync(file)) return;
  const { testUser } = JSON.parse(fs.readFileSync(file, 'utf8'));
  const { rows } = await pool.query('SELECT 1 FROM users WHERE email = $1', [testUser.email]);
  if (rows.length) return;
  const hash = await bcrypt.hash(testUser.password, 12);
  const enc = encrypt(testUser.plaintextTotpSecret);
  await pool.query(
    `INSERT INTO users (email, password_hash, totp_enabled, totp_secret_encrypted, totp_iv, totp_tag)
     VALUES ($1, $2, true, $3, $4, $5) ON CONFLICT (email) DO NOTHING`,
    [testUser.email, hash, enc.ciphertext, enc.iv, enc.authTag]
  );
  console.log(`[seed] created 2FA test user ${testUser.email}`);
}

module.exports = { pool, waitForDb, migrate, seed };
