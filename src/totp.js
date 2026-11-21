'use strict';
// RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30s step) implemented on node:crypto.
const crypto = require('crypto');

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEP = 30;

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = str.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0, value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 character');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

function currentWindow(nowMs = Date.now()) {
  return Math.floor(nowMs / 1000 / STEP);
}

function hotp(secretBase32, counter, digits = 6) {
  const key = base32Decode(secretBase32);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const offset = h[h.length - 1] & 0x0f;
  const bin =
    ((h[offset] & 0x7f) << 24) |
    (h[offset + 1] << 16) |
    (h[offset + 2] << 8) |
    h[offset + 3];
  return String(bin % 10 ** digits).padStart(digits, '0');
}

function totp(secretBase32, nowMs = Date.now(), digits = 6) {
  return hotp(secretBase32, currentWindow(nowMs), digits);
}

function safeEqual(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

/**
 * Checks windows T-1, T, T+1 (clock drift). Returns the exact window that
 * matched, or null. Every window is evaluated (no early exit).
 */
function verify(secretBase32, code, nowMs = Date.now(), drift = 1) {
  const t = currentWindow(nowMs);
  let matched = null;
  for (let w = t - drift; w <= t + drift; w++) {
    if (safeEqual(hotp(secretBase32, w), code)) matched = w;
  }
  return matched;
}

function otpauthUri(secret, email, issuer) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(email)}`;
  return (
    `otpauth://totp/${label}?secret=${secret}` +
    `&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=${STEP}`
  );
}

module.exports = {
  base32Encode, base32Decode, generateSecret, currentWindow,
  hotp, totp, verify, otpauthUri,
};
