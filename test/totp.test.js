'use strict';
const assert = require('assert');
const totp = require('../src/totp');

process.env.MASTER_ENCRYPTION_KEY = '11'.repeat(32);
const { encrypt, decrypt } = require('../src/crypto_module');

// RFC 6238 Appendix B (SHA1) vectors, secret "12345678901234567890"
const secret = totp.base32Encode(Buffer.from('12345678901234567890'));
assert.strictEqual(totp.hotp(secret, Math.floor(59 / 30), 8), '94287082');
assert.strictEqual(totp.hotp(secret, Math.floor(1111111109 / 30), 8), '07081804');
assert.strictEqual(totp.hotp(secret, Math.floor(2000000000 / 30), 8), '69279037');

// base32 round trip
const rnd = totp.generateSecret(20);
assert.strictEqual(totp.base32Encode(totp.base32Decode(rnd)), rnd);

// verify returns the exact matched window and honors drift
const now = 1700000000000;
const w = totp.currentWindow(now);
assert.strictEqual(totp.verify(rnd, totp.hotp(rnd, w), now), w);
assert.strictEqual(totp.verify(rnd, totp.hotp(rnd, w - 1), now), w - 1);
assert.strictEqual(totp.verify(rnd, totp.hotp(rnd, w + 1), now), w + 1);
assert.strictEqual(totp.verify(rnd, totp.hotp(rnd, w + 2), now), null);

// AES-GCM round trip, unique IVs, tamper detection
const a = encrypt(rnd), b = encrypt(rnd);
assert.notStrictEqual(a.iv, b.iv);
assert.ok(!a.ciphertext.includes(rnd));
assert.strictEqual(decrypt(a.iv, a.ciphertext, a.authTag), rnd);
const bad = (a.ciphertext[0] === '0' ? '1' : '0') + a.ciphertext.slice(1);
assert.throws(() => decrypt(a.iv, bad, a.authTag));

console.log('all tests passed');
