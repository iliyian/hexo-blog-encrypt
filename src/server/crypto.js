'use strict';

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const pbkdf2 = promisify(crypto.pbkdf2);

/* c8 ignore start — optional dependency; PBKDF2 mode works when it is absent */
let argon2;
try {
  argon2 = require('argon2');
} catch (_e) {
  // argon2 is optional; PBKDF2 mode works without it.
}
/* c8 ignore stop */

const DEFAULT_ITERATIONS = 250000;
const SALT_BYTES = 32;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const HASH = 'sha256';
const CIPHER = 'aes-256-gcm';

const DEFAULT_ARGON2_TIME = 3;
const DEFAULT_ARGON2_MEMORY = 65536;
const DEFAULT_ARGON2_PARALLELISM = 1;

function deriveKey(password, salt, iterations) {
  const passwordBuf = typeof password === 'string'
    ? Buffer.from(password, 'utf8')
    : Buffer.from(String(password), 'utf8');
  // Async PBKDF2 (#252): runs on the libuv thread pool so a multi-post build
  // does not block the event loop for each derivation.
  return pbkdf2(passwordBuf, salt, iterations, KEY_BYTES, HASH);
}

function saltFromOpts(opts) {
  if (opts && opts.salt !== undefined) {
    if (!Buffer.isBuffer(opts.salt) || opts.salt.length !== SALT_BYTES) {
      throw new Error('salt must be a 32-byte Buffer');
    }
    return Buffer.from(opts.salt);
  }
  return crypto.randomBytes(SALT_BYTES);
}

async function encrypt(plaintext, password, opts) {
  const iterations = (opts && Number.isInteger(opts.iterations) && opts.iterations > 0)
    ? opts.iterations
    : DEFAULT_ITERATIONS;
  const salt = saltFromOpts(opts);
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const dk = await deriveKey(password, salt, iterations);
  const cipher = crypto.createCipheriv(CIPHER, dk, nonce);
  const enc = Buffer.concat([
    cipher.update(Buffer.from(String(plaintext), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([enc, tag]);
  return { salt, nonce, ciphertext };
}

async function decrypt(salt, nonce, ciphertext, password, opts) {
  const iterations = (opts && Number.isInteger(opts.iterations) && opts.iterations > 0)
    ? opts.iterations
    : DEFAULT_ITERATIONS;
  if (!Buffer.isBuffer(salt) || salt.length !== SALT_BYTES) {
    throw new Error('salt must be a 32-byte Buffer');
  }
  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_BYTES) {
    throw new Error('nonce must be a 12-byte Buffer');
  }
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length < TAG_BYTES) {
    throw new Error('ciphertext must be a Buffer of length ≥ 16');
  }
  const dk = await deriveKey(password, salt, iterations);
  const enc = ciphertext.slice(0, ciphertext.length - TAG_BYTES);
  const tag = ciphertext.slice(ciphertext.length - TAG_BYTES);
  const decipher = crypto.createDecipheriv(CIPHER, dk, nonce);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(enc), decipher.final()]);
  return out.toString('utf8');
}

// ==================== Argon2id (async) ====================

async function encryptArgon2id(plaintext, password, opts) {
  /* c8 ignore next 6 — only reachable when the optional argon2 dependency is absent */
  if (!argon2) {
    throw new Error(
      'hexo-blog-encrypt: argon2id KDF requires the "argon2" npm package. ' +
      'Install it with: npm install argon2'
    );
  }
  // The argon2 npm package rejects timeCost < 2.
  const timeCost = (opts && Number.isInteger(opts.timeCost) && opts.timeCost >= 2)
    ? opts.timeCost : DEFAULT_ARGON2_TIME;
  const memoryCost = (opts && Number.isInteger(opts.memoryCost) && opts.memoryCost >= 8192)
    ? opts.memoryCost : DEFAULT_ARGON2_MEMORY;
  const parallelism = (opts && Number.isInteger(opts.parallelism) && opts.parallelism >= 1)
    ? opts.parallelism : DEFAULT_ARGON2_PARALLELISM;

  const salt = saltFromOpts(opts);
  const nonce = crypto.randomBytes(NONCE_BYTES);

  const dk = await argon2.hash(String(password), {
    type: argon2.argon2id,
    salt,
    timeCost,
    memoryCost,
    parallelism,
    hashLength: KEY_BYTES,
    raw: true,
  });

  const cipher = crypto.createCipheriv(CIPHER, dk, nonce);
  const enc = Buffer.concat([
    cipher.update(Buffer.from(String(plaintext), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([enc, tag]);
  return { salt, nonce, ciphertext, kdf: { algorithm: 'argon2id', timeCost, memoryCost, parallelism } };
}

module.exports = {
  encrypt,
  decrypt,
  encryptArgon2id,
  deriveKey,
  DEFAULT_ITERATIONS,
  // Fork-compatible alias for the PBKDF2 default.
  DEFAULT_PBKDF2_ITERATIONS: DEFAULT_ITERATIONS,
  DEFAULT_ARGON2_TIME,
  DEFAULT_ARGON2_MEMORY,
  DEFAULT_ARGON2_PARALLELISM,
  SALT_BYTES,
  NONCE_BYTES,
  KEY_BYTES,
  TAG_BYTES,
};
