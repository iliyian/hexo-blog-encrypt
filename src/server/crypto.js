'use strict';

const crypto = require('node:crypto');
let argon2;
try {
  argon2 = require('argon2');
} catch (_e) {
  // argon2 is optional; PBKDF2 mode works without it.
}

const SALT_BYTES = 32;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const HASH = 'sha256';
const CIPHER = 'aes-256-gcm';

const DEFAULT_PBKDF2_ITERATIONS = 250000;
const DEFAULT_ARGON2_TIME = 3;
const DEFAULT_ARGON2_MEMORY = 65536;
const DEFAULT_ARGON2_PARALLELISM = 1;

function deriveKeyPbkdf2(password, salt, iterations) {
  const passwordBuf = typeof password === 'string'
    ? Buffer.from(password, 'utf8')
    : Buffer.from(String(password), 'utf8');
  return crypto.pbkdf2Sync(passwordBuf, salt, iterations, KEY_BYTES, HASH);
}

// ==================== PBKDF2 (sync — original v4 API) ====================

function encrypt(plaintext, password, opts) {
  const iterations = (opts && Number.isInteger(opts.iterations) && opts.iterations > 0)
    ? opts.iterations
    : DEFAULT_PBKDF2_ITERATIONS;
  const salt = crypto.randomBytes(SALT_BYTES);
  const nonce = crypto.randomBytes(NONCE_BYTES);
  const dk = deriveKeyPbkdf2(password, salt, iterations);
  const cipher = crypto.createCipheriv(CIPHER, dk, nonce);
  const enc = Buffer.concat([
    cipher.update(Buffer.from(String(plaintext), 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  const ciphertext = Buffer.concat([enc, tag]);
  return { salt, nonce, ciphertext };
}

function decrypt(salt, nonce, ciphertext, password, opts) {
  const iterations = (opts && Number.isInteger(opts.iterations) && opts.iterations > 0)
    ? opts.iterations
    : DEFAULT_PBKDF2_ITERATIONS;
  if (!Buffer.isBuffer(salt) || salt.length !== SALT_BYTES) {
    throw new Error('salt must be a 32-byte Buffer');
  }
  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_BYTES) {
    throw new Error('nonce must be a 12-byte Buffer');
  }
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length < TAG_BYTES) {
    throw new Error('ciphertext must be a Buffer of length ≥ 16');
  }
  const dk = deriveKeyPbkdf2(password, salt, iterations);
  const enc = ciphertext.slice(0, ciphertext.length - TAG_BYTES);
  const tag = ciphertext.slice(ciphertext.length - TAG_BYTES);
  const decipher = crypto.createDecipheriv(CIPHER, dk, nonce);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(enc), decipher.final()]);
  return out.toString('utf8');
}

// ==================== Argon2id (async) ====================

async function encryptArgon2id(plaintext, password, opts) {
  if (!argon2) {
    throw new Error(
      'hexo-blog-encrypt: argon2id KDF requires the "argon2" npm package. ' +
      'Install it with: npm install argon2'
    );
  }
  const timeCost = (opts && Number.isInteger(opts.timeCost) && opts.timeCost >= 1)
    ? opts.timeCost : DEFAULT_ARGON2_TIME;
  const memoryCost = (opts && Number.isInteger(opts.memoryCost) && opts.memoryCost >= 8192)
    ? opts.memoryCost : DEFAULT_ARGON2_MEMORY;
  const parallelism = (opts && Number.isInteger(opts.parallelism) && opts.parallelism >= 1)
    ? opts.parallelism : DEFAULT_ARGON2_PARALLELISM;

  const salt = crypto.randomBytes(SALT_BYTES);
  const nonce = crypto.randomBytes(NONCE_BYTES);

  const dk = await argon2.hash(password, {
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
  DEFAULT_PBKDF2_ITERATIONS,
  DEFAULT_ARGON2_TIME,
  DEFAULT_ARGON2_MEMORY,
  DEFAULT_ARGON2_PARALLELISM,
  SALT_BYTES,
  NONCE_BYTES,
  KEY_BYTES,
  TAG_BYTES,
};
