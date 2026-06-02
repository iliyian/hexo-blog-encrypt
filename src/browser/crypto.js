'use strict';

// Browser-side AES-256-GCM decryption with PBKDF2 or Argon2id key derivation.
// KDF is selected by the `data-kdf-algorithm` attribute in the HTML template.
//
// PBKDF2:   Web Crypto API (crypto.subtle)
// Argon2id: hash-wasm WASM module
//
// AES: 256-bit key, GCM mode, 12-byte nonce, 16-byte auth tag.
//
// Unified failure path: ANY thrown value (DOMException OperationError,
// TypeError, etc.) collapses to {ok: false}. Wrong-password and
// tampered-ciphertext are indistinguishable under GCM by design.

const { argon2id: hashWasmArgon2id } = require('hash-wasm');

const KEY_BITS = 256;
const TAG_BITS = 128;
const TAG_BYTES = TAG_BITS / 8;
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });
const TEXT_ENCODER = new TextEncoder();

function hexToBytes(hex) {
  const len = hex.length;
  if (len % 2 !== 0) {
    throw new Error('hexo-blog-encrypt: hex string has odd length');
  }
  const out = new Uint8Array(len / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

// ---------- PBKDF2 (Web Crypto) ----------

async function deriveKeyPbkdf2(password, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    TEXT_ENCODER.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: KEY_BITS },
    true, // extractable=true so storage.js can persist the raw key bytes when autoSave is on
    ['decrypt']
  );
}

// ---------- Argon2id (hash-wasm) ----------

async function deriveKeyArgon2id(password, salt, opts) {
  const timeCost = (opts && Number.isInteger(opts.timeCost) && opts.timeCost >= 1)
    ? opts.timeCost : 3;
  const memoryCost = (opts && Number.isInteger(opts.memoryCost) && opts.memoryCost >= 8192)
    ? opts.memoryCost : 65536;
  const parallelism = (opts && Number.isInteger(opts.parallelism) && opts.parallelism >= 1)
    ? opts.parallelism : 1;

  const raw = await hashWasmArgon2id({
    password,
    salt,
    iterations: timeCost,
    memorySize: memoryCost,
    parallelism,
    hashLength: KEY_BITS / 8,
    outputType: 'binary',
  });

  // Import the raw bytes as an AES-GCM key.
  // extractable=true so storage.js can persist the key when autoSave is on.
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'AES-GCM', length: KEY_BITS },
    true,
    ['decrypt']
  );
}

// ---------- AES-GCM decryption ----------

async function decryptWithKey(key, nonce, ciphertextWithTag) {
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: TAG_BITS },
    key,
    ciphertextWithTag
  );
  return TEXT_DECODER.decode(plainBuf);
}

// ---------- High-level: derive + decrypt ----------

async function tryDecryptWithPassword({ password, saltHex, nonceHex, ciphertextHex,
                                        algorithm, iterations, timeCost, memoryCost, parallelism }) {
  try {
    const salt = hexToBytes(saltHex);
    const nonce = hexToBytes(nonceHex);
    const ciphertext = hexToBytes(ciphertextHex);
    if (ciphertext.length < TAG_BYTES) return { ok: false };

    let key;
    if (algorithm === 'argon2id') {
      key = await deriveKeyArgon2id(password, salt, { timeCost, memoryCost, parallelism });
    } else {
      key = await deriveKeyPbkdf2(password, salt, iterations || 250000);
    }

    const plaintext = await decryptWithKey(key, nonce, ciphertext);
    return { ok: true, plaintext, key };
  } catch (_e) {
    return { ok: false };
  }
}

// Same shape, but reuses an already-derived key (autosave fast path).
async function tryDecryptWithKey({ key, nonceHex, ciphertextHex }) {
  try {
    const nonce = hexToBytes(nonceHex);
    const ciphertext = hexToBytes(ciphertextHex);
    if (ciphertext.length < TAG_BYTES) return { ok: false };
    const plaintext = await decryptWithKey(key, nonce, ciphertext);
    return { ok: true, plaintext };
  } catch (_e) {
    return { ok: false };
  }
}

module.exports = {
  tryDecryptWithPassword,
  tryDecryptWithKey,
  deriveKeyPbkdf2,
  deriveKeyArgon2id,
  decryptWithKey,
  hexToBytes,
};
