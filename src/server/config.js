'use strict';

const PBKDF2_FLOOR = 100000;
const PBKDF2_RECOMMENDED = 600000;
// Argon2id parameter floors: time ≥ 1, memory ≥ 8192 (8 MB), parallelism ≥ 1.
const ARGON2_TIME_FLOOR = 1;
const ARGON2_MEMORY_FLOOR = 8192;

const DEFAULTS = Object.freeze({
  abstract: 'Here\'s something encrypted, password is required to continue reading.',
  message: 'Hey, password is required here.',
  theme: 'default',
  wrong_pass_message: 'Oh, this is an invalid password. Check and try again, please.',
  // wrong_hash_message intentionally omitted from DEFAULTS — it defaults to the
  // resolved wrong_pass_message in resolve() below (single source of truth under
  // unified GCM failure handling).
  silent: false,
  autoSave: false,
  decryptButton: Object.freeze({
    show: true,
    text: 'Decrypt',
  }),
  kdf: Object.freeze({
    algorithm: 'pbkdf2',
    // PBKDF2 settings (used when algorithm === 'pbkdf2')
    iterations: 250000,
    // Argon2id settings (used when algorithm === 'argon2id')
    timeCost: 3,
    memoryCost: 65536,
    parallelism: 1,
  }),
});

function clone(value) {
  if (value === null || typeof value !== 'object') return value;
  if (typeof structuredClone === 'function') return structuredClone(value);
  /* c8 ignore next 2 — Node ≥18 always has structuredClone; fallback is for non-Node hosts. */
  return JSON.parse(JSON.stringify(value));
}

function deepMerge(base, overlay) {
  if (overlay === null || overlay === undefined) return clone(base);
  if (typeof base !== 'object' || base === null || Array.isArray(base)) return clone(overlay);
  if (typeof overlay !== 'object' || Array.isArray(overlay)) return clone(overlay);
  const out = {};
  const keys = new Set([...Object.keys(base), ...Object.keys(overlay)]);
  for (const key of keys) {
    if (key in overlay) {
      out[key] = deepMerge(base[key], overlay[key]);
    } else {
      out[key] = clone(base[key]);
    }
  }
  return out;
}

function shallowPickKnown(source, knownKeys) {
  const out = {};
  for (const key of knownKeys) {
    if (key in source) out[key] = source[key];
  }
  return out;
}

// Keys allowed to flow from the front-matter `post` object into `resolve()`'s
// deep merge. Deliberately EXCLUDES `tags`: Hexo materializes `post.tags` as a
// Warehouse Query containing functions/methods, which `structuredClone` cannot
// clone (DataCloneError). The post's tag list is read directly by
// `resolveTagPassword(hexoConfig.encrypt, data.tags)` over in `index.js`; the
// `tags` field on `hexoConfig.encrypt` (the {name, password} registry) is
// allowed and lives in `KNOWN_KEYS`.
const POST_KNOWN_KEYS = [
  'password',
  'abstract',
  'message',
  'theme',
  'template',
  'wrong_pass_message',
  'wrong_hash_message',
  'silent',
  'autoSave',
  'decryptButton',
  'kdf',
];

const KNOWN_KEYS = [
  ...POST_KNOWN_KEYS,
  'tags',
];

function resolve(hexoConfig, postData, logger) {
  // Only `warn` is ever called from this module; keep the no-op default minimal.
  const log = logger || { warn: () => {} };

  // hexo.config.encrypt may legitimately be missing OR a non-object truthy
  // value (e.g. `encrypt: true` in _config.yml, which YAML parses as boolean).
  // Treat any non-plain-object as "no encrypt block configured".
  const hexoEncrypt = (
    hexoConfig
    && typeof hexoConfig.encrypt === 'object'
    && hexoConfig.encrypt !== null
    && !Array.isArray(hexoConfig.encrypt)
  ) ? hexoConfig.encrypt : {};
  const post = postData || {};

  // Layer 1: defaults → hexo encrypt block (for top-level shared keys, NOT password/theme overrides per-post).
  let merged = deepMerge(DEFAULTS, shallowPickKnown(hexoEncrypt, KNOWN_KEYS));

  // Layer 2: post front-matter wins. Use POST_KNOWN_KEYS (which excludes
  // `tags`) to avoid pulling Hexo's Warehouse Query for `post.tags` into
  // the deep-merge — `structuredClone` would throw DataCloneError on the
  // function-bearing internals.
  merged = deepMerge(merged, shallowPickKnown(post, POST_KNOWN_KEYS));

  // Deprecation: template → theme.
  if (merged.template !== undefined && merged.template !== null) {
    log.warn(
      'hexo-blog-encrypt: "template" is deprecated, use "theme" instead. ' +
      'See https://github.com/D0n9X1n/hexo-blog-encrypt#encrypt-theme'
    );
    if (merged.theme === DEFAULTS.theme) {
      merged.theme = merged.template;
    }
    delete merged.template;
  }

  // Password: undefined or empty-string disables encryption (caller short-circuits).
  if (merged.password === undefined || merged.password === null) return null;
  merged.password = String(merged.password);
  if (merged.password === '') return null;

  // Normalise KDF algorithm: undefined/garbage → 'pbkdf2'.
  if (typeof merged.kdf !== 'object' || merged.kdf === null) {
    merged.kdf = { algorithm: 'pbkdf2', iterations: undefined };
  }
  if (!merged.kdf.algorithm || !['pbkdf2', 'argon2id'].includes(merged.kdf.algorithm)) {
    merged.kdf.algorithm = 'pbkdf2';
  }

  if (merged.kdf.algorithm === 'pbkdf2') {
    if (!Number.isInteger(merged.kdf.iterations) || merged.kdf.iterations < PBKDF2_FLOOR) {
      throw new Error(
        `hexo-blog-encrypt: kdf.iterations must be an integer ≥ ${PBKDF2_FLOOR.toLocaleString('en-US').replace(/,/g, '_')} ` +
        `(got ${merged.kdf.iterations}). 100_000 is the absolute floor; ${PBKDF2_RECOMMENDED.toLocaleString('en-US').replace(/,/g, '_')}+ is recommended (OWASP 2023).`
      );
    }
    if (merged.kdf.iterations < PBKDF2_RECOMMENDED) {
      log.warn(
        `hexo-blog-encrypt: kdf.iterations=${merged.kdf.iterations} is below the OWASP-recommended 600_000. ` +
        'Consider raising it for stronger brute-force resistance.'
      );
    }
  } else {
    // Argon2id validation.
    if (!Number.isInteger(merged.kdf.timeCost) || merged.kdf.timeCost < ARGON2_TIME_FLOOR) {
      throw new Error(
        `hexo-blog-encrypt: kdf.timeCost must be an integer ≥ ${ARGON2_TIME_FLOOR} (got ${merged.kdf.timeCost}).`
      );
    }
    if (!Number.isInteger(merged.kdf.memoryCost) || merged.kdf.memoryCost < ARGON2_MEMORY_FLOOR) {
      throw new Error(
        `hexo-blog-encrypt: kdf.memoryCost must be an integer ≥ ${ARGON2_MEMORY_FLOOR} (8 MB) (got ${merged.kdf.memoryCost}).`
      );
    }
    if (!Number.isInteger(merged.kdf.parallelism) || merged.kdf.parallelism < 1) {
      throw new Error(
        `hexo-blog-encrypt: kdf.parallelism must be an integer ≥ 1 (got ${merged.kdf.parallelism}).`
      );
    }
  }

  // wrong_hash_message handling under GCM:
  //   - User explicitly set it → keep it but warn (deprecated alias).
  //   - User did NOT set it → default to the resolved wrong_pass_message.
  const userSetWhm =
    (post.wrong_hash_message !== undefined) || (hexoEncrypt.wrong_hash_message !== undefined);
  if (userSetWhm) {
    log.warn(
      'hexo-blog-encrypt: "wrong_hash_message" is deprecated under v4 (AES-GCM unifies wrong-password ' +
      'and tampered-ciphertext failures). The value is now an alias of "wrong_pass_message". ' +
      'Set "wrong_pass_message" instead.'
    );
  } else {
    merged.wrong_hash_message = merged.wrong_pass_message;
  }

  return merged;
}

module.exports = {
  resolve,
  DEFAULTS,
  PBKDF2_FLOOR,
  PBKDF2_RECOMMENDED,
  ARGON2_TIME_FLOOR,
  ARGON2_MEMORY_FLOOR,
};
