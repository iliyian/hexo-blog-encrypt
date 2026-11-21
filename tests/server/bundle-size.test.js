'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BUNDLE_PATH = path.resolve(__dirname, '../../lib/hbe.bundle.js');
// This fork keeps Argon2id support (hash-wasm) on top of upstream v4.1.0's
// multi-container runtime. hash-wasm embeds its WASM payload in the bundle,
// so the PBKDF2-only upstream budget (10 KiB) does not apply. The 240 KiB
// ceiling leaves headroom for the merged browser code and fails if the
// bundle grows unexpectedly.
const MAX_BYTES = 245760;

if (!fs.existsSync(BUNDLE_PATH)) {
  test.skip('lib/hbe.bundle.js missing — run `npm run build` first');
} else {
  test(`browser bundle is ≤ ${MAX_BYTES} bytes (current budget)`, () => {
    const bytes = fs.statSync(BUNDLE_PATH).size;
    assert.ok(
      bytes <= MAX_BYTES,
      `lib/hbe.bundle.js is ${bytes} bytes, over the ${MAX_BYTES}-byte budget. ` +
      'Either trim the bundle or raise MAX_BYTES with explicit justification.'
    );
  });

  test('browser bundle is non-empty', () => {
    const bytes = fs.statSync(BUNDLE_PATH).size;
    assert.ok(bytes > 0, 'lib/hbe.bundle.js exists but is 0 bytes');
  });

  test('browser bundle sourcemap exists alongside the bundle', () => {
    assert.ok(
      fs.existsSync(BUNDLE_PATH + '.map'),
      'lib/hbe.bundle.js.map should be emitted alongside the bundle'
    );
  });
}
