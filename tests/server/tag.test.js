'use strict';

const { test, before, after, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const argon2 = require('argon2');

const { buildSite } = require('../helpers/buildSite.js');
const { decrypt } = require('../../src/server/crypto');
const { _internal } = require('../../src/server/tag');

const SECRET = '<p>BLOCK SECRET</p>';

function extractPayload(html) {
  const m = (re) => {
    const r = html.match(re);
    if (!r) throw new Error('payload missing field; regex=' + re);
    return r[1];
  };
  return {
    salt: Buffer.from(m(/data-salt="([0-9a-f]+)"/i), 'hex'),
    nonce: Buffer.from(m(/data-nonce="([0-9a-f]+)"/i), 'hex'),
    ciphertext: Buffer.from(
      m(/<script id="hbeData"[^>]*>([\s\S]*?)<\/script>/i).trim(),
      'hex'
    ),
    algorithm: m(/data-kdf-algorithm="([^"]*)"/i) || 'pbkdf2',
    iterations: parseInt(m(/data-kdf-iterations="([^"]*)"/i), 10) || 250000,
    timeCost: parseInt(m(/data-kdf-time-cost="([^"]*)"/i), 10) || 3,
    memoryCost: parseInt(m(/data-kdf-memory-cost="([^"]*)"/i), 10) || 65536,
    parallelism: parseInt(m(/data-kdf-parallelism="([^"]*)"/i), 10) || 1,
  };
}

async function decryptPayload(payload, password) {
  if (payload.algorithm === 'argon2id') {
    const dk = await argon2.hash(password, {
      type: argon2.argon2id,
      salt: payload.salt,
      timeCost: payload.timeCost,
      memoryCost: payload.memoryCost,
      parallelism: payload.parallelism,
      hashLength: 32,
      raw: true,
    });
    const tag = payload.ciphertext.subarray(payload.ciphertext.length - 16);
    const body = payload.ciphertext.subarray(0, payload.ciphertext.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', dk, payload.nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
  }
  return decrypt(payload.salt, payload.nonce, payload.ciphertext, password, {
    iterations: payload.iterations,
  });
}

let hexo;
let originalEncrypt;

before(async () => {
  hexo = await buildSite();
});

after(async () => {
  if (hexo) await hexo.exit();
});

beforeEach(() => {
  originalEncrypt = hexo.config.encrypt;
  hexo.config.encrypt = {};
});

afterEach(() => {
  hexo.config.encrypt = originalEncrypt;
});

async function render(content, data) {
  const post = Object.assign({ title: 'tag-test', tags: [] }, data);
  const html = await hexo.extend.tag.render(content, post);
  post.content = html;
  await hexo.execFilter('after_post_render', post, { context: hexo });
  return post.content;
}

// ---------------------------------------------------------------------------
// {% encrypt %} — partial (single block) encryption
// ---------------------------------------------------------------------------
test('{% encrypt %} encrypts only the block and leaves surrounding text public', async () => {
  const html = await render(
    'PUBLIC BEFORE\n{% encrypt "pw" %}' + SECRET + '{% endencrypt %}\nPUBLIC AFTER'
  );

  assert.match(html, /^PUBLIC BEFORE\n/);
  assert.match(html, /\nPUBLIC AFTER$/);
  assert.equal((html.match(/hbe-container/g) || []).length, 1);
  assert.equal((html.match(/<script data-pjax/g) || []).length, 1);
  assert.match(html, /css\/hbe\.style\.css/);
  assert.ok(!html.includes('BLOCK SECRET'), 'plaintext must not leak into the page');

  const payload = extractPayload(html);
  assert.equal(payload.algorithm, 'pbkdf2');
  assert.equal(await decryptPayload(payload, 'pw'), SECRET);
  await assert.rejects(() => decryptPayload(payload, 'wrong'));
});

test('{% encrypt %} supports a quoted password with spaces', async () => {
  const html = await render('{% encrypt "pass word" %}' + SECRET + '{% endencrypt %}');
  assert.equal(await decryptPayload(extractPayload(html), 'pass word'), SECRET);
});

test('two sibling {% encrypt %} blocks have independent passwords and containers', async () => {
  const html = await render(
    '{% encrypt "one" %}<p>ONE</p>{% endencrypt %}' +
    '{% encrypt "two" %}<p>TWO</p>{% endencrypt %}'
  );

  assert.equal((html.match(/hbe-container/g) || []).length, 2);
  assert.equal((html.match(/<script data-pjax/g) || []).length, 2);

  const containers = html.split('<div class="hbe hbe-container"').slice(1);
  assert.equal(containers.length, 2);
  const first = extractPayload(containers[0]);
  const second = extractPayload(containers[1]);
  assert.equal(await decryptPayload(first, 'one'), '<p>ONE</p>');
  assert.equal(await decryptPayload(second, 'two'), '<p>TWO</p>');
  await assert.rejects(() => decryptPayload(first, 'two'));
});

test('{% encrypt %} honours theme / hidden button / custom button text from config', async () => {
  hexo.config.encrypt = {
    theme: 'flip',
    decryptButton: { show: false, text: 'Open' },
  };
  const html = await render('{% encrypt "pw" %}' + SECRET + '{% endencrypt %}');
  assert.match(html, /hbe-input-field-flip/);
  assert.match(html, /hbe-button hbe-button-hidden/);
  assert.match(html, />Open<\/button>/);
});

test('{% encrypt %} with argon2id emits argon2id wire attributes and decrypts', async () => {
  hexo.config.encrypt = {
    kdf: { algorithm: 'argon2id', timeCost: 2, memoryCost: 8192, parallelism: 1 },
  };
  const html = await render('{% encrypt "pw" %}' + SECRET + '{% endencrypt %}');
  const payload = extractPayload(html);
  assert.equal(payload.algorithm, 'argon2id');
  assert.equal(payload.timeCost, 2);
  assert.equal(payload.memoryCost, 8192);
  assert.equal(await decryptPayload(payload, 'pw'), SECRET);
});

test('{% encrypt %} rejects a missing password', async () => {
  await assert.rejects(
    () => render('{% encrypt %}x{% endencrypt %}'),
    /requires at least 1 password/
  );
});

test('parsePasswords rejects an explicitly empty password', () => {
  assert.throws(
    () => _internal.parsePasswords([''], 'encrypt', 1, { title: 'T' }),
    /empty password in post "T"/
  );
  assert.throws(
    () => _internal.parsePasswords([], 'encrypt_nested', 2, {}),
    /requires at least 2 password arguments/
  );
});

// ---------------------------------------------------------------------------
// {% encrypt_nested %} — explicit multi-layer encryption
// ---------------------------------------------------------------------------
test('{% encrypt_nested %} creates outer-first layers and only the outer has assets', async () => {
  const html = await render(
    '{% encrypt_nested "outer" "inner" %}' + SECRET + '{% endencrypt_nested %}'
  );

  assert.equal((html.match(/hbe-container/g) || []).length, 1);
  assert.equal((html.match(/<script data-pjax/g) || []).length, 1);

  const outer = extractPayload(html);
  const layer2 = await decryptPayload(outer, 'outer');
  assert.match(layer2, /hbe-container/);
  assert.ok(!/<script data-pjax/.test(layer2), 'inner layers must not carry the runtime script');

  const inner = extractPayload(layer2);
  assert.equal(await decryptPayload(inner, 'inner'), SECRET);
  await assert.rejects(() => decryptPayload(outer, 'inner'));
});

test('{% encrypt_nested %} supports three layers', async () => {
  const html = await render(
    '{% encrypt_nested "a" "b" "c" %}' + SECRET + '{% endencrypt_nested %}'
  );
  let layer = html;
  for (const password of ['a', 'b', 'c']) {
    const payload = extractPayload(layer);
    layer = await decryptPayload(payload, password);
  }
  assert.equal(layer, SECRET);
});

test('{% encrypt_nested %} requires at least two passwords', async () => {
  await assert.rejects(
    () => render('{% encrypt_nested "only-one" %}x{% endencrypt_nested %}'),
    /requires at least 2 password/
  );
});

test('tag errors include the post title when available', async () => {
  await assert.rejects(
    () => render('{% encrypt %}x{% endencrypt %}', { title: 'My Post' }),
    /in post "My Post"/
  );
  await assert.rejects(
    () => hexo.extend.tag.render('{% encrypt %}x{% endencrypt %}', { title: '' }),
    /requires at least 1 password/,
    'untitled posts must not produce an empty title suffix'
  );
});

// ---------------------------------------------------------------------------
// Internal helpers — asset path + render branches
// ---------------------------------------------------------------------------
test('getAssets normalizes root and joins the hashed bundle + css routes', () => {
  const routes = [
    { path: 'css/hbe.style.css' },
    { path: 'lib/hbe.0123456789.js' },
  ];
  const assetGenerator = () => routes;
  assert.deepEqual(
    _internal.getAssets({ config: { root: '/blog' } }, assetGenerator),
    { js: '/blog/lib/hbe.0123456789.js', css: '/blog/css/hbe.style.css' }
  );
  assert.deepEqual(
    _internal.getAssets({ config: { root: '/blog/' } }, assetGenerator),
    { js: '/blog/lib/hbe.0123456789.js', css: '/blog/css/hbe.style.css' }
  );
  assert.deepEqual(
    _internal.getAssets({ config: {} }, assetGenerator),
    { js: '/lib/hbe.0123456789.js', css: '/css/hbe.style.css' }
  );
});

test('getAssets throws when the generator did not emit the expected routes', () => {
  assert.throws(
    () => _internal.getAssets({ config: {} }, () => [{ path: 'only.css' }]),
    /bundle\/CSS routes are missing/
  );
});

test('renderWidget covers the default button and asset-less (inner layer) forms', () => {
  const renderer = {
    render(opts) {
      assert.equal(opts.format, '4');
      return `<widget theme="${opts.theme}" kdf="${opts.kdfAlgorithm}" iters="${opts.kdfIterations}" ` +
        `time="${opts.kdfTimeCost}" mem="${opts.kdfMemoryCost}" par="${opts.kdfParallelism}" ` +
        `button="${opts.buttonClass}">${opts.buttonText}</widget>`;
    },
  };
  const cfg = {
    message: 'msg',
    wrong_pass_message: 'wpm',
    wrong_hash_message: 'whm',
    decryptButton: undefined,
  };
  const result = {
    salt: crypto.randomBytes(32),
    nonce: crypto.randomBytes(12),
    ciphertext: crypto.randomBytes(24),
    kdf: { algorithm: 'pbkdf2', iterations: 250000 },
  };
  assert.equal(
    _internal.renderWidget({ renderer, cfg, result, assets: null }),
    '<widget theme="default" kdf="pbkdf2" iters="250000" time="" mem="" par="" button="">Decrypt</widget>'
  );
  assert.equal(
    _internal.renderWidget({ renderer, cfg, result, assets: { js: '/x.js', css: '/x.css' } }),
    '<widget theme="default" kdf="pbkdf2" iters="250000" time="" mem="" par="" button="">Decrypt</widget>' +
    '<script data-pjax src="/x.js"></script><link href="/x.css" rel="stylesheet" type="text/css">'
  );
});

test('processBlocks rejects an unmatched end marker', async () => {
  await assert.rejects(
    () => _internal.processBlocks('x<!--hexo-blog-encrypt:end:abc-->y', { post: { title: 'T' } }),
    /unmatched encrypt-tag end marker in post "T"/
  );
});

test('processBlocks rejects an unclosed start marker', async () => {
  const marker = _internal.makeMarker('encrypt', ['pw']);
  await assert.rejects(
    () => _internal.processBlocks('x' + marker.start + 'body', { post: { title: 'T' } }),
    /unclosed \{% encrypt %\} block in post "T"/
  );
});

test('processBlocks rejects a malformed marker payload', async () => {
  await assert.rejects(
    () => _internal.processBlocks(
      'x<!--hexo-blog-encrypt:start:abc:AAAA-->body<!--hexo-blog-encrypt:end:abc-->y',
      { post: { title: 'T' } }
    ),
    /malformed encrypt-tag marker payload/
  );
});

test('processBlocks rejects valid base64 that decodes to invalid marker options', async () => {
  const payload = Buffer.from(JSON.stringify({ tagName: 'encrypt', passwords: [] }), 'utf8')
    .toString('base64');
  await assert.rejects(
    () => _internal.processBlocks(
      'x<!--hexo-blog-encrypt:start:abc:' + payload + '-->body<!--hexo-blog-encrypt:end:abc-->y',
      { post: { title: 'T' } }
    ),
    /malformed encrypt-tag marker options/
  );
});

test('parsePasswords treats a non-array argument list as empty', () => {
  assert.throws(
    () => _internal.parsePasswords(undefined, 'encrypt', 1, {}),
    /requires at least 1 password argument/
  );
});

test('renderMarker handles a null body (empty block)', () => {
  const handlers = _internal.createTagHandlers();
  const html = handlers.encrypt.call({}, ['pw'], null);
  assert.match(html, /^<!--hexo-blog-encrypt:start:[0-9a-z]+:[A-Za-z0-9+/=]+-->/);
  assert.match(html, /<!--hexo-blog-encrypt:end:[0-9a-z]+-->$/);
});

test('processBlocks wraps body-render failures with the post title', async () => {
  const marker = _internal.makeMarker('encrypt', ['pw']);
  const deps = {
    post: { title: 'T', engine: 'markdown' },
    hexo: { config: {}, render: { render: async () => { throw new Error('render boom'); } } },
    renderer: { render: () => '' },
    assetGenerator: () => [{ path: 'css/hbe.style.css' }, { path: 'lib/hbe.0123456789.js' }],
    logger: { info() {}, warn() {} },
  };
  await assert.rejects(
    () => _internal.processBlocks(marker.start + SECRET + marker.end, deps),
    /failed to render \{% encrypt %\} block body in post "T": render boom/
  );
});

test('renderBody coerces a null renderer result to an empty string', async () => {
  const out = await _internal.renderBody('<p>x</p>', {
    post: { engine: 'markdown' },
    hexo: { render: { render: async () => null } },
  });
  assert.equal(out, '');
});
