'use strict';

// Block-level encryption tags.
//
//   {% encrypt "password" %} ... {% endencrypt %}
//     The block is encrypted on its own; the rest of the post stays public.
//
//   {% encrypt_nested "outer" "inner" ... %} ... {% endencrypt_nested %}
//     Every password adds one layer. The first argument is the outermost
//     password (the one the reader sees first); additional arguments encrypt
//     the already-encrypted result. This is the explicit nested form and does
//     not rely on Nunjucks being able to nest same-name block tags (it can't).
//
// The tags themselves are synchronous and only emit HTML-comment markers.
// Encryption happens in a lower-priority `after_post_render` filter:
//
//   - Hexo's async block tags do not propagate a rejected promise (the
//     NunjucksAsyncBlock.run wrapper has no rejection handler), so a failed
//     async tag becomes an unhandled rejection instead of a build error.
//   - A filter's rejection *is* awaited by Hexo's render pipeline, so a
//     misconfigured block fails the build with a normal error.
//
// Markers are processed innermost-first, so an `{% encrypt %}` inside an
// `{% encrypt_nested %}` block is encrypted into the outer layer correctly.

const { resolve } = require('./config');
const { encrypt, encryptArgon2id } = require('./crypto');

const FORMAT_VERSION = '4';
const START_PREFIX = '<!--hexo-blog-encrypt:start:';
const END_PREFIX = '<!--hexo-blog-encrypt:end:';
const START_RE = /<!--hexo-blog-encrypt:start:([0-9a-z]+):([A-Za-z0-9+/=]*)-->/g;

let markerSeq = 0;

function normalizeRoot(root) {
  if (typeof root !== 'string') return '/';
  return root.endsWith('/') ? root : root + '/';
}

function titleOf(post) {
  return (post && typeof post.title === 'string' && post.title.trim())
    ? ` in post "${post.title.trim()}"`
    : '';
}

function parsePasswords(args, tagName, minLayers, post) {
  const passwords = Array.isArray(args) ? args.map((v) => String(v)) : [];
  if (passwords.length < minLayers) {
    throw new Error(
      `hexo-blog-encrypt: {% ${tagName} %} requires at least ${minLayers} password ` +
      `argument${minLayers === 1 ? '' : 's'}${titleOf(post)}.`
    );
  }
  for (const password of passwords) {
    if (password === '') {
      throw new Error(
        `hexo-blog-encrypt: {% ${tagName} %} has an empty password${titleOf(post)}.`
      );
    }
  }
  return passwords;
}

function makeMarker(tagName, passwords) {
  const id = (++markerSeq).toString(36);
  const payload = Buffer.from(JSON.stringify({ tagName, passwords }), 'utf8').toString('base64');
  return {
    start: START_PREFIX + id + ':' + payload + '-->',
    end: END_PREFIX + id + '-->',
  };
}

function createTagHandlers() {
  function tag(tagName, minLayers) {
    return function renderMarker(args, body) {
      const passwords = parsePasswords(args, tagName, minLayers, this);
      const marker = makeMarker(tagName, passwords);
      return marker.start + String(body == null ? '' : body) + marker.end;
    };
  }
  return {
    encrypt: tag('encrypt', 1),
    encryptNested: tag('encrypt_nested', 2),
  };
}

function getAssets(hexo, assetGenerator) {
  const routes = assetGenerator();
  const jsRoute = routes.find((r) => /^lib\/hbe\.[0-9a-f]{10}\.js$/.test(r.path));
  const cssRoute = routes.find((r) => r.path === 'css/hbe.style.css');
  if (!jsRoute || !cssRoute) {
    throw new Error('hexo-blog-encrypt: bundle/CSS routes are missing; cannot render an encrypt tag');
  }
  const root = normalizeRoot(hexo.config && hexo.config.root);
  return {
    js: root + jsRoute.path,
    css: root + cssRoute.path,
  };
}

async function encryptWithConfig(plaintext, password, cfg) {
  if (cfg.kdf.algorithm === 'argon2id') {
    return encryptArgon2id(plaintext, password, {
      timeCost: cfg.kdf.timeCost,
      memoryCost: cfg.kdf.memoryCost,
      parallelism: cfg.kdf.parallelism,
    });
  }
  const result = await encrypt(plaintext, password, {
    iterations: cfg.kdf.iterations,
  });
  return Object.assign({}, result, {
    kdf: { algorithm: 'pbkdf2', iterations: cfg.kdf.iterations },
  });
}

function renderWidget(opts) {
  const { renderer, cfg, result, assets } = opts;
  const buttonShow = !cfg.decryptButton || cfg.decryptButton.show !== false;
  const buttonText = (cfg.decryptButton && typeof cfg.decryptButton.text === 'string')
    ? cfg.decryptButton.text
    : 'Decrypt';
  const themeName = String(cfg.theme || 'default').trim().toLowerCase();

  const rendered = renderer.render({
    theme: themeName,
    format: FORMAT_VERSION,
    ciphertext: result.ciphertext.toString('hex'),
    salt: result.salt.toString('hex'),
    nonce: result.nonce.toString('hex'),
    message: cfg.message,
    wpm: cfg.wrong_pass_message,
    whm: cfg.wrong_hash_message,
    buttonClass: buttonShow ? '' : ' hbe-button-hidden',
    buttonText,
    kdfAlgorithm: result.kdf.algorithm,
    kdfIterations: result.kdf.iterations || '',
    kdfTimeCost: result.kdf.timeCost || '',
    kdfMemoryCost: result.kdf.memoryCost || '',
    kdfParallelism: result.kdf.parallelism || '',
    autoSave: !!cfg.autoSave,
  });

  if (!assets) return rendered;
  return rendered +
    `<script data-pjax src="${assets.js}"></script>` +
    `<link href="${assets.css}" rel="stylesheet" type="text/css">`;
}

function decodeMarker(match) {
  let payload;
  try {
    payload = JSON.parse(Buffer.from(match[2], 'base64').toString('utf8'));
  } catch (e) {
    throw new Error('hexo-blog-encrypt: malformed encrypt-tag marker payload', { cause: e });
  }
  if (
    !payload
    || typeof payload.tagName !== 'string'
    || !Array.isArray(payload.passwords)
    || payload.passwords.length === 0
    || payload.passwords.some((p) => typeof p !== 'string' || p === '')
  ) {
    throw new Error('hexo-blog-encrypt: malformed encrypt-tag marker options');
  }
  return payload;
}

function findLastStart(html) {
  START_RE.lastIndex = 0;
  let last = null;
  let match;
  while ((match = START_RE.exec(html)) !== null) {
    last = {
      index: match.index,
      token: match[0],
      id: match[1],
      options: decodeMarker(match),
    };
  }
  return last;
}

async function renderBody(body, deps) {
  const { hexo, post } = deps;
  const engine = (post && post.engine) || 'markdown';
  try {
    const rendered = await hexo.render.render({
      text: body,
      engine,
      toString: true,
    });
    return String(rendered == null ? '' : rendered);
  } catch (e) {
    throw new Error(
      `hexo-blog-encrypt: failed to render {% encrypt %} block body${titleOf(post)}: ${e.message}`,
      { cause: e }
    );
  }
}

async function renderLayers(post, options, body, deps) {
  const { hexo, renderer, assetGenerator, logger } = deps;
  const { tagName, passwords } = options;

  // Only the outermost container gets the runtime <script>/<link>. Inner
  // layers are encrypted output, so a script inside them would itself be
  // encrypted; the browser initialises them via the reveal-time init call.
  const assets = getAssets(hexo, assetGenerator);
  // Tag bodies are escaped from the Markdown pass by Hexo (tags are restored
  // only after Markdown rendering), so render the block body ourselves.
  let html = await renderBody(body, deps);

  for (let i = passwords.length - 1; i >= 0; i--) {
    const password = passwords[i];
    const cfg = resolve(hexo.config, Object.assign({}, post, {
      password,
      // A stable salt is derived from the post permalink; using it for
      // every block in a post would make identical blocks share a salt.
      // Blocks always get a fresh random salt.
      stableSalt: false,
    }), logger);
    /* c8 ignore next 5 — passwords are validated non-empty before this loop */
    if (cfg === null) {
      throw new Error(
        `hexo-blog-encrypt: {% ${tagName} %} could not resolve a password${titleOf(post)}.`
      );
    }
    const result = await encryptWithConfig(html, cfg.password, cfg);
    html = renderWidget({
      renderer,
      cfg,
      result,
      assets: i === 0 ? assets : null,
    });
  }

  logger.info(
    `hexo-blog-encrypt: encrypted ${passwords.length} block layer${passwords.length === 1 ? '' : 's'} ` +
    `via {% ${tagName} %}${titleOf(post)}.`
  );
  return html;
}

async function processBlocks(html, deps) {
  let out = String(html);
  let guard = 0;

  for (;;) {
    const start = findLastStart(out);
    if (start === null) {
      const endAt = out.indexOf(END_PREFIX);
      if (endAt !== -1) {
        throw new Error(
          `hexo-blog-encrypt: unmatched encrypt-tag end marker${titleOf(deps.post)}.`
        );
      }
      return out;
    }

    const endToken = END_PREFIX + start.id + '-->';
    const endAt = out.indexOf(endToken, start.index + start.token.length);
    if (endAt === -1) {
      throw new Error(
        `hexo-blog-encrypt: unclosed {% ${start.options.tagName} %} block${titleOf(deps.post)}.`
      );
    }
    const body = out.slice(start.index + start.token.length, endAt);
    const replacement = await renderLayers(deps.post, start.options, body, deps);
    out = out.slice(0, start.index) + replacement + out.slice(endAt + endToken.length);

    /* c8 ignore next 3 — defensive: marker count is bounded by post size */
    if (++guard > 10000) {
      throw new Error('hexo-blog-encrypt: too many nested encrypt-tag blocks');
    }
  }
}

function registerTags(hexo) {
  const handlers = createTagHandlers();
  hexo.extend.tag.register('encrypt', handlers.encrypt, { ends: true });
  hexo.extend.tag.register('encrypt_nested', handlers.encryptNested, { ends: true });
}

function registerBlockFilter(hexo, deps) {
  hexo.extend.filter.register('after_post_render', async function encryptBlockFilter(data) {
    if (typeof data.content !== 'string' || !data.content.includes(START_PREFIX)) {
      return data;
    }
    data.content = await processBlocks(data.content, Object.assign({ post: data, hexo }, deps));
    return data;
  }, 900);
}

module.exports = {
  registerTags,
  registerBlockFilter,
  _internal: {
    createTagHandlers,
    parsePasswords,
    makeMarker,
    renderBody,
    getAssets,
    encryptWithConfig,
    renderWidget,
    processBlocks,
  },
};
