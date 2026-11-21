# Partial and Nested Encryption

[简体中文](Partial-and-Nested-Encryption-zh-CN)

This fork adds two block-level tags on top of upstream v4.1.0:

- `{% encrypt "password" %}` encrypts **only that block**. The rest of the post stays public.
- `{% encrypt_nested "outer" "inner" ... %}` encrypts the block once per password, outermost first.

Both tags are available in the fork only. Upstream `hexo-blog-encrypt` still encrypts whole posts, so a stock npm install does not understand them.

## How it works

A tag body is written in the post's normal Markdown:

```markdown
Public introduction.

{% encrypt "block-secret" %}
**Only this block is encrypted.**
{% endencrypt %}

Still public.

{% encrypt_nested "outer" "inner" %}
**Two passwords are required.**
{% endencrypt_nested %}
```

Hexo escapes tag bodies before the Markdown pass, so the plugin renders each body with the post's Markdown engine before encrypting it. Normal Markdown, fenced code blocks and HTML all work inside a block.

The synchronous tags only emit an HTML-comment marker. Encryption runs in an `after_post_render` filter at priority 900, before whole-post encryption. This keeps build errors catchable: a bad block fails `hexo generate` instead of becoming an unhandled promise rejection.

## Partial encryption

`{% encrypt %}` produces one `.hbe-container` and appends the runtime bundle `<script>`/`<link>` tags to that container. A post may contain several independent blocks; the browser runtime discovers all of them and keeps every lookup scoped to its own container.

Example with two independent blocks:

```markdown
{% encrypt "first-password" %}
First secret.
{% endencrypt %}

Public text between the blocks.

{% encrypt "second-password" %}
Second secret.
{% endencrypt %}
```

Each block gets its own fresh 32-byte salt and 12-byte nonce, even when `stableSalt: true` is configured. A stable salt is derived from the post permalink, and reusing it for every block would make identical blocks share a salt.

## Nested encryption

### Explicit layers: `encrypt_nested`

Pass one password per layer, outermost first:

```markdown
{% encrypt_nested "outer-password" "inner-password" %}
Only someone with both passwords can read this.
{% endencrypt_nested %}
```

The reader sees the outer password prompt first. After it decrypts, the inner container appears and asks for the inner password. Add more arguments for more layers.

Only the outermost container carries the runtime bundle. Inner layers are encrypted output, so a script inside them would be encrypted too. The browser's reveal-time `init(decrypted)` call discovers and initialises each inner container as it becomes visible.

### Post-level outer layer

You can also combine the existing whole-post password with a block tag:

```markdown
---
title: Post-level outer password plus a block-level inner password
password: outer-password
---

{% encrypt "inner-password" %}
Only someone with both passwords can read this.
{% endencrypt %}
```

The block is encrypted first, then the whole post (including the block container) is encrypted by the normal `password:` filter. This is the same two-layer result as `encrypt_nested`, but the outer layer's prompt is the standard post password form.

### Same-name limitation

Nunjucks cannot parse two nested block tags with the same name, so this does **not** work:

```markdown
{% encrypt "outer" %}
{% encrypt "inner" %}...{% endencrypt %}
{% endencrypt %}
```

Use `encrypt_nested` for explicit layers, or the post-level `password:` + `{% encrypt %}` combination above. Different tag names can be nested when needed.

## Rendering, assets and caching

- Multiple encrypted containers on one page are supported by the merged upstream v4.1.0 browser runtime.
- Each `{% encrypt %}` block appends its own copy of the bundle `<script>`; the runtime is idempotent and sets each container up exactly once. Browsers cache the script bytes.
- A `{% encrypt_nested %}` block appends the script only to the outermost container.
- `autoSave` uses the container's position on the page. Reordering blocks invalidates that block's saved key; the salt check then drops the stale entry and prompts again.
- Search indexes and feeds see the generated widget HTML (ciphertext), not the block plaintext. Public parts of a partial post are indexed normally.

## Security notes

- Block encryption is client-side, like whole-post encryption. Anyone who downloads the page can attack the ciphertext offline.
- Nested layers are sequential encryption, not a stronger primitive: an attacker must break the outer password and then the inner password. If both layers use the same password, there is no additional protection.
- A partial post intentionally publishes the text around the block. Do not put sensitive context outside the tag.
- See [Security Model](Security-Model) for the threat model, `autoSave` caveats and offline guessing guidance.

## See also

- [Configuration Reference](Configuration-Reference)
- [Tag-Based Encryption](Tag-Based-Encryption)
- [Security Model](Security-Model)
- [Browser Support](Browser-Support)
