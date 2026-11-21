# 部分加密与嵌套加密

[English](Partial-and-Nested-Encryption)

本 fork 在上游 v4.1.0 的基础上增加了两个块级标签:

- `{% encrypt "密码" %}` 只加密**这个块**, 文章其余部分保持公开.
- `{% encrypt_nested "外层" "内层" ... %}` 按密码数量逐层加密, 第一个参数是最外层.

这两个标签只存在于本 fork. 上游 `hexo-blog-encrypt` 仍然只支持整篇加密, 直接安装 npm 版本不会识别它们.

## 工作原理

标签内容按文章原本的 Markdown 书写:

```markdown
公开的开头.

{% encrypt "block-secret" %}
**只有这个块会被加密.**
{% endencrypt %}

仍然是公开的.

{% encrypt_nested "outer" "inner" %}
**需要两层密码.**
{% endencrypt_nested %}
```

Hexo 会在 Markdown 渲染前转义标签内容, 所以插件会先用文章对应的 Markdown 引擎渲染块内容, 再执行加密. 普通 Markdown、围栏代码块和 HTML 都可以写在块内.

同步标签只输出一个 HTML 注释标记; 真正的加密在 `after_post_render` 过滤器 (优先级 900) 中完成, 早于整篇加密. 这样错误可以被构建流程捕获: 配置有误的块会让 `hexo generate` 失败, 而不是变成未处理的 Promise rejection.

## 部分加密

`{% encrypt %}` 生成一个 `.hbe-container`, 并在这个容器后追加运行时 bundle 的 `<script>`/`<link>`. 一篇文章可以包含多个互相独立的块; 浏览器运行时会发现所有容器, 并把每个查询限制在各自的容器内.

两个独立块的例子:

```markdown
{% encrypt "first-password" %}
第一个秘密.
{% endencrypt %}

两个块之间的公开文字.

{% encrypt "second-password" %}
第二个秘密.
{% endencrypt %}
```

每个块都会生成独立的 32 字节 salt 和 12 字节 nonce, 即使配置了 `stableSalt: true` 也一样. stable salt 按文章永久链接派生, 如果每个块都复用会让相同内容的块共享 salt.

## 嵌套加密

### 显式分层: `encrypt_nested`

每层一个密码, 最外层在前:

```markdown
{% encrypt_nested "outer-password" "inner-password" %}
只有同时知道两个密码的人才能读到这段.
{% endencrypt_nested %}
```

读者先看到外层密码框. 外层解密后, 内层容器出现并索要内层密码. 继续增加参数即可增加层数.

只有最外层容器携带运行时 bundle. 内层是加密后的输出, 如果里面再放 script 也会被一并加密. 浏览器在每次解密后调用 `init(decrypted)`, 逐层发现并初始化新出现的容器.

### 文章级外层

也可以把现有的整篇密码和块级标签组合起来:

```markdown
---
title: 文章级外层密码 + 块级内层密码
password: outer-password
---

{% encrypt "inner-password" %}
只有同时知道两个密码的人才能读到这段.
{% endencrypt %}
```

插件先加密块, 再由正常的 `password:` 过滤器加密整篇文章 (包括块容器). 效果和 `encrypt_nested` 的两层嵌套相同, 只是外层提示使用的是标准文章密码表单.

### 同名标签限制

Nunjucks 无法解析两个同名的嵌套成对标签, 所以下面这样**不行**:

```markdown
{% encrypt "outer" %}
{% encrypt "inner" %}...{% endencrypt %}
{% endencrypt %}
```

需要显式多层时请用 `encrypt_nested`, 或者用文章级 `password:` + `{% encrypt %}` 的组合. 不同名的标签可以嵌套.

## 渲染、资源与缓存

- 合并后的上游 v4.1.0 浏览器运行时支持一页多个加密容器.
- 每个 `{% encrypt %}` 块都会追加一份 bundle `<script>`; 运行时是幂等的, 每个容器只会初始化一次, 浏览器也会缓存脚本内容.
- `{% encrypt_nested %}` 只把脚本追加到最外层容器.
- `autoSave` 按容器在页面中的位置保存密钥. 调整块顺序会让对应密钥失效; salt 校验会丢弃过期条目并重新提示.
- 搜索索引和 feed 看到的是生成的控件 HTML (密文), 不会包含块内明文. 部分加密文章中公开的部分会正常被索引.

## 安全说明

- 块级加密和整篇加密一样是客户端加密. 任何下载到页面的人都可以离线爆破密文.
- 嵌套是顺序加密, 不是更强的密码学原语: 攻击者必须先破解外层密码, 再破解内层密码. 如果两层使用相同密码, 不会增加额外保护.
- 部分加密会有意公开块周围的文字. 不要把敏感上下文放在标签外.
- 威胁模型、`autoSave` 注意事项和离线爆破建议见 [安全模型](Security-Model-zh-CN).

## 另见

- [配置参考](Configuration-Reference-zh-CN)
- [基于标签的加密](Tag-Based-Encryption-zh-CN)
- [安全模型](Security-Model-zh-CN)
- [浏览器支持](Browser-Support-zh-CN)
