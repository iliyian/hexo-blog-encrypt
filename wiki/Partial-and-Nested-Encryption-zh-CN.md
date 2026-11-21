# 部分加密与嵌套加密

[English](Partial-and-Nested-Encryption)

本 fork 在上游 v4.1.0 的基础上增加了一个块级标签:

- `{% encrypt "密码" ... %}` 只加密**这个块**, 文章其余部分保持公开. 多个密码参数会逐层加密, 第一个参数是最外层; 每层还需要自己的公开文字时, 也可以同名嵌套.

这个标签只存在于本 fork. 上游 `hexo-blog-encrypt` 仍然只支持整篇加密, 直接安装 npm 版本不会识别它.

## 工作原理

标签内容按文章原本的 Markdown 书写:

```markdown
公开的开头.

{% encrypt "block-secret" %}
**只有这个块会被加密.**
{% endencrypt %}

仍然是公开的.

{% encrypt "outer" "inner" %}
**需要两层密码.**
{% endencrypt %}
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

### 一个标签内多个密码

每层一个密码, 最外层在前:

```markdown
{% encrypt "outer-password" "inner-password" %}
只有同时知道两个密码的人才能读到这段.
{% endencrypt %}
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

插件先加密块, 再由正常的 `password:` 过滤器加密整篇文章 (包括块容器). 效果和多参数形式的两层嵌套相同, 只是外层提示使用的是标准文章密码表单.

### `{% encrypt %}` 嵌套 `{% encrypt %}`

同名 nesting 可以工作, 层数不限:

```markdown
{% encrypt "a" %}
输入第一个密码后可见.

{% encrypt "b" %}
输入第二个密码后可见.

{% encrypt "c" %}
最终秘密.
{% endencrypt %}
{% endencrypt %}
{% endencrypt %}
```

外层块内容交给 Markdown 引擎之前, 内层控件会先换成 HTML 注释占位符, 渲染后再还原. 否则 Markdown 会把 `<script id="hbeData">` 里缩进的密文变成 `<br>`, 导致解密失败.

多参数形式和同名嵌套也可以互相组合. 同一段内容用一串密码锁住时, 多参数更简短; 每层还需要展示公开文字时, 同名嵌套更自然.

## 渲染、资源与缓存

- 合并后的上游 v4.1.0 浏览器运行时支持一页多个加密容器.
- 每个 `{% encrypt %}` 块都会追加一份 bundle `<script>`; 运行时是幂等的, 每个容器只会初始化一次, 浏览器也会缓存脚本内容.
- 带多个密码参数的块只把脚本追加到最外层容器.
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

## 树状结构

嵌套不要求是一条链: 一个块里可以放多个并列的子块, 子块里还能继续嵌套:

```markdown
{% encrypt "root" %}
输入 root 后可见.

{% encrypt "a" %}
分支 A.
{% endencrypt %}

{% encrypt "b" %}
分支 B 在输入 root 后可见.

{% encrypt "b1" %}
B 的下级秘密.
{% endencrypt %}
{% endencrypt %}

{% encrypt "c" %}
分支 C.
{% endencrypt %}
{% endencrypt %}
```

输入 root 后会出现三个独立密码框. `a` 和 `c` 各自独立解密; `b` 解密后显示公开文字和第四个密码框 (`b1`). 某个分支输错密码不影响其他分支, 每个分支仍使用独立的 salt/nonce.
