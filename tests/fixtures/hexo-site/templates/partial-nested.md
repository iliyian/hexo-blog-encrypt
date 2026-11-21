---
title: partial-nested-fixture
date: 2026-01-01 00:00:00
---

PUBLIC BEFORE

{% encrypt "blockpw" %}
**BLOCK SECRET**
{% endencrypt %}

PUBLIC MIDDLE

{% encrypt_nested "outer" "inner" %}
**NESTED SECRET**
{% endencrypt_nested %}

PUBLIC AFTER
