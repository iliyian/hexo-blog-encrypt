---
title: partial-nested-fixture
date: 2026-01-01 00:00:00
---

PUBLIC BEFORE

{% encrypt "blockpw" %}
**BLOCK SECRET**
{% endencrypt %}

PUBLIC MIDDLE

{% encrypt "outer" "inner" %}
**NESTED SECRET**
{% endencrypt %}

PUBLIC AFTER
