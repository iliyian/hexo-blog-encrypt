---
title: tree-nested-fixture
date: 2026-01-01 00:00:02
---

TOP PUBLIC

{% encrypt "root" %}
ROOT PUBLIC

{% encrypt "a" %}
BRANCH A SECRET
{% endencrypt %}

{% encrypt "b" %}
BRANCH B PUBLIC
{% encrypt "b1" %}
BRANCH B1 SECRET
{% endencrypt %}
{% endencrypt %}

{% encrypt "c" %}
BRANCH C SECRET
{% endencrypt %}
{% endencrypt %}

BOTTOM PUBLIC
