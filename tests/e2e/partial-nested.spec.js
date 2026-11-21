'use strict';

// Block-level tags (fork addition):
//   {% encrypt %}         — partial encryption, one password per block
//   {% encrypt_nested %}  — one password per layer, outermost first
//
// These tests exercise the real Hexo build of tests/fixtures/hexo-site. The
// fixtures are materialized by tests/helpers/buildSite.js from
// templates/partial-nested.md and templates/post-nested.md.

const { test, expect } = require('./fixtures');

function passwordInput(container) {
  return container.locator('input[type="password"]');
}

async function submitPassword(container, password) {
  const input = passwordInput(container);
  await input.fill(password);
  await input.press('Enter');
}

test.describe('partial and nested encryption', () => {
  test('partial blocks decrypt independently while public text stays visible', async ({ page }) => {
    await page.goto('/partial-nested/');

    await expect(page.locator('body')).toContainText('PUBLIC BEFORE');
    await expect(page.locator('body')).toContainText('PUBLIC MIDDLE');
    await expect(page.locator('body')).toContainText('PUBLIC AFTER');
    await expect(page.locator('body')).not.toContainText('BLOCK SECRET');
    await expect(page.locator('body')).not.toContainText('NESTED SECRET');

    // First independent block.
    await submitPassword(page.locator('.hbe-container').first(), 'blockpw');
    await expect(page.locator('body')).toContainText('BLOCK SECRET');
    await expect(page.locator('body')).not.toContainText('NESTED SECRET');
    await expect(page.locator('body')).toContainText('PUBLIC MIDDLE');

    // Explicit nested block: outer password first, then inner password.
    await submitPassword(page.locator('.hbe-container').first(), 'outer');
    await expect(page.locator('body')).not.toContainText('NESTED SECRET');
    await expect(page.locator('.hbe-container')).toHaveCount(1);

    await submitPassword(page.locator('.hbe-container').first(), 'inner');
    await expect(page.locator('body')).toContainText('NESTED SECRET');
    await expect(page.locator('body')).toContainText('BLOCK SECRET');
  });

  test('post-level password can wrap a block-level password', async ({ page }) => {
    await page.goto('/post-nested/');

    await expect(page.locator('body')).not.toContainText('POST INNER SECRET');

    // Outer layer: the normal whole-post password form.
    await submitPassword(page.locator('.hbe-container').first(), 'postpw');

    // Inner block appears after the outer decrypt.
    await expect(page.locator('.hbe-container')).toHaveCount(1);
    await submitPassword(page.locator('.hbe-container').first(), 'innerpw');
    await expect(page.locator('body')).toContainText('POST INNER SECRET');
  });

  test('a wrong block password fails closed and the right one still works', async ({ page }) => {
    await page.goto('/partial-nested/');

    const first = page.locator('.hbe-container').first();
    await submitPassword(first, 'not-the-password');
    await expect(page.locator('body')).not.toContainText('BLOCK SECRET');
    await expect(first.locator('[role="alert"]')).not.toBeEmpty();

    await submitPassword(page.locator('.hbe-container').first(), 'blockpw');
    await expect(page.locator('body')).toContainText('BLOCK SECRET');
  });
});
