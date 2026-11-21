'use strict';

// Block-level tags (fork addition):
//   {% encrypt %} — partial encryption; multiple arguments add layers,
//                   outermost password first
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

test.describe('tree-shaped nesting', () => {
  test('sibling branches decrypt independently, each with its own password', async ({ page }) => {
    await page.goto('/tree-nested/');

    await expect(page.locator('body')).toContainText('TOP PUBLIC');
    await expect(page.locator('body')).toContainText('BOTTOM PUBLIC');
    await expect(page.locator('body')).not.toContainText('ROOT PUBLIC');
    await expect(page.locator('.hbe-container')).toHaveCount(1);

    // Root layer reveals three sibling blocks.
    await submitPassword(page.locator('.hbe-container').first(), 'root');
    await expect(page.locator('body')).toContainText('ROOT PUBLIC');
    await expect(page.locator('.hbe-container')).toHaveCount(3);

    // Branch A is independent. Revealed containers drop out of the
    // `.hbe-container` list, so always target the first remaining one.
    await submitPassword(page.locator('.hbe-container').first(), 'a');
    await expect(page.locator('body')).toContainText('BRANCH A SECRET');
    await expect(page.locator('body')).not.toContainText('BRANCH C SECRET');
    await expect(page.locator('.hbe-container')).toHaveCount(2);

    // Branch B is still locked; it reveals public text plus a nested form.
    await expect(page.locator('body')).not.toContainText('BRANCH B1 SECRET');
    await submitPassword(page.locator('.hbe-container').first(), 'b');
    await expect(page.locator('body')).toContainText('BRANCH B PUBLIC');
    // B's nested form plus untouched branch C.
    await expect(page.locator('.hbe-container')).toHaveCount(2);

    await submitPassword(page.locator('.hbe-container').first(), 'b1');
    await expect(page.locator('body')).toContainText('BRANCH B1 SECRET');
    await expect(page.locator('.hbe-container')).toHaveCount(1);

    // Branch C still decrypts with its own password.
    await submitPassword(page.locator('.hbe-container').first(), 'c');
    await expect(page.locator('body')).toContainText('BRANCH C SECRET');
    await expect(page.locator('.hbe-container')).toHaveCount(0);
  });
});
