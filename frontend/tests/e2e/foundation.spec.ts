import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test('connects the real local frontend and backend without claiming analysis', async ({ page }) => {
  const config = readFileSync(fileURLToPath(new URL('../../../.env', import.meta.url)), 'utf8');
  const token = /^AEGISFORGE_API_TOKEN=(.+)$/m.exec(config)?.[1].trim();
  if (!token) throw new Error('Initialize the local .env before running the smoke test.');
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '代码安全工作台' })).toBeVisible();
  await expect(page.getByText('本地服务在线')).toBeVisible();
  await page.getByLabel('访问令牌').fill('incorrect-token');
  await page.getByRole('button', { name: '连接服务' }).click();
  await expect(page.getByText('访问令牌无效或缺失。')).toBeVisible();
  await page.getByLabel('访问令牌').fill(token);
  await page.getByRole('button', { name: '连接服务' }).click();
  await expect(page.getByText('已连接本地服务')).toBeVisible();
  await expect(page.getByLabel('访问令牌')).toHaveValue('');
  await expect(page.getByText('模拟模式 · 真实模型尚未接入')).toBeVisible();
  await page.screenshot({ path: 'test-results/foundation-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('heading', { name: '代码安全工作台' })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/foundation-mobile.png', fullPage: true });
});
