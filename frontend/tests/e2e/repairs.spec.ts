import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';

test.use({ reducedMotion: 'reduce' });

async function prepare(page: Page, real: boolean) {
  const config = readFileSync(fileURLToPath(new URL('../../../.env', import.meta.url)), 'utf8');
  const token = /^AEGISFORGE_API_TOKEN=(.+)$/m.exec(config)?.[1].trim();
  if (!token) throw new Error('Initialize the local API token first.');
  await page.goto('/');
  await page.getByLabel('访问令牌').fill(token);
  await page.getByRole('button', { name: '连接服务' }).click();
  await expect(page.getByText('已连接本地服务')).toBeVisible();
  await page.getByRole('button', { name: '受控 XSS 示例', exact: true }).click();
  await page.getByRole('button', { name: '保存并预览特征' }).click();
  await expect(page.locator('.artifact-preview')).toContainText('CWE-79');
  await page.getByRole('combobox', { name: '模型', exact: true }).click();
  await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)')
    .getByText(real ? 'DeepSeek' : '模拟模型', { exact: true }).click();
  await page.getByRole('button', { name: '创建检测任务' }).click();
  const detail = page.getByRole('article', { name: '任务详情' });
  await expect(detail).toContainText('CWE-79', { timeout: 120000 });
  await detail.getByRole('button', { name: real ? '生成DeepSeek候选修复' : '生成模拟候选修复' }).first().click();
  return token;
}

test('keeps fake repair unverified, downloads, validates and restores the candidate', async ({ page }) => {
  test.setTimeout(90000);
  const token = await prepare(page, false);
  const panel = page.locator('.repair-panel');
  await expect(panel).toContainText('候选已生成');
  await expect(panel).toContainText('模拟流程只演示处理链路');
  const downloading = page.waitForEvent('download');
  await panel.getByRole('button', { name: '下载候选源码' }).click();
  expect(readFileSync((await (await downloading).path())!, 'utf8')).toContain('def greet');
  await panel.getByRole('button', { name: '申请受控动态验证' }).click();
  await expect(panel).toContainText('存在失败的固定测试', { timeout: 40000 });
  await expect(panel).toContainText('security_browser_no_script：失败');
  await expect(panel).not.toContainText('受控验证全部通过');
  expect(page.url()).toMatch(/repair=[0-9a-f-]{36}/);
  await page.reload();
  await page.getByLabel('访问令牌').fill(token);
  await page.getByRole('button', { name: '连接服务' }).click();
  await expect(panel).toContainText('候选已生成');
  await expect(panel).toContainText('security_browser_no_script：失败');
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('real DeepSeek repair passes through the separate deployed Docker controller', async ({ page }) => {
  test.skip(process.env.AEGISFORGE_E2E_REAL !== '1', 'Explicit opt-in required: consumes model calls.');
  test.setTimeout(240000);
  await prepare(page, true);
  const panel = page.locator('.repair-panel');
  await expect(panel).toContainText('候选已生成', { timeout: 180000 });
  await panel.getByRole('button', { name: '申请受控动态验证' }).click();
  await expect(panel).toContainText('受控验证全部通过', { timeout: 40000 });
  await panel.getByText('修复执行契约', { exact: true }).click();
  await expect(panel).toContainText('repair-contract-1.0');
  await page.screenshot({ path: 'test-results/m4-real-repair-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/m4-real-repair-mobile.png', fullPage: true });
});
