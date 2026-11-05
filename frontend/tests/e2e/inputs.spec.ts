import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.use({ reducedMotion: 'reduce' });

test('uploads source and HTTP inputs, shows redacted evidence and rejects invalid content', async ({ page }) => {
  const config = readFileSync(fileURLToPath(new URL('../../../.env', import.meta.url)), 'utf8');
  const token = /^AEGISFORGE_API_TOKEN=(.+)$/m.exec(config)?.[1].trim();
  if (!token) throw new Error('Initialize the local .env before running browser tests.');
  await page.goto('/');
  await page.getByLabel('访问令牌').fill(token);
  await page.getByRole('button', { name: '连接服务' }).click();
  await expect(page.getByText('已连接本地服务')).toBeVisible();

  const panel = page.locator('.ingest-panel');
  const preview = panel.locator('.artifact-preview');
  const submit = panel.getByRole('button', { name: '保存并预览特征' });
  const editor = panel.getByLabel('或粘贴内容');
  await panel.getByLabel('选择文件（优先于粘贴内容）').setInputFiles({
    name: 'sample.py', mimeType: 'text/x-python',
    buffer: Buffer.from('import os\napi_key = "SYNTHETIC_PRIVATE_VALUE"\nos.system(request.args["cmd"])\n'),
  });
  await submit.click();
  await expect(preview.getByRole('heading', { name: '脱敏预览 · sample.py' })).toBeVisible();
  await expect(preview).toContainText('CWE-78');
  await expect(preview).toContainText('第 3 行');
  await expect(preview).not.toContainText('SYNTHETIC_PRIVATE_VALUE');
  await expect(preview).toContainText('[REDACTED]');
  await preview.getByText(/查看输入特征/).click();
  await expect(preview.getByText('输入来源', { exact: true })).toBeVisible();

  await panel.getByRole('button', { name: '载入开发示例' }).click();
  expect(await panel.locator('input[type=file]').evaluate((node: HTMLInputElement) => node.files?.length)).toBe(0);
  for (const [code, cwe] of [
    ['from flask import request\ndef index():\n    return "<img src=x onerror=window.m2Injected=1>" + request.args["q"]\n', 'CWE-79'],
    ['cursor.execute("SELECT * FROM users WHERE id=" + request.args["id"])\n', 'CWE-89'],
  ]) {
    await editor.fill(code);
    await submit.click();
    await expect(preview).toContainText(cwe);
  }
  expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).m2Injected)).toBeUndefined();

  const inputType = panel.getByRole('combobox', { name: '输入类型' });
  await inputType.click();
  await inputType.press('ArrowDown');
  await inputType.press('Enter');
  await editor.fill("POST /login HTTP/1.1\nHost: example.invalid\nCookie: session=SYNTHETIC_COOKIE\nContent-Type: application/x-www-form-urlencoded\n\npassword=%27+or+%271%27%3D%271");
  await submit.click();
  await expect(preview).toContainText('CWE-89');
  await expect(preview).toContainText('离线请求特征不能证明服务端存在漏洞');
  await expect(preview).not.toContainText('SYNTHETIC_COOKIE');
  await expect(preview).not.toContainText("'1'='1");
  await editor.fill('invalid HTTP text');
  await expect(preview).not.toBeVisible();
  await submit.click();
  await expect(panel.getByRole('alert')).toContainText('HTTP/1.x');

  await inputType.click();
  await inputType.press('ArrowUp');
  await inputType.press('Enter');
  await panel.getByRole('button', { name: '载入开发示例' }).click();
  await submit.click();
  await expect(preview).toContainText('CWE-78');
  await inputType.press('Escape');
  await expect(page.locator('.ant-select-dropdown')).not.toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: 'test-results/m2-input-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  // Measure the settled responsive layout after the viewport change.
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: 'test-results/m2-input-mobile.png', fullPage: true });
});
