import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

test.use({ reducedMotion: 'reduce' });

// Default fake model only: no model budget is consumed and nothing here talks to DeepSeek.
test('navigates evidence, compares a simulated candidate, exports a source-free report and removes the task', async ({ page }) => {
  test.setTimeout(120000);
  const config = readFileSync(fileURLToPath(new URL('../../../.env', import.meta.url)), 'utf8');
  const token = /^AEGISFORGE_API_TOKEN=(.+)$/m.exec(config)?.[1].trim();
  if (!token) throw new Error('Initialize local .env before browser tests.');
  const auth = { Authorization: `Bearer ${token}` };

  await page.goto('/');
  await page.getByLabel('访问令牌').fill(token);
  await page.getByRole('button', { name: '连接服务' }).click();
  await expect(page.getByText('已连接本地服务')).toBeVisible();
  await page.getByRole('button', { name: '受控 XSS 示例', exact: true }).click();
  await page.getByRole('button', { name: '保存并预览特征' }).click();
  await expect(page.locator('.artifact-preview')).toContainText('CWE-79');
  await page.getByRole('combobox', { name: '模型', exact: true }).click();
  await page.locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden)').getByText('模拟模型', { exact: true }).click();
  await page.getByRole('button', { name: '创建检测任务' }).click();

  const detail = page.getByRole('article', { name: '任务详情' });
  await expect(detail).toContainText('CWE-79', { timeout: 60000 });
  const scanId = /scan=([0-9a-f-]{36})/.exec(page.url())?.[1] ?? '';
  expect(scanId).toHaveLength(36);
  const short = scanId.slice(0, 8);

  // The overview and the history list refresh by themselves once the task exists.
  const history = page.getByRole('region', { name: '历史管理' });
  await expect(history.getByRole('button', { name: `查看任务 ${short}` })).toBeVisible();
  await expect(history.getByText('模拟模型（未做真实分析）').first()).toBeVisible();

  // Evidence navigator: plain-text source, line numbers, text tags, keyboard access.
  await detail.getByRole('button', { name: '查看证据位置' }).first().click();
  const source = page.getByRole('group', { name: /^源码与发现位置：/ });
  await expect(source).toBeVisible();
  await expect(source.locator('.mark-selected').first()).toBeVisible();
  await expect(source.getByText('当前所选发现 · CWE-79').first()).toBeVisible();
  await source.focus();
  await page.keyboard.press('ArrowDown');
  await expect(source.locator('.source-line.cursor')).toHaveCount(1);
  expect(await source.locator('script').count()).toBe(0);

  // Repair history and the compare view. A simulated candidate is identical to the original.
  await detail.getByRole('button', { name: '生成模拟候选修复' }).first().click();
  const panel = page.locator('.repair-panel');
  await expect(panel).toContainText('候选已生成');
  const repairId = /repair=([0-9a-f-]{36})/.exec(page.url())?.[1] ?? '';
  expect(repairId).toHaveLength(36);
  await expect(page.getByRole('region', { name: '本任务的修复记录' })).toBeVisible();
  await expect(panel.getByLabel('修复说明卡')).toContainText('不证明候选没有其他漏洞');
  await panel.getByRole('button', { name: '对比原文与候选' }).click();
  await expect(panel.getByRole('group', { name: '原文源码' })).toBeVisible();
  await expect(panel.getByRole('group', { name: '候选源码' })).toBeVisible();
  await expect(panel).toContainText('模拟候选与原文相同');
  await expect(panel).not.toContainText('受控验证全部通过');

  // Reports: readable Markdown table, no source, no file name, no fenced dump.
  const exporting = page.waitForEvent('download');
  await history.getByRole('button', { name: `导出 Markdown ${short}` }).click();
  const report = await exporting;
  expect(report.suggestedFilename()).toBe(`aegisforge-report-${short}.md`);
  const markdown = readFileSync((await report.path())!, 'utf8');
  expect(markdown).toContain('| CWE | 等级 |');
  expect(markdown).toContain('## 修复说明卡');
  expect(markdown).not.toContain('```');
  expect(markdown).not.toContain('def greet');
  expect(markdown).not.toContain(token);

  const jsonDownload = page.waitForEvent('download');
  await history.getByRole('button', { name: `导出 JSON ${short}` }).click();
  const jsonReport = readFileSync((await (await jsonDownload).path())!, 'utf8');
  const payload = JSON.parse(jsonReport);
  expect(payload.schema_version).toBe('report-2.1');
  expect(payload.content_digest).toMatch(/^[0-9a-f]{64}$/);
  expect(payload.source_free).toBe(true);
  expect(jsonReport).not.toContain(token);
  writeFileSync(fileURLToPath(new URL('../../../data/m5-e2e-report.json', import.meta.url)), jsonReport);
  await page.screenshot({ path: 'test-results/m5-workbench-desktop.png', fullPage: true });

  // Mobile layout keeps the page itself from scrolling sideways.
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/m5-workbench-mobile.png', fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });

  await detail.getByRole('button', { name: '按当前配置重试' }).click();
  await expect(detail).toContainText('此前尝试（1）');
  await expect(panel).toContainText('旧尝试候选');
  await expect(panel.getByRole('button', { name: '申请受控动态验证' })).toBeDisabled();
  await expect(detail.locator('h3').getByText('部分完成', { exact:true })).toBeVisible();

  // Removal needs an explicit confirmation and then closes every entry for the task and repair.
  await history.getByRole('button', { name: `移出历史 ${short}` }).click();
  await expect(history).toContainText('预算审计和输入快照仍保留');
  await history.getByRole('button', { name: '保留' }).click();
  await expect(detail).toBeVisible();
  await history.getByRole('button', { name: `移出历史 ${short}` }).click();
  await history.getByRole('button', { name: '确认移出' }).click();
  await expect(history.getByRole('button', { name: `查看任务 ${short}` })).toHaveCount(0);
  await expect(detail).toHaveCount(0);
  await expect(panel).toHaveCount(0);
  expect(page.url()).not.toMatch(/scan=|repair=/);
  const gone = [
    `/api/v1/scans/${scanId}`, `/api/v1/scans/${scanId}/findings`, `/api/v1/workspace/${scanId}/report`,
    `/api/v1/repairs?scan_id=${scanId}`, `/api/v1/repairs/${repairId}`, `/api/v1/repairs/${repairId}/compare`,
    `/api/v1/repairs/${repairId}/download?format=source`,
  ];
  for (const path of gone) expect((await page.request.get(path, { headers: auth })).status(), path).toBe(404);
  expect((await page.request.post(`/api/v1/repairs/${repairId}/validate`, { headers: auth })).status()).toBe(404);
});
