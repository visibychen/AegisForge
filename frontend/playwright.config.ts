import { defineConfig } from '@playwright/test';

const selectedBrowser = process.env.PLAYWRIGHT_BROWSER ?? 'chromium';
if (selectedBrowser !== 'chromium' && selectedBrowser !== 'firefox') throw new Error('Unsupported test browser');

export default defineConfig({
  testDir: './tests/e2e',
  use: {
    baseURL: 'http://127.0.0.1:5173',
    browserName: selectedBrowser,
    channel: process.env.PLAYWRIGHT_CHANNEL,
    viewport: { width: 1440, height: 1000 },
  },
  reporter: 'list',
  timeout: 30000,
});
