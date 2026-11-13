import { defineConfig } from '@playwright/test';

const selectedBrowser = process.env.PLAYWRIGHT_BROWSER ?? 'chromium';
if (selectedBrowser !== 'chromium' && selectedBrowser !== 'firefox') throw new Error('Unsupported test browser');

// A machine-readable report is only written when the launcher asks for it, and only to an ignored
// path; the launcher publishes counts, never this raw file (it may carry error text).
const jsonReport = process.env.PLAYWRIGHT_JSON_REPORT;

export default defineConfig({
  testDir: './tests/e2e',
  // Playwright empties its output directory at the start of every run. Each browser gets its own, so
  // a second run (for example Firefox after Chromium) can never delete the first run's artifacts.
  outputDir: `test-results/${selectedBrowser}`,
  use: {
    baseURL: 'http://127.0.0.1:5173',
    browserName: selectedBrowser,
    channel: process.env.PLAYWRIGHT_CHANNEL,
    viewport: { width: 1440, height: 1000 },
  },
  reporter: jsonReport ? [['list'], ['json', { outputFile: jsonReport }]] : 'list',
  timeout: 30000,
});
