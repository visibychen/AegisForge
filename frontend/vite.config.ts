import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

const localPort = process.env.AEGISFORGE_DEV_API_PORT ?? '8000';
if (!/^\d{1,5}$/.test(localPort) || Number(localPort) < 1 || Number(localPort) > 65535) throw new Error('Invalid local API port');
const apiTarget = `http://127.0.0.1:${localPort}`;

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': apiTarget,
      '/health': apiTarget,
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    restoreMocks: true,
    clearMocks: true,
  },
});
