import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
const localDeps = resolve('../.browser-deps');
const port = process.env.UNION_E2E_PORT ?? '8011';
if (!['8011', '5173'].includes(port)) throw new Error('UNION_E2E_PORT must be 8011 or 5173');
const baseURL = `http://127.0.0.1:${port}`;
if (existsSync(localDeps + '/usr/lib/x86_64-linux-gnu')) {
    process.env.LD_LIBRARY_PATH = localDeps + '/usr/lib/x86_64-linux-gnu';
    process.env.FONTCONFIG_FILE = localDeps + '/fonts.conf';
}
export default defineConfig({ testDir: './tests', fullyParallel: false, workers: 1, timeout: 30000, use: { baseURL, browserName: 'chromium', launchOptions: { chromiumSandbox: true } }, webServer: { command: `UNION_MODE=demo UNION_DEMO_SCENARIO=recovery ../.venv/bin/python -m uvicorn backend.app.main:app --app-dir .. --host 127.0.0.1 --port ${port} --workers 1 --no-access-log --no-proxy-headers`, url: `${baseURL}/api/health`, reuseExistingServer: false, gracefulShutdown: { signal: 'SIGTERM', timeout: 5000 } }, reporter: 'list' });
