import { mkdir, stat } from 'node:fs/promises';
import { chromium } from 'playwright';

try {
  if (process.getuid?.() === 0) throw new Error('NON_ROOT_REQUIRED');
  const config = process.env.BROKER_CONFIG;
  if (!config || ((await stat(config)).mode & 0o077) !== 0)
    throw new Error('PRIVATE_CONFIG_REQUIRED');
  await mkdir(process.env.HOME ?? '/tmp/boring-login', { recursive: true, mode: 0o700 });
  // Fail closed before the server is healthy when the Linux namespace/seccomp
  // configuration cannot launch Chromium with its sandbox enabled.
  const browser = await chromium.launch({ headless: true, chromiumSandbox: true });
  await browser.close();
  await import('../dist/apps/broker/src/main.js');
} catch {
  process.stderr.write(
    'Synthetic container startup refused: check non-root UID, private configuration, PostgreSQL and Chromium sandbox support.\n',
  );
  process.exitCode = 1;
}
