import { mkdir, writeFile, access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { newSettings, newToken, SettingsFile } from '../apps/broker/src/config.js';
const dir = resolve('.local');
await mkdir(dir, { recursive: true, mode: 0o700 });
const path = resolve(dir, 'broker.json');
try {
  await access(path);
  process.stderr.write('Configuration already exists; bootstrap will not replace it.\n');
  process.exit(1);
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
}
const adminToken = newToken(),
  clientToken = newToken();
await new SettingsFile(path, newSettings(adminToken, clientToken)).save();
await writeFile(resolve(dir, 'owner-token'), adminToken + '\n', { mode: 0o600, flag: 'wx' });
await writeFile(resolve(dir, 'client-token'), clientToken + '\n', { mode: 0o600, flag: 'wx' });
await writeFile(
  resolve(dir, 'mcp-client.json'),
  JSON.stringify(
    { url: 'http://127.0.0.1:3210/mcp', headers: { Authorization: `Bearer ${clientToken}` } },
    null,
    2,
  ) + '\n',
  { mode: 0o600, flag: 'wx' },
);
process.stdout.write(
  'Created private synthetic configuration in .local/. Transport tokens were written to private files.\n',
);
