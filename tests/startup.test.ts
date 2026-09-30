import { describe, expect, it } from 'vitest';
import { createServer } from 'node:http';
import { MemoryStore } from '../packages/core/index.js';
import {
  SettingsFile,
  newSettings,
  newToken,
  syntheticTrustedConfig,
} from '../apps/broker/src/config.js';
import { startBroker } from '../apps/broker/src/startup.js';
import { listen, closeServer } from '../apps/broker/src/http.js';

async function unusedPort() {
  const server = createServer();
  const port = await listen(server);
  await closeServer(server);
  return port;
}
describe('startup resource containment', () => {
  it('closes fixture and agent listeners when the owner listener fails to bind', async () => {
    const occupied = createServer(),
      adminPort = await listen(occupied),
      sitePort = await unusedPort(),
      agentPort = await unusedPort();
    const settings = newSettings(newToken(), newToken());
    settings.trusted = syntheticTrustedConfig(`http://127.0.0.1:${sitePort}`);
    const file = new SettingsFile('/unused-synthetic-config', settings);
    try {
      await expect(
        startBroker(file, new MemoryStore(), {
          agentPort,
          adminPort,
          allowedHostnames: ['127.0.0.1'],
        }),
      ).rejects.toMatchObject({ code: 'EADDRINUSE' });
      for (const port of [sitePort, agentPort]) {
        const probe = createServer();
        await listen(probe, port);
        await closeServer(probe);
      }
    } finally {
      await closeServer(occupied);
    }
  });
  it('closes the fixture when trusted runtime validation fails', async () => {
    const sitePort = await unusedPort(),
      settings = newSettings(newToken(), newToken());
    settings.trusted = syntheticTrustedConfig(`http://127.0.0.1:${sitePort}`);
    settings.trusted.runtimes = [];
    await expect(
      startBroker(new SettingsFile('/unused-synthetic-config', settings), new MemoryStore(), {
        agentPort: 0,
        adminPort: 0,
        allowedHostnames: ['127.0.0.1'],
      }),
    ).rejects.toMatchObject({ code: 'POLICY_DENIED' });
    const probe = createServer();
    await listen(probe, sitePort);
    await closeServer(probe);
  });
});
