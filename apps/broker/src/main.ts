import { resolve } from 'node:path';
import pg from 'pg';
import { SettingsFile } from './config.js';
import { startBroker } from './startup.js';
import { MemoryStore, PostgresStore, type TransactionStore } from '../../../packages/core/index.js';

async function main() {
  const file = await SettingsFile.open(resolve(process.env.BROKER_CONFIG ?? '.local/broker.json'));
  if ((process.env.BROKER_HOST ?? '127.0.0.1') !== '127.0.0.1')
    throw new Error('LOOPBACK_REQUIRED');
  let store: TransactionStore;
  if (process.env.DATABASE_URL)
    store = new PostgresStore(
      new pg.Pool({
        connectionString: process.env.DATABASE_URL,
        max: 5,
        connectionTimeoutMillis: 5000,
      }),
    );
  else if (process.env.BROKER_EPHEMERAL_SYNTHETIC === '1') store = new MemoryStore();
  else throw new Error('PERSISTENCE_REQUIRED');
  const allowedHostnames = (process.env.BROKER_ALLOWED_HOSTNAMES ?? '127.0.0.1,localhost').split(
    ',',
  );
  const { agentPort, adminPort, stop } = await startBroker(file, store, {
    agentPort: Number(process.env.BROKER_PORT ?? 3210),
    adminPort: Number(process.env.BROKER_ADMIN_PORT ?? 3211),
    allowedHostnames,
  });
  process.stdout.write(
    `Synthetic broker: http://127.0.0.1:${agentPort}/mcp\nOwner console: http://127.0.0.1:${adminPort}\nProduction credentials disabled.\n`,
  );
  process.once('SIGINT', () => {
    void stop();
  });
  process.once('SIGTERM', () => {
    void stop();
  });
}
main().catch(() => {
  process.stderr.write(
    'Broker startup failed. Check private configuration, persistence, and listener availability.\n',
  );
  process.exitCode = 1;
});
