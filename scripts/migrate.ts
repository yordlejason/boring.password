import pg from 'pg';
import { PostgresStore } from '../packages/core/index.js';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL_REQUIRED');
const store = new PostgresStore(
  new pg.Pool({ connectionString: process.env.DATABASE_URL, connectionTimeoutMillis: 5000 }),
);
try {
  await store.initialize();
  process.stdout.write('Applied authorization metadata schema.\n');
} finally {
  await store.close();
}
