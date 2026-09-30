import { PGlite } from '@electric-sql/pglite';
import { describe, expect, it } from 'vitest';
import { BrokerController, PostgresStore } from '../../packages/core/index.js';
import type { QueryPool } from '../../packages/core/index.js';
import { caller, harness, input, worker } from './fixtures.js';

describe('actual PostgreSQL schema and transactional store', () => {
  it('persists requests/approval replay/one-use permits and recovers under a new boot epoch', async () => {
    const database = new PGlite(),
      pool: QueryPool = {
        query: async (sql, values) =>
          (await database.query(sql, values)) as { rows: Array<Record<string, unknown>> },
      };
    const store = new PostgresStore(pool),
      h = harness({}, store);
    try {
      const { request, approval } = await h.approved();
      const results = await Promise.allSettled([
        h.controller.acquireExecution(request.request_id, worker),
        h.controller.acquireExecution(request.request_id, worker),
      ]);
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      const attempt = results.find((r) => r.status === 'fulfilled')!;
      if (attempt.status !== 'fulfilled') throw new Error('Missing attempt');
      const permit = await h.controller.issuePermit(
        attempt.value.attemptId,
        'password',
        'enter_password',
        worker,
      );
      const consumed = await Promise.allSettled([
        h.controller.consumePermit(permit.id, worker),
        h.controller.consumePermit(permit.id, worker),
      ]);
      expect(consumed.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      expect(
        (
          await database.query<{ count: number }>(
            'SELECT COUNT(*)::int AS count FROM secret_permit_consumptions',
          )
        ).rows[0]!.count,
      ).toBe(1);
      expect(
        (
          await database.query<{ count: number }>(
            'SELECT COUNT(*)::int AS count FROM auth_requests',
          )
        ).rows[0]!.count,
      ).toBe(1);
      const restarted = new BrokerController(store, h.config, {
        brokerId: 'broker_test',
        bootEpoch: 'boot_recovered',
      });
      await restarted.initialize();
      expect((await restarted.status(caller, request.request_id)).state).toBe('OUTCOME_UNKNOWN');
      await expect(restarted.approve(approval)).rejects.toMatchObject({ code: 'APPROVAL_INVALID' });
      await expect(restarted.consumePermit(permit.id, worker)).rejects.toMatchObject({
        code: 'PERMIT_INVALID',
      });
      const body = (
        await database.query<{ body: { state: string } }>('SELECT body FROM auth_requests')
      ).rows[0]!.body;
      expect(body.state).toBe('OUTCOME_UNKNOWN');
    } finally {
      await database.close();
    }
  }, 30_000);
  it('idempotency and rollback persist through independent controller reads', async () => {
    const database = new PGlite(),
      pool: QueryPool = {
        query: async (sql, values) =>
          (await database.query(sql, values)) as { rows: Array<Record<string, unknown>> },
      };
    const store = new PostgresStore(pool),
      h = harness({}, store);
    try {
      const request = await h.controller.request(caller, input),
        same = await h.controller.request(caller, input);
      expect(same.request_id).toBe(request.request_id);
      await expect(
        h.controller.request(caller, { ...input, purpose: 'another purpose' }),
      ).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
      expect(
        (
          await database.query<{ count: number }>(
            'SELECT COUNT(*)::int AS count FROM auth_requests',
          )
        ).rows[0]!.count,
      ).toBe(1);
      const controller = new BrokerController(store, h.config, {
        brokerId: 'broker_test',
        bootEpoch: 'boot_test',
      });
      expect((await controller.status(caller, request.request_id)).state).toBe('AWAITING_APPROVAL');
    } finally {
      await database.close();
    }
  }, 30_000);
});
