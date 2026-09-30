import { randomBytes, sign } from 'node:crypto';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { BrokerController, PostgresStore } from '../packages/core/index.js';
import { caller, harness, input, worker } from './core/fixtures.js';

// Opt in with BOTH fields. Runs against a fresh random schema and never modifies
// the running broker's schema, requests, credential metadata or approval state.
const enabled = process.env.BORING_LOGIN_POSTGRES_TEST === '1' && Boolean(process.env.DATABASE_URL);
describe.runIf(enabled)('external PostgreSQL independent-connection concurrency', () => {
  const schema = `broker_test_${randomBytes(8).toString('hex')}`;
  const admin = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    max: 2,
    connectionTimeoutMillis: 5000,
  });
  const poolA = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    max: 5,
    connectionTimeoutMillis: 5000,
    options: `--search_path=${schema}`,
  });
  const poolB = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    max: 5,
    connectionTimeoutMillis: 5000,
    options: `--search_path=${schema}`,
  });
  const storeA = new PostgresStore(poolA);
  const storeB = new PostgresStore(poolB);

  beforeAll(async () => {
    try {
      await admin.query(`CREATE SCHEMA ${schema}`);
      await storeA.initialize();
      await storeB.initialize();
    } catch {
      throw new Error('FULL_POSTGRES_UNAVAILABLE');
    }
  });
  afterAll(async () => {
    await Promise.allSettled([storeA.close(), storeB.close()]);
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`).catch(() => undefined);
    await admin.end();
  });

  it('serializes cross-pool approval nonce replay, execution leasing and permit consumption', async () => {
    const first = harness({}, storeA);
    const second = new BrokerController(storeB, first.config, {
      brokerId: 'broker_test',
      bootEpoch: 'boot_test',
    });
    await first.controller.initialize();
    await second.initialize();
    const request = await first.controller.request(caller, {
      ...input,
      idempotency_key: 'pg_nonce',
    });
    const challenge = await first.controller.createChallenge(
      caller.ownerId,
      request.request_id,
      'device_test',
    );
    const approval = {
      challenge_id: challenge.challenge_id,
      device_id: 'device_test',
      signature_base64: sign('sha256', Buffer.from(challenge.payload_base64, 'base64'), {
        key: first.key.privateKey,
        dsaEncoding: 'der',
      }).toString('base64'),
    };
    const nonceRace = await Promise.allSettled([
      first.controller.approve(approval),
      second.approve(approval),
    ]);
    expect(nonceRace.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(
      (
        await poolA.query(
          'SELECT count(*)::int AS n FROM approval_challenges WHERE consumed_at IS NOT NULL',
        )
      ).rows[0].n,
    ).toBe(1);
    const leaseRace = await Promise.allSettled([
      first.controller.acquireExecution(request.request_id, worker),
      second.acquireExecution(request.request_id, worker),
    ]);
    expect(leaseRace.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const acquired = leaseRace.find((result) => result.status === 'fulfilled');
    if (!acquired || acquired.status !== 'fulfilled') throw new Error('EXECUTION_EXPECTED');
    const permit = await first.controller.issuePermit(
      acquired.value.attemptId,
      'password',
      'enter_password',
      worker,
    );
    const permitRace = await Promise.allSettled([
      first.controller.consumePermit(permit.id, worker),
      second.consumePermit(permit.id, worker),
    ]);
    expect(permitRace.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(
      (
        await poolB.query(
          'SELECT count(*)::int AS n FROM secret_permit_consumptions WHERE permit_id=$1',
          [permit.id],
        )
      ).rows[0].n,
    ).toBe(1);
    expect((await second.status(caller, request.request_id)).state).toBe('EXECUTING');
    await first.controller.crashExecution(acquired.value.attemptId, worker);
    expect((await second.status(caller, request.request_id)).state).toBe('OUTCOME_UNKNOWN');
  });

  it('rolls back conflicting idempotency and fences restart recovery across pools', async () => {
    const first = harness({}, storeA);
    // The prior crash case deliberately quarantined its runtime. This case uses
    // a distinct trusted runtime rather than erasing that safety state.
    first.config.runtimes[0]!.id = 'runtime_pg_restart';
    first.config.workloads[0]!.runtimeId = 'runtime_pg_restart';
    first.config.contexts[0]!.runtimeId = 'runtime_pg_restart';
    const request = await first.controller.request(caller, {
      ...input,
      idempotency_key: 'pg_idempotency',
    });
    expect(request.state).toBe('AWAITING_APPROVAL');
    await expect(
      first.controller.request(caller, {
        ...input,
        idempotency_key: 'pg_idempotency',
        purpose: 'Changed scope',
      }),
    ).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
    expect(
      (
        await poolA.query('SELECT count(*)::int AS n FROM auth_requests WHERE idempotency_key=$1', [
          'pg_idempotency',
        ])
      ).rows[0].n,
    ).toBe(1);
    const recovered = new BrokerController(storeB, first.config, {
      brokerId: 'broker_test',
      bootEpoch: 'boot_recovered_pg',
    });
    await recovered.initialize();
    expect((await recovered.status(caller, request.request_id)).state).toBe('CANCELLED');
  });

  it('durably retires old approval, execution and session authority after an owner mode change', async () => {
    const first = harness({}, storeA);
    const runtimeId = 'runtime_pg_policy';
    first.config.runtimes[0]!.id = runtimeId;
    first.config.workloads[0]!.runtimeId = runtimeId;
    first.config.contexts[0]!.runtimeId = runtimeId;
    const executionWorker = { ...worker, runtimeId };
    const second = new BrokerController(storeB, first.config, {
      brokerId: 'broker_test',
      bootEpoch: 'boot_test',
    });
    await first.controller.initialize();
    await second.initialize();
    const approve = async (idempotency_key: string) => {
      const request = await first.controller.request(caller, { ...input, idempotency_key });
      const challenge = await first.controller.createChallenge(
        caller.ownerId,
        request.request_id,
        'device_test',
      );
      const approval = {
        challenge_id: challenge.challenge_id,
        device_id: 'device_test',
        signature_base64: sign('sha256', Buffer.from(challenge.payload_base64, 'base64'), {
          key: first.key.privateKey,
          dsaEncoding: 'der',
        }).toString('base64'),
      };
      return { request, challenge, approval };
    };
    const prior = await approve('pg_policy_session');
    await first.controller.approve(prior.approval);
    const completed = await first.controller.acquireExecution(
      prior.request.request_id,
      executionWorker,
    );
    for (const factor of completed.factorPlan) {
      const permit = await first.controller.issuePermit(
        completed.attemptId,
        factor.factor,
        factor.step,
        executionWorker,
      );
      await first.controller.consumePermit(permit.id, executionWorker);
      await first.controller.recordSecretDelivered(permit.id, executionWorker);
    }
    const session = await first.controller.completeExecution(completed.attemptId, executionWorker, {
      verifiedAccountId: 'acct_synthetic',
    });
    const pending = await approve('pg_policy_pending');
    const running = await approve('pg_policy_running');
    await first.controller.approve(running.approval);
    const attempt = await first.controller.acquireExecution(
      running.request.request_id,
      executionWorker,
    );
    const permit = await first.controller.issuePermit(
      attempt.attemptId,
      'password',
      'enter_password',
      executionWorker,
    );
    await first.controller.consumePermit(permit.id, executionWorker);

    expect(
      await first.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'safe'),
    ).toEqual({
      sessionRefs: [session.session_ref],
    });
    Object.assign(first.config.policies[0]!, { version: 2, mode: 'safe' });
    expect((await second.status(caller, pending.request.request_id)).state).toBe('CANCELLED');
    expect((await second.status(caller, running.request.request_id)).state).toBe('OUTCOME_UNKNOWN');
    await expect(second.approve(pending.approval)).rejects.toBeDefined();
    await expect(second.consumePermit(permit.id, executionWorker)).rejects.toBeDefined();
    await expect(
      second.authorizeSessionOperation(caller, session.session_ref, 'synthetic.list_resources'),
    ).rejects.toMatchObject({
      code: 'SESSION_EXPIRED',
    });
    expect((await second.failExecution(attempt.attemptId, executionWorker)).state).toBe(
      'OUTCOME_UNKNOWN',
    );
    const persisted = await storeB.transaction((state) => structuredClone(state));
    expect(persisted.challenges[pending.challenge.challenge_id]!.invalidatedAt).toBeDefined();
    expect(persisted.challenges[pending.challenge.challenge_id]!.consumedAt).toBeUndefined();
    expect(persisted.attempts[attempt.attemptId]!.state).toBe('OUTCOME_UNKNOWN');
    expect(persisted.quarantinedRuntimes[runtimeId]).toBe(true);
    expect(persisted.sessions[session.session_ref]!.revokedAt).toBeDefined();
  });
});
