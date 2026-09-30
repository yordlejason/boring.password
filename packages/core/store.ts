import { readFile } from 'node:fs/promises';
import type { BrokerState, TransactionStore } from './types.js';

export function emptyState(): BrokerState {
  return {
    requests: {},
    challenges: {},
    attempts: {},
    permits: {},
    sessions: {},
    audit: [],
    quarantinedRuntimes: {},
  };
}

/** Serializes whole transactions, cloning on entry/exit so callers cannot mutate persisted state. */
export class MemoryStore implements TransactionStore {
  private state: BrokerState;
  private tail: Promise<unknown> = Promise.resolve();
  constructor(initial: BrokerState = emptyState()) {
    this.state = structuredClone(initial);
  }
  transaction<T>(fn: (state: BrokerState) => T | Promise<T>): Promise<T> {
    const work = this.tail.then(async () => {
      const snapshot = structuredClone(this.state);
      const result = await fn(snapshot);
      this.state = snapshot;
      return structuredClone(result);
    });
    this.tail = work.catch(() => undefined);
    return work;
  }
  snapshot(): Promise<BrokerState> {
    return this.transaction((state) => structuredClone(state));
  }
}

export interface QueryResult {
  rows: Array<Record<string, unknown>>;
}
export interface QueryClient {
  query(sql: string, values?: unknown[]): Promise<QueryResult>;
  release?(): void;
}
export interface QueryPool extends QueryClient {
  connect?(): Promise<QueryClient>;
  end?(): Promise<void>;
}

/** A metadata row lock fences every transition, approval consumption and permit consumption
 * across all broker instances. Secret material never enters this repository. */
export class PostgresStore implements TransactionStore {
  private initialized?: Promise<void>;
  private tail: Promise<unknown> = Promise.resolve();
  constructor(private readonly pool: QueryPool) {}
  initialize(): Promise<void> {
    this.initialized ??= (async () => {
      const schema = await readFile(
        new URL('../../../db/001_authorization.sql', import.meta.url),
        'utf8',
      ).catch(async () =>
        readFile(new URL('../../db/001_authorization.sql', import.meta.url), 'utf8'),
      );
      for (const statement of schema
        .split(';')
        .map((value) => value.trim())
        .filter(Boolean))
        await this.pool.query(statement);
    })();
    return this.initialized;
  }
  transaction<T>(fn: (state: BrokerState) => T | Promise<T>): Promise<T> {
    // Embedded PostgreSQL engines provide one connection; serialize those locally.
    if (!this.pool.connect) {
      const work = this.tail.then(() => this.run(fn));
      this.tail = work.catch(() => undefined);
      return work;
    }
    return this.run(fn);
  }
  private async run<T>(fn: (state: BrokerState) => T | Promise<T>): Promise<T> {
    await this.initialize();
    const client = this.pool.connect ? await this.pool.connect() : this.pool;
    await client.query('BEGIN');
    try {
      const metadata = (
        await client.query(
          'SELECT boot_epoch, quarantined_runtimes FROM broker_metadata WHERE singleton=true FOR UPDATE',
        )
      ).rows[0]!;
      const state = emptyState();
      if (typeof metadata.boot_epoch === 'string') state.bootEpoch = metadata.boot_epoch;
      state.quarantinedRuntimes = metadata.quarantined_runtimes as Record<string, boolean>;
      for (const [table, field] of [
        ['auth_requests', 'requests'],
        ['approval_challenges', 'challenges'],
        ['execution_attempts', 'attempts'],
        ['secret_permits', 'permits'],
        ['protected_sessions', 'sessions'],
      ] as const) {
        for (const row of (await client.query(`SELECT id, body FROM ${table}`)).rows) {
          (state[field] as Record<string, unknown>)[row.id as string] = row.body;
        }
      }
      state.audit = (
        await client.query('SELECT body FROM audit_events ORDER BY timestamp, id')
      ).rows.map((row) => row.body as BrokerState['audit'][number]);
      const result = await fn(state);
      await client.query(
        'UPDATE broker_metadata SET boot_epoch=$1, quarantined_runtimes=$2::jsonb WHERE singleton=true',
        [state.bootEpoch ?? null, JSON.stringify(state.quarantinedRuntimes)],
      );
      for (const request of Object.values(state.requests)) {
        await client.query(
          'INSERT INTO auth_requests(id,owner_id,client_id,idempotency_key,revision,state,body) VALUES($1,$2,$3,$4,$5,$6,$7::jsonb) ON CONFLICT(id) DO UPDATE SET revision=EXCLUDED.revision,state=EXCLUDED.state,body=EXCLUDED.body',
          [
            request.id,
            request.context.ownerId,
            request.context.clientId,
            request.idempotencyKey,
            request.revision,
            request.state,
            JSON.stringify(request),
          ],
        );
      }
      for (const challenge of Object.values(state.challenges)) {
        await client.query(
          'INSERT INTO approval_challenges(id,request_id,request_revision,device_id,nonce,payload_bytes,payload_digest,consumed_at,body) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb) ON CONFLICT(id) DO UPDATE SET consumed_at=EXCLUDED.consumed_at,body=EXCLUDED.body',
          [
            challenge.id,
            challenge.requestId,
            challenge.revision,
            challenge.deviceId,
            challenge.nonce,
            Buffer.from(challenge.payloadBase64, 'base64'),
            challenge.payloadDigest,
            challenge.consumedAt ?? null,
            JSON.stringify(challenge),
          ],
        );
      }
      // Retire old attempts first so the partial unique runtime fence stays valid.
      for (const attempt of Object.values(state.attempts).sort(
        (a, b) => Number(a.state === 'ACTIVE') - Number(b.state === 'ACTIVE'),
      )) {
        await client.query(
          'INSERT INTO execution_attempts(id,request_id,request_revision,execution_generation,runtime_id,state,lease_expires_at,body) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(id) DO UPDATE SET state=EXCLUDED.state,lease_expires_at=EXCLUDED.lease_expires_at,body=EXCLUDED.body',
          [
            attempt.attemptId,
            attempt.requestId,
            attempt.revision,
            attempt.executionGeneration,
            attempt.runtimeId,
            attempt.state,
            attempt.leaseExpiresAt,
            JSON.stringify(attempt),
          ],
        );
      }
      for (const permit of Object.values(state.permits)) {
        await client.query(
          'INSERT INTO secret_permits(id,request_id,request_revision,attempt_id,factor,adapter_step,consumed_at,body) VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb) ON CONFLICT(id) DO UPDATE SET consumed_at=EXCLUDED.consumed_at,body=EXCLUDED.body',
          [
            permit.id,
            permit.requestId,
            permit.revision,
            permit.attemptId,
            permit.factor,
            permit.adapterStep,
            permit.consumedAt ?? null,
            JSON.stringify(permit),
          ],
        );
        if (permit.consumedAt)
          await client.query(
            'INSERT INTO secret_permit_consumptions(permit_id,consumed_at) VALUES($1,$2) ON CONFLICT DO NOTHING',
            [permit.id, permit.consumedAt],
          );
      }
      for (const session of Object.values(state.sessions)) {
        await client.query(
          'INSERT INTO protected_sessions(id,request_id,owner_id,client_id,workload_id,body) VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body',
          [
            session.id,
            session.requestId,
            session.ownerId,
            session.clientId,
            session.workloadId,
            JSON.stringify(session),
          ],
        );
      }
      for (const event of state.audit)
        await client.query(
          'INSERT INTO audit_events(id,event,timestamp,body) VALUES($1,$2,$3,$4::jsonb) ON CONFLICT DO NOTHING',
          [event.id, event.event, event.timestamp, JSON.stringify(event)],
        );
      await client.query('COMMIT');
      return structuredClone(result);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release?.();
    }
  }
  async close(): Promise<void> {
    await this.pool.end?.();
  }
}
