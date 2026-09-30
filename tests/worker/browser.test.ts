import { existsSync } from 'node:fs';
import { PGlite } from '@electric-sql/pglite';
import { chromium } from 'playwright';
import { describe, expect, it } from 'vitest';
import { SyntheticBrowserWorker } from '../../services/browser-worker/index.js';
import type { ExecutionBinding } from '../../services/browser-worker/contracts.js';
import { startSyntheticSite, type SyntheticAttack } from '../../adapters/synthetic-login/site.js';
import { createSyntheticManifest } from '../../adapters/synthetic-login/manifest.js';
import { SYNTHETIC_CREDENTIAL } from '../../services/secret-service/synthetic-fixture.js';
import { fakeBinding, fakeBroker } from './helpers.js';

const browserInstalled = existsSync(chromium.executablePath());

describe('reviewed synthetic manifest', () => {
  it.each([
    'https://127.0.0.1:3212',
    'http://localhost:3212',
    'http://127.0.0.1.evil.test:3212',
    'http://127.0.0.1:3212/login',
    'http://user:secret@127.0.0.1:3212',
  ])('refuses non-reviewed origin %s', (origin) => {
    expect(() => createSyntheticManifest(origin)).toThrow('DESTINATION_MISMATCH');
  });
});

describe('reviewed factor-plan binding', () => {
  it.each([
    [
      'reversed factors',
      [
        { factor: 'totp', step: 'enter_totp' },
        { factor: 'password', step: 'enter_password' },
      ],
    ],
    ['missing factor', [{ step: 'enter_password' }, { factor: 'totp', step: 'enter_totp' }]],
    ['missing step', [{ factor: 'password' }, { factor: 'totp', step: 'enter_totp' }]],
    [
      'extra key',
      [
        { factor: 'password', step: 'enter_password', extra: true },
        { factor: 'totp', step: 'enter_totp' },
      ],
    ],
    [
      'unknown key',
      [
        { factor: 'password', unknown: 'enter_password' },
        { factor: 'totp', step: 'enter_totp' },
      ],
    ],
    [
      'unknown factor',
      [
        { factor: 'recovery', step: 'enter_password' },
        { factor: 'totp', step: 'enter_totp' },
      ],
    ],
    [
      'unknown step',
      [
        { factor: 'password', step: 'enter_recovery' },
        { factor: 'totp', step: 'enter_totp' },
      ],
    ],
    ['missing entry', [{ factor: 'password', step: 'enter_password' }]],
    ['extra entry', [...fakeBinding().factorPlan, { factor: 'totp', step: 'enter_totp' }]],
    ['non-array plan', { factor: 'password', step: 'enter_password' }],
    ['null entry', [null, { factor: 'totp', step: 'enter_totp' }]],
  ])('rejects %s before issuing a credential permit', async (_name, factorPlan) => {
    const binding = { ...fakeBinding(), factorPlan } as ExecutionBinding;
    const broker = fakeBroker(binding);
    const worker = new SyntheticBrowserWorker({
      broker,
      origin: binding.destination,
      workerId: binding.workerId,
      runtimeId: binding.runtimeId,
      runtimeGeneration: binding.runtimeGeneration,
    });
    try {
      expect(await worker.authenticate(binding.requestId)).toEqual({
        state: 'FAILED',
        code: 'ADAPTER_UNSUPPORTED',
      });
      expect(broker.events).toEqual(['begin', 'fail']);
      expect(broker.consumed).toHaveLength(0);
      expect(broker.delivered).toHaveLength(0);
      expect(broker.completed).toBe(false);
    } finally {
      await worker.close();
    }
  });
});

// A skipped suite is explicitly reported if Chromium is missing; install it with
// `npx playwright install chromium`. The security release gate remains incomplete.
describe.runIf(browserInstalled)('actual Chromium synthetic containment', () => {
  it('authenticates JSONB-persisted factor plans despite reordered object keys', async () => {
    const site = await startSyntheticSite();
    const database = new PGlite();
    let worker: SyntheticBrowserWorker | undefined;
    try {
      await database.exec('CREATE TABLE worker_binding (body jsonb NOT NULL)');
      await database.query('INSERT INTO worker_binding (body) VALUES ($1::jsonb)', [
        JSON.stringify(fakeBinding(site.origin)),
      ]);
      const binding = (
        await database.query<{ body: ExecutionBinding }>('SELECT body FROM worker_binding')
      ).rows[0]!.body;
      // This reproduces the database serialization that caused the live failure.
      expect(Object.keys(binding.factorPlan[0]!)).toEqual(['step', 'factor']);
      const broker = fakeBroker(binding);
      // Also exercise a permit transport using the opposite insertion order;
      // neither worker nor private secret-service authorization can depend on it.
      broker.tamper = (permit) => ({
        ...permit,
        factorPlan: permit.factorPlan.map(({ factor, step }) => ({ factor, step })),
      });
      worker = new SyntheticBrowserWorker({
        broker,
        origin: site.origin,
        workerId: binding.workerId,
        runtimeId: binding.runtimeId,
        runtimeGeneration: binding.runtimeGeneration,
      });
      const result = await worker.authenticate(binding.requestId);
      expect(result.state).toBe('SUCCEEDED');
      if (result.state !== 'SUCCEEDED') throw new Error('AUTHENTICATION_EXPECTED');
      expect((await worker.readProfile(result.sessionRef)).permission).toBe('read_profile');
      expect(broker.consumed.map(({ factor }) => factor)).toEqual(['password', 'totp']);
      expect(broker.delivered).toEqual(['password', 'totp']);
      expect(site.submissions()).toEqual({ password: 1, totp: 1 });
      expect(broker.failures).toHaveLength(0);
      await worker.endSession(result.sessionRef);
    } finally {
      await worker?.close();
      await database.close();
      await site.close();
    }
  });
  it('authenticates, independently verifies identity and exposes only allowlisted profile metadata', async () => {
    const site = await startSyntheticSite();
    const binding = fakeBinding(site.origin);
    const broker = fakeBroker(binding);
    const worker = new SyntheticBrowserWorker({
      broker,
      origin: site.origin,
      workerId: binding.workerId,
      runtimeId: binding.runtimeId,
      runtimeGeneration: binding.runtimeGeneration,
    });
    try {
      const result = await worker.authenticate(binding.requestId);
      expect(result.state).toBe('SUCCEEDED');
      if (result.state !== 'SUCCEEDED') throw new Error('AUTHENTICATION_EXPECTED');
      expect(await worker.readProfile(result.sessionRef)).toEqual({
        accountRef: 'acct_synthetic',
        displayName: 'Synthetic Owner',
        service: 'Synthetic Login',
        permission: 'read_profile',
      });
      expect(site.submissions()).toEqual({ password: 1, totp: 1 });
      expect(broker.events).toEqual([
        'begin',
        'issue_password',
        'consume_password',
        'delivered_password',
        'issue_totp',
        'consume_totp',
        'delivered_totp',
        'complete',
      ]);
      const observations = JSON.stringify({
        result,
        events: broker.events,
        consumed: broker.consumed,
        profile: await worker.readProfile(result.sessionRef),
      });
      expect(observations).not.toContain(SYNTHETIC_CREDENTIAL.password);
      expect(observations).not.toContain(SYNTHETIC_CREDENTIAL.totpSeed);
      expect(observations).not.toContain('synthetic_session=');
      expect(observations).not.toContain('authorization');
      await worker.endSession(result.sessionRef);
      await expect(worker.readProfile(result.sessionRef)).rejects.toMatchObject({
        code: 'POLICY_DENIED',
      });
    } finally {
      await worker.close();
      await site.close();
    }
  });

  it.each([
    ['wrong-origin', 'DESTINATION_MISMATCH', 0, 0],
    ['cross-origin-frame', 'DESTINATION_MISMATCH', 0, 0],
    ['wrong-account', 'ACCOUNT_MISMATCH', 1, 1],
    ['recovery', 'INTERACTION_REQUIRED', 1, 0],
    ['unexpected-otp', 'INTERACTION_REQUIRED', 1, 0],
  ] as const)(
    'fails closed for %s without exposing a session',
    async (attack, code, password, totp) => {
      const site = await startSyntheticSite({ attack: attack as SyntheticAttack });
      const binding = fakeBinding(site.origin);
      const broker = fakeBroker(binding);
      const worker = new SyntheticBrowserWorker({
        broker,
        origin: site.origin,
        workerId: binding.workerId,
        runtimeId: binding.runtimeId,
        runtimeGeneration: binding.runtimeGeneration,
      });
      try {
        const result = await worker.authenticate(binding.requestId);
        expect(result).toEqual({ state: 'FAILED', code });
        expect(broker.completed).toBe(false);
        expect(site.submissions()).toEqual({ password, totp });
        expect(broker.failures).toEqual([code]);
        if (password === 0) expect(broker.consumed).toHaveLength(0);
        // No automatic second submission, including after a known failure.
        expect(site.submissions().password).toBeLessThanOrEqual(1);
        expect(site.submissions().totp).toBeLessThanOrEqual(1);
      } finally {
        await worker.close();
        await site.close();
      }
    },
  );

  it('takes one exclusive runtime lock and rejects concurrent execution', async () => {
    const site = await startSyntheticSite();
    const binding = fakeBinding(site.origin);
    const broker = fakeBroker(binding);
    const worker = new SyntheticBrowserWorker({
      broker,
      origin: site.origin,
      workerId: binding.workerId,
      runtimeId: binding.runtimeId,
      runtimeGeneration: binding.runtimeGeneration,
    });
    try {
      const first = worker.authenticate(binding.requestId);
      const second = await worker.authenticate(binding.requestId);
      expect(second).toEqual({ state: 'FAILED', code: 'POLICY_DENIED' });
      expect((await first).state).toBe('SUCCEEDED');
      expect(site.submissions()).toEqual({ password: 1, totp: 1 });
    } finally {
      await worker.close();
      await site.close();
    }
  });

  it('quarantines an ambiguous private delivery and never automatically retries it', async () => {
    const site = await startSyntheticSite();
    const binding = fakeBinding(site.origin);
    const broker = fakeBroker(binding);
    broker.recordSecretDelivered = async () => {
      throw new Error(SYNTHETIC_CREDENTIAL.password);
    };
    const worker = new SyntheticBrowserWorker({
      broker,
      origin: site.origin,
      workerId: binding.workerId,
      runtimeId: binding.runtimeId,
      runtimeGeneration: binding.runtimeGeneration,
    });
    try {
      const result = await worker.authenticate(binding.requestId);
      expect(result).toEqual({ state: 'OUTCOME_UNKNOWN', code: 'OUTCOME_UNKNOWN' });
      expect(broker.consumed).toHaveLength(1);
      expect(broker.failures).toEqual(['OUTCOME_UNKNOWN']);
      expect(site.submissions()).toEqual({ password: 0, totp: 0 });
      expect(await worker.authenticate(binding.requestId)).toEqual(result);
      expect(broker.events.filter((event) => event === 'begin')).toHaveLength(1);
      expect(JSON.stringify(result)).not.toContain(SYNTHETIC_CREDENTIAL.password);
    } finally {
      await worker.close();
      await site.close();
    }
  });

  it('has no agent interfaces for scripts, screenshots, traces, CDP or reusable browser state', async () => {
    const site = await startSyntheticSite();
    const binding = fakeBinding(site.origin);
    const worker = new SyntheticBrowserWorker({
      broker: fakeBroker(binding),
      origin: site.origin,
      workerId: binding.workerId,
      runtimeId: binding.runtimeId,
      runtimeGeneration: binding.runtimeGeneration,
    });
    try {
      expect(Object.getOwnPropertyNames(Object.getPrototypeOf(worker)).sort()).toEqual([
        'authenticate',
        'close',
        'constructor',
        'endSession',
        'readProfile',
      ]);
      expect(Object.keys(worker)).toEqual([]);
    } finally {
      await worker.close();
      await site.close();
    }
  });
});
