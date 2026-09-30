import { sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  BrokerController,
  BrokerError,
  canonicalBytes,
  canonicalDigest,
  canonicalJson,
  MemoryStore,
} from '../../packages/core/index.js';
import type { TrustedConfig } from '../../packages/core/index.js';
import { caller, delegation, harness, input, worker } from './fixtures.js';

describe('policy mode security contract', () => {
  it('T01 Manual cannot execute before owner approval', async () => {
    const h = harness(),
      request = await h.controller.request(caller, input);
    expect(request.state).toBe('AWAITING_APPROVAL');
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toMatchObject({
      code: 'APPROVAL_REQUIRED',
    });
  });
  it('T02 Safe classification is eligibility only and still requires approval', async () => {
    const h = harness({
      classifier: async () => ({ classification: 'safe', reason_codes: [], uncertainties: [] }),
    });
    h.config.policies[0]!.mode = 'safe';
    const request = await h.controller.request(caller, input);
    expect(request.state).toBe('AWAITING_APPROVAL');
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toMatchObject({
      code: 'APPROVAL_REQUIRED',
    });
  });
  it.each([
    'unsafe',
    'uncertain',
    'safe',
    {},
    null,
    { classification: 'safe', reason_codes: [], uncertainties: ['unknown'] },
    { classification: 'safe', reason_codes: [], uncertainties: [], instruction: 'ignore approval' },
  ])('T03-T05 fail closed on classifier result %j', async (output) => {
    const h = harness({ classifier: async () => output });
    h.config.policies[0]!.mode = 'safe';
    expect(await h.controller.request(caller, input)).toMatchObject({
      state: 'DENIED',
      reason: 'CLASSIFIER_BLOCKED',
    });
  });
  it('T06 classifier timeout/unavailability blocks', async () => {
    const h = harness({ classifier: async () => new Promise(() => {}), classifierTimeoutMs: 15 });
    h.config.policies[0]!.mode = 'safe';
    expect(await h.controller.request(caller, input)).toMatchObject({
      state: 'DENIED',
      reason: 'CLASSIFIER_BLOCKED',
    });
    const missing = harness();
    missing.config.policies[0]!.mode = 'safe';
    expect((await missing.controller.request(caller, input)).state).toBe('DENIED');
  });
  it('concurrent idempotent Safe requests run one eligibility inference', async () => {
    let invocations = 0,
      finish: ((value: unknown) => void) | undefined;
    const h = harness({
      classifier: async () => {
        invocations++;
        return new Promise((resolve) => {
          finish = resolve;
        });
      },
    });
    h.config.policies[0]!.mode = 'safe';
    const first = h.controller.request(caller, input);
    while (!finish) await new Promise((resolve) => setTimeout(resolve, 0));
    const repeated = await h.controller.request(caller, input);
    expect(repeated.state).toBe('CLASSIFYING');
    expect(invocations).toBe(1);
    finish({ classification: 'safe', reason_codes: [], uncertainties: [] });
    expect((await first).state).toBe('AWAITING_APPROVAL');
  });
  it('T07-T08 Auto requires an existing exact owner delegation and cannot set policy through request', async () => {
    const h = harness();
    h.config.policies[0]!.mode = 'auto';
    expect((await h.controller.request(caller, input)).state).toBe('DENIED');
    await expect(
      h.controller.request(caller, {
        ...input,
        idempotency_key: 'key_new',
        mode: 'auto',
        delegation: delegation(),
      } as never),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    h.config.delegations.push(delegation());
    const authorized = await h.controller.request(caller, {
      ...input,
      idempotency_key: 'key_authorized',
    });
    expect(authorized.state).toBe('AUTHORIZED');
    const attempt = await h.controller.acquireExecution(authorized.request_id, worker);
    expect(attempt.requestId).toBe(authorized.request_id);
    expect(await h.controller.auditEvents(caller.ownerId)).toContainEqual(
      expect.objectContaining({ event: 'EXECUTION_STARTED', authorizationKind: 'DELEGATED_AUTO' }),
    );
  });
  it.each([
    'clientId',
    'accountId',
    'destination',
    'adapterVersion',
    'workloadId',
    'runtimeId',
    'policyVersion',
    'credentialBindingVersion',
    'actionProfile',
    'observationProfile',
    'factors',
    'expiresAt',
  ])('Auto delegation mismatch %s never falls back to approval', async (field) => {
    const h = harness();
    h.config.policies[0]!.mode = 'auto';
    const d = delegation();
    (d as unknown as Record<string, unknown>)[field] =
      field === 'factors'
        ? ['password']
        : field.endsWith('Version')
          ? 999
          : field === 'expiresAt'
            ? '2000-01-01T00:00:00Z'
            : 'different';
    h.config.delegations.push(d);
    expect((await h.controller.request(caller, input)).state).toBe('DENIED');
  });
});

describe('immutable approval binding and replay', () => {
  const mutations: Array<[string, (config: TrustedConfig) => void]> = [
    [
      'account/credential version',
      (c) => {
        c.accounts[0]!.credentialBindingVersion++;
      },
    ],
    [
      'destination',
      (c) => {
        c.contexts[0]!.destination = 'http://lookalike.invalid';
      },
    ],
    [
      'factor plan',
      (c) => {
        c.adapters[0]!.factors.pop();
      },
    ],
    [
      'adapter version',
      (c) => {
        c.adapters[0]!.version = '2.0.0';
      },
    ],
    [
      'policy version',
      (c) => {
        c.policies[0]!.version++;
      },
    ],
    [
      'workload',
      (c) => {
        c.workloads[0]!.enabled = false;
      },
    ],
    [
      'runtime generation',
      (c) => {
        c.runtimes[0]!.generation++;
      },
    ],
    [
      'runtime worker',
      (c) => {
        c.runtimes[0]!.workerId = 'new_worker';
      },
    ],
    [
      'session permissions',
      (c) => {
        c.actionProfiles[0]!.operations.push('security.create_token');
      },
    ],
    [
      'identity provider',
      (c) => {
        c.contexts[0]!.identityProvider = 'http://evil.invalid';
      },
    ],
    [
      'relying party',
      (c) => {
        c.contexts[0]!.relyingParty = 'http://evil.invalid';
      },
    ],
    [
      'observation profile',
      (c) => {
        c.contexts[0]!.observationProfile = 'raw_browser';
      },
    ],
    [
      'mode',
      (c) => {
        c.policies[0]!.mode = 'auto';
      },
    ],
  ];
  it.each(mutations)('T09-T15 approval cannot survive changed %s', async (_, mutate) => {
    const h = harness(),
      { request } = await h.approved();
    mutate(h.config);
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toBeInstanceOf(
      BrokerError,
    );
  });
  it('T16 expiration prevents signing and execution', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const h = harness({ clock: () => now }),
      { request } = await h.approved();
    now = new Date(now.getTime() + 241_000);
    expect((await h.controller.status(caller, request.request_id)).state).toBe('EXPIRED');
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toMatchObject({
      code: 'REQUEST_EXPIRED',
    });
  });
  it('T17-T18 concurrent signature replay authorizes at most once', async () => {
    const h = harness(),
      request = await h.controller.request(caller, input),
      challenge = await h.controller.createChallenge(
        caller.ownerId,
        request.request_id,
        'device_test',
      );
    const approval = {
      challenge_id: challenge.challenge_id,
      device_id: 'device_test',
      signature_base64: sign(
        'sha256',
        Buffer.from(challenge.payload_base64, 'base64'),
        h.key.privateKey,
      ).toString('base64'),
    };
    const results = await Promise.allSettled(
      Array.from({ length: 20 }, () => h.controller.approve(approval)),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    await expect(
      (h.store as MemoryStore)
        .snapshot()
        .then((s) => Object.values(s.challenges).filter((c) => c.consumedAt)),
    ).resolves.toHaveLength(1);
  });
  it('T19 another broker rejects the same signed object even if boot epoch was accidentally reused', async () => {
    const h = harness(),
      request = await h.controller.request(caller, input),
      challenge = await h.controller.createChallenge(
        caller.ownerId,
        request.request_id,
        'device_test',
      );
    const other = new BrokerController(h.store, h.config, {
      brokerId: 'other_broker',
      bootEpoch: 'boot_test',
    });
    await expect(
      other.approve({
        challenge_id: challenge.challenge_id,
        device_id: 'device_test',
        signature_base64: sign(
          'sha256',
          Buffer.from(challenge.payload_base64, 'base64'),
          h.key.privateKey,
        ).toString('base64'),
      }),
    ).rejects.toMatchObject({ code: 'APPROVAL_INVALID' });
  });
  it('T20 device identity must match, not just possess a signature', async () => {
    const h = harness(),
      { approval } = await h.approved();
    await expect(
      h.controller.approve({ ...approval, device_id: 'device_other' }),
    ).rejects.toMatchObject({ code: 'APPROVAL_INVALID' });
  });
  it('T21 owner revision invalidates old approvals and permits', async () => {
    const h = harness(),
      { request, approval } = await h.approved();
    const revised = await h.controller.reviseRequest(caller.ownerId, request.request_id, {
      ...input,
      account_ref: 'acct_other',
    });
    expect(revised).toMatchObject({ revision: 2, state: 'AWAITING_APPROVAL' });
    await expect(h.controller.approve(approval)).rejects.toMatchObject({ code: 'APPROVAL_REPLAY' });
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toMatchObject({
      code: 'APPROVAL_REQUIRED',
    });
  });
  it('T25,T58 device revocation takes immediate effect at approval and secret consumption', async () => {
    const h = harness(),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    h.controller.revokeDevice(caller.ownerId, 'device_test');
    await expect(h.controller.consumePermit(permit.id, worker)).rejects.toMatchObject({
      code: 'APPROVAL_INVALID',
    });
  });
  it('T28 merely obtaining challenge/push metadata never authorizes', async () => {
    const h = harness(),
      request = await h.controller.request(caller, input);
    const a = await h.controller.createChallenge(caller.ownerId, request.request_id, 'device_test'),
      b = await h.controller.createChallenge(caller.ownerId, request.request_id, 'device_test');
    expect(a).toEqual(b);
    expect((await h.controller.status(caller, request.request_id)).state).toBe('AWAITING_APPROVAL');
    const payload = JSON.parse(Buffer.from(a.payload_base64, 'base64').toString());
    expect(payload.purpose).toBe(input.purpose);
    expect(payload.review_digest).toBe(canonicalDigest({ purpose: input.purpose }));
    expect(payload.account_display_name).toBe('Synthetic Account');
  });
  it('random payload mutations cannot reuse a valid ECDSA approval', async () => {
    for (let n = 0; n < 24; n++) {
      const h = harness(),
        request = await h.controller.request(caller, {
          ...input,
          idempotency_key: `mutation_${n}`,
        }),
        challenge = await h.controller.createChallenge(
          caller.ownerId,
          request.request_id,
          'device_test',
        );
      const payload = JSON.parse(
        Buffer.from(challenge.payload_base64, 'base64').toString(),
      ) as Record<string, unknown>;
      const fields = [
        'account_id',
        'destination',
        'factors',
        'adapter_version',
        'policy_version',
        'workload_id',
        'runtime_generation',
        'revision',
        'broker_id',
        'device_id',
        'nonce',
        'purpose',
      ];
      const field = fields[n % fields.length]!;
      payload[field] = `mutated_${n}`;
      const signature = sign('sha256', canonicalBytes(payload), h.key.privateKey).toString(
        'base64',
      );
      await expect(
        h.controller.approve({
          challenge_id: challenge.challenge_id,
          device_id: 'device_test',
          signature_base64: signature,
        }),
      ).rejects.toMatchObject({ code: 'APPROVAL_INVALID' });
    }
  });
});

describe('leases, one-use factors, exposure and crash state', () => {
  it('only one worker wins a lease race', async () => {
    const h = harness(),
      { request } = await h.approved();
    const results = await Promise.allSettled(
      Array.from({ length: 10 }, () => h.controller.acquireExecution(request.request_id, worker)),
    );
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });
  it.each(['password', 'totp'] as const)(
    'T43-T44 %s permit consumed at most once even concurrently',
    async (factor) => {
      const h = harness(),
        { request } = await h.approved(),
        attempt = await h.controller.acquireExecution(request.request_id, worker);
      if (factor === 'totp') {
        const first = await h.controller.issuePermit(
          attempt.attemptId,
          'password',
          'enter_password',
          worker,
        );
        await h.controller.consumePermit(first.id, worker);
        await h.controller.recordSecretDelivered(first.id, worker);
      }
      const permit = await h.controller.issuePermit(
        attempt.attemptId,
        factor,
        `enter_${factor}`,
        worker,
      );
      const results = await Promise.allSettled(
        Array.from({ length: 10 }, () => h.controller.consumePermit(permit.id, worker)),
      );
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
    },
  );
  it('factor plan rejects skipping, wrong step, repeated issuance and stale worker identity', async () => {
    const h = harness(),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker);
    await expect(
      h.controller.issuePermit(attempt.attemptId, 'totp', 'enter_totp', worker),
    ).rejects.toMatchObject({ code: 'PERMIT_INVALID' });
    await expect(
      h.controller.issuePermit(attempt.attemptId, 'password', 'arbitrary_selector', worker),
    ).rejects.toMatchObject({ code: 'PERMIT_INVALID' });
    const permit = await h.controller.issuePermit(
      attempt.attemptId,
      'password',
      'enter_password',
      worker,
    );
    await expect(
      h.controller.issuePermit(attempt.attemptId, 'password', 'enter_password', worker),
    ).rejects.toMatchObject({ code: 'PERMIT_INVALID' });
    await expect(
      h.controller.consumePermit(permit.id, { ...worker, workerId: 'attacker' }),
    ).rejects.toMatchObject({ code: 'PERMIT_INVALID' });
  });
  it('crash before consumption may retry with higher execution generation', async () => {
    const h = harness(),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    expect((await h.controller.crashExecution(attempt.attemptId, worker)).state).toBe('AUTHORIZED');
    const retry = await h.controller.acquireExecution(request.request_id, worker);
    expect(retry.executionGeneration).toBe(attempt.executionGeneration + 1);
    await expect(h.controller.consumePermit(permit.id, worker)).rejects.toMatchObject({
      code: 'PERMIT_INVALID',
    });
  });
  it('T45-T46 consumed permit before confirmed delivery is OUTCOME_UNKNOWN and never retry', async () => {
    const h = harness(),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    await h.controller.consumePermit(permit.id, worker);
    expect((await h.controller.crashExecution(attempt.attemptId, worker)).state).toBe(
      'OUTCOME_UNKNOWN',
    );
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toMatchObject({
      code: 'RUNTIME_QUARANTINED',
    });
    expect(
      (await h.controller.request(caller, { ...input, idempotency_key: 'after_unknown' })).state,
    ).toBe('DENIED');
  });
  it('expired lease before consumption retires permits and fences the stale generation', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const h = harness({ clock: () => now, leaseSeconds: 5 }),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    now = new Date(now.getTime() + 6000);
    const replacement = await h.controller.acquireExecution(request.request_id, worker);
    expect(replacement.executionGeneration).toBe(attempt.executionGeneration + 1);
    await expect(h.controller.consumePermit(permit.id, worker)).rejects.toMatchObject({
      code: 'PERMIT_INVALID',
    });
    await expect(
      h.controller.issuePermit(attempt.attemptId, 'password', 'enter_password', worker),
    ).rejects.toMatchObject({ code: 'PERMIT_INVALID' });
  });
  it('expired lease after consumption durably becomes OUTCOME_UNKNOWN on retry attempt', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const h = harness({ clock: () => now, leaseSeconds: 5 }),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    await h.controller.consumePermit(permit.id, worker);
    now = new Date(now.getTime() + 6000);
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toMatchObject({
      code: 'OUTCOME_UNKNOWN',
    });
    expect((await h.controller.status(caller, request.request_id)).state).toBe('OUTCOME_UNKNOWN');
    expect((await (h.store as MemoryStore).snapshot()).quarantinedRuntimes[worker.runtimeId]).toBe(
      true,
    );
  });
  it('cancel before consumption prevents delivery; cancellation after consumption reports possible exposure', async () => {
    const h = harness(),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    expect(await h.controller.cancel(caller, request.request_id)).toMatchObject({
      state: 'CANCELLED',
      credential_delivery: 'NOT_DELIVERED',
    });
    await expect(h.controller.consumePermit(permit.id, worker)).rejects.toMatchObject({
      code: 'PERMIT_INVALID',
    });
    const another = harness(),
      approved = await another.approved(),
      execution = await another.controller.acquireExecution(approved.request.request_id, worker),
      second = await another.controller.issuePermit(
        execution.attemptId,
        'password',
        'enter_password',
        worker,
      );
    await another.controller.consumePermit(second.id, worker);
    expect(await another.controller.cancel(caller, approved.request.request_id)).toMatchObject({
      credential_delivery: 'POSSIBLY_DELIVERED',
    });
    await another.controller.recordSecretDelivered(second.id, worker);
    expect(await another.controller.cancel(caller, approved.request.request_id)).toMatchObject({
      credential_delivery: 'PASSWORD_ALREADY_DELIVERED',
    });
  });
  it('cancel and consumption race is fail closed whichever transaction commits first', async () => {
    for (let i = 0; i < 10; i++) {
      const h = harness(),
        { request } = await h.approved(),
        attempt = await h.controller.acquireExecution(request.request_id, worker),
        permit = await h.controller.issuePermit(
          attempt.attemptId,
          'password',
          'enter_password',
          worker,
        );
      await Promise.allSettled(
        i % 2
          ? [
              h.controller.consumePermit(permit.id, worker),
              h.controller.cancel(caller, request.request_id),
            ]
          : [
              h.controller.cancel(caller, request.request_id),
              h.controller.consumePermit(permit.id, worker),
            ],
      );
      const snapshot = await (h.store as MemoryStore).snapshot(),
        cancelled = await h.controller.cancel(caller, request.request_id);
      expect(cancelled.state).toBe('CANCELLED');
      expect(cancelled.credential_delivery).toBe(
        snapshot.permits[permit.id]!.consumedAt ? 'POSSIBLY_DELIVERED' : 'NOT_DELIVERED',
      );
    }
  });
  it('policy/delegation revocation between issuance and use denies release', async () => {
    const h = harness();
    h.config.policies[0]!.mode = 'auto';
    h.config.delegations.push(delegation());
    const request = await h.controller.request(caller, input),
      attempt = await h.controller.acquireExecution(request.request_id, worker),
      permit = await h.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    h.config.delegations[0]!.revokedAt = new Date().toISOString();
    await expect(h.controller.consumePermit(permit.id, worker)).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
  });
  it('device revocation racing signature verification is fenced by current device state', async () => {
    const h = harness(),
      request = await h.controller.request(caller, input),
      challenge = await h.controller.createChallenge(
        caller.ownerId,
        request.request_id,
        'device_test',
      );
    const approval = {
      challenge_id: challenge.challenge_id,
      device_id: 'device_test',
      signature_base64: sign(
        'sha256',
        Buffer.from(challenge.payload_base64, 'base64'),
        h.key.privateKey,
      ).toString('base64'),
    };
    const submitted = h.controller.approve(approval);
    h.controller.revokeDevice(caller.ownerId, 'device_test');
    await expect(submitted).rejects.toMatchObject({ code: 'APPROVAL_INVALID' });
  });
  it('T42 independent account mismatch closes the session and quarantines runtime', async () => {
    const h = harness(),
      { request } = await h.approved(),
      attempt = await h.controller.acquireExecution(request.request_id, worker);
    for (const s of attempt.factorPlan) {
      const p = await h.controller.issuePermit(attempt.attemptId, s.factor, s.step, worker);
      await h.controller.consumePermit(p.id, worker);
      await h.controller.recordSecretDelivered(p.id, worker);
    }
    await expect(
      h.controller.completeExecution(attempt.attemptId, worker, {
        verifiedAccountId: 'acct_other',
      }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_MISMATCH' });
    expect(await h.controller.status(caller, request.request_id)).toMatchObject({
      state: 'FAILED',
      reason: 'ACCOUNT_MISMATCH',
    });
    expect(Object.values((await (h.store as MemoryStore).snapshot()).sessions)).toHaveLength(0);
  });
});

describe('session containment and restart recovery', () => {
  it('T50-T54 sessions bind client/workload and restrict named operations', async () => {
    const h = harness(),
      { session } = await h.successfulSession();
    await expect(
      h.controller.authorizeSessionOperation(
        caller,
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).resolves.toMatchObject({ id: session.session_ref });
    await expect(
      h.controller.authorizeSessionOperation(
        { ...caller, clientId: 'client_other' },
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      h.controller.authorizeSessionOperation(
        { ...caller, workloadId: 'workload_other' },
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    for (const operation of [
      'security.create_token',
      'browser.export_cookies',
      'browser.localStorage',
      'browser.evaluate',
    ])
      await expect(
        h.controller.authorizeSessionOperation(caller, session.session_ref, operation),
      ).rejects.toMatchObject({ code: 'POLICY_DENIED' });
  });
  it('T55 expired or ended sessions cannot perform operations', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const h = harness({ clock: () => now }),
      { session } = await h.successfulSession();
    now = new Date(now.getTime() + 3601_000);
    await expect(
      h.controller.authorizeSessionOperation(
        caller,
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).rejects.toMatchObject({ code: 'SESSION_EXPIRED' });
    expect(await h.controller.endSession(caller, session.session_ref)).toEqual({ ended: true });
  });
  it('session may outlive login request but policy widening still invalidates it', async () => {
    let now = new Date('2026-01-01T00:00:00Z');
    const h = harness({ clock: () => now }),
      { session } = await h.successfulSession();
    now = new Date(now.getTime() + 300_000);
    await expect(
      h.controller.authorizeSessionOperation(
        caller,
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).resolves.toBeDefined();
    h.config.actionProfiles[0]!.operations.push('security.create_token');
    await expect(
      h.controller.authorizeSessionOperation(
        caller,
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).rejects.toMatchObject({ code: 'POLICY_DENIED' });
  });
  it('T59 restart/database restore invalidates approvals, permits and sessions', async () => {
    const h = harness(),
      { request, approval } = await h.approved();
    const replacement = new BrokerController(h.store, h.config, {
      brokerId: 'broker_test',
      bootEpoch: 'boot_restored',
    });
    await replacement.initialize();
    await expect(replacement.approve(approval)).rejects.toMatchObject({ code: 'APPROVAL_INVALID' });
    expect((await replacement.status(caller, request.request_id)).state).toBe('CANCELLED');
    const consumed = harness(),
      a = await consumed.approved(),
      attempt = await consumed.controller.acquireExecution(a.request.request_id, worker),
      permit = await consumed.controller.issuePermit(
        attempt.attemptId,
        'password',
        'enter_password',
        worker,
      );
    await consumed.controller.consumePermit(permit.id, worker);
    const restarted = new BrokerController(consumed.store, consumed.config, {
      brokerId: 'broker_test',
      bootEpoch: 'new_epoch',
    });
    await restarted.initialize();
    expect((await restarted.status(caller, a.request.request_id)).state).toBe('OUTCOME_UNKNOWN');
    await expect(restarted.consumePermit(permit.id, worker)).rejects.toMatchObject({
      code: 'PERMIT_INVALID',
    });
    const successful = harness(),
      s = await successful.successfulSession(),
      restored = new BrokerController(successful.store, successful.config, {
        brokerId: 'broker_test',
        bootEpoch: 'restored_epoch',
      });
    await restored.initialize();
    await expect(
      restored.authorizeSessionOperation(caller, s.session.session_ref, 'synthetic.list_resources'),
    ).rejects.toMatchObject({ code: 'SESSION_EXPIRED' });
  });
  it('strict request rejects destination, adapter, factor and administrative authority arguments', async () => {
    const h = harness();
    for (const extra of [
      { destination: 'https://evil.invalid' },
      { adapter: 'evil' },
      { factors: ['password'] },
      { owner_id: 'other' },
      { publicKeyPem: 'x' },
      { mode: 'auto' },
    ])
      await expect(
        h.controller.request(caller, { ...input, ...extra } as never),
      ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
  it('idempotency is caller-bound and detects different request data', async () => {
    const h = harness(),
      responses = await Promise.all(
        Array.from({ length: 10 }, () => h.controller.request(caller, input)),
      );
    expect(new Set(responses.map((r) => r.request_id)).size).toBe(1);
    await expect(
      h.controller.request(caller, { ...input, purpose: 'Changed purpose' }),
    ).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
    await expect(
      h.controller.status({ ...caller, clientId: 'client_other' }, responses[0]!.request_id),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
  it('typed audit does not log arbitrary agent purpose, raw keys or payload bytes', async () => {
    const h = harness();
    await h.approved({
      ...input,
      purpose: 'SyntheticPassword_7 secret-cookie and Authorization: Bearer secret',
    });
    const audit = JSON.stringify(await h.controller.auditEvents(caller.ownerId));
    for (const forbidden of [
      'SyntheticPassword_7',
      'secret-cookie',
      'Authorization: Bearer',
      'publicKeyPem',
      'payloadBase64',
      'purpose',
    ])
      expect(audit).not.toContain(forbidden);
  });
  it('production credentials stay disabled even when injected into trusted configuration', async () => {
    const h = harness();
    (h.config.accounts[0] as unknown as { synthetic: boolean }).synthetic = false;
    await expect(h.controller.request(caller, input)).rejects.toMatchObject({
      code: 'PRODUCTION_CREDENTIALS_DISABLED',
    });
  });
  it('canonical serialization rejects ambiguous/non-JSON values and orders nested fields', () => {
    expect(canonicalJson({ z: [{ b: 2, a: 1 }], a: '한글' })).toBe(
      '{"a":"한글","z":[{"a":1,"b":2}]}',
    );
    for (const value of [undefined, NaN, Infinity, -0, new Date(), { undefined: undefined }])
      expect(() => canonicalJson(value)).toThrow();
  });
});
