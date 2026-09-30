import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SettingsFile, newSettings, newToken, type Settings } from '../apps/broker/src/config.js';
import { createRuntime } from '../apps/broker/src/runtime.js';
import type { OwnerPolicySummary } from '../apps/broker/src/http.js';
import { MemoryStore, type Delegation, type Mode } from '../packages/core/index.js';

const owner = 'owner_local',
  policyId = 'policy_synthetic';
const caller = { ownerId: owner, clientId: 'client_local', workloadId: 'workload_local' };
const worker = {
  workerId: 'worker_synthetic',
  runtimeId: 'runtime_synthetic',
  runtimeGeneration: 1,
};
const input = (key: string) => ({
  context_ref: 'ctx_synthetic',
  account_ref: 'acct_synthetic',
  operation: 'sign_in' as const,
  workload_ref: 'workload_local',
  purpose: 'Synthetic mode boundary test.',
  idempotency_key: key,
});
const cleanup: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  vi.restoreAllMocks();
  for (const close of cleanup.splice(0).reverse()) await close();
});

async function fixture(blocked = false) {
  const dir = await mkdtemp(join(tmpdir(), 'boring-login-policy-'));
  cleanup.push(() => rm(dir, { recursive: true, force: true }));
  const settings = newSettings(newToken(), newToken());
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  settings.trusted.devices.push({
    id: 'device_test',
    ownerId: owner,
    displayName: 'Synthetic Approval Key',
    assuranceProfile: 'SYNTHETIC_TEST_KEY',
    publicKeyPem: key.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  });
  const path = blocked ? join(dir, 'blocker', 'config.json') : join(dir, 'config.json');
  if (blocked) await writeFile(dirname(path), 'synthetic IO blocker');
  const file = new SettingsFile(path, settings),
    store = new MemoryStore();
  if (!blocked) await file.save();
  const runtime = await createRuntime(file, store, 'http://127.0.0.1:3212');
  cleanup.push(() => runtime.close());
  async function approved(id: string) {
    const request = await runtime.controller.request(caller, input(id));
    const challenge = await runtime.controller.createChallenge(
      owner,
      request.request_id,
      'device_test',
    );
    const approval = {
      challenge_id: challenge.challenge_id,
      device_id: 'device_test',
      signature_base64: sign('sha256', Buffer.from(challenge.payload_base64, 'base64'), {
        key: key.privateKey,
        dsaEncoding: 'der',
      }).toString('base64'),
    };
    await runtime.controller.approve(approval);
    return { request, challenge, approval };
  }
  return { file, runtime, store, approved, key };
}
async function summary(app: Awaited<ReturnType<typeof fixture>>) {
  return ((await app.runtime.control.overview(owner)) as { policies: OwnerPolicySummary[] })
    .policies[0]!;
}
const change = (app: Awaited<ReturnType<typeof fixture>>, mode: Mode, expected_version = 1) =>
  app.runtime.control.setPolicyMode(owner, policyId, { mode, expected_version });
function delegation(policyVersion = 2): Delegation {
  return {
    id: 'delegation_test',
    ownerId: owner,
    clientId: caller.clientId,
    accountId: 'acct_synthetic',
    destination: 'http://127.0.0.1:3212',
    adapterId: 'synthetic-login',
    adapterVersion: '1.0.0',
    operation: 'sign_in',
    factors: ['password', 'totp'],
    actionProfile: 'synthetic_read_profile',
    observationProfile: 'synthetic_read_profile',
    workloadId: caller.workloadId,
    runtimeId: worker.runtimeId,
    policyId,
    policyVersion,
    credentialBindingVersion: 1,
    maxSessionSeconds: 60,
    expiresAt: '2099-01-01T00:00:00.000Z',
  };
}

describe('owner mode updates are staged, durable and versioned', () => {
  it('preserves same-mode version and journal, including a legacy settings reopen', async () => {
    const app = await fixture(),
      invalidation = vi.spyOn(app.runtime.controller, 'invalidatePolicy');
    const legacy = structuredClone(app.file.settings) as Partial<Settings>;
    delete legacy.ownerPolicyChanges;
    await writeFile(app.file.path, JSON.stringify(legacy), { mode: 0o600 });
    expect((await SettingsFile.open(app.file.path)).settings.ownerPolicyChanges).toEqual([]);
    expect(await change(app, 'manual')).toEqual({
      id: policyId,
      mode: 'manual',
      version: 1,
      enabled: true,
      auto_delegation_available: false,
    });
    expect(invalidation).not.toHaveBeenCalled();
    expect(app.file.settings.ownerPolicyChanges).toEqual([]);
    expect((await SettingsFile.open(app.file.path)).settings.trusted.policies[0]!.version).toBe(1);
  });

  it('serializes competing expected versions and persists exactly one typed owner journal row', async () => {
    const app = await fixture(),
      configIdentity = app.file.settings.trusted;
    const result = await Promise.allSettled([change(app, 'safe'), change(app, 'auto')]);
    expect(result.filter((value) => value.status === 'fulfilled')).toHaveLength(1);
    expect(result.find((value) => value.status === 'rejected')).toMatchObject({
      status: 'rejected',
      reason: { code: 'POLICY_DENIED' },
    });
    const reopened = await SettingsFile.open(app.file.path);
    expect(reopened.settings.trusted.policies[0]).toMatchObject({ mode: 'safe', version: 2 });
    expect(app.file.settings.trusted).toBe(configIdentity);
    expect(app.runtime.controller.config.policies[0]).toMatchObject({ mode: 'safe', version: 2 });
    expect(reopened.settings.ownerPolicyChanges).toEqual([
      {
        ownerId: owner,
        policyId,
        previousMode: 'manual',
        mode: 'safe',
        previousVersion: 1,
        version: 2,
        changedAt: expect.any(String),
      },
    ]);
    expect(Object.keys(reopened.settings.ownerPolicyChanges[0]!).sort()).toEqual([
      'changedAt',
      'mode',
      'ownerId',
      'policyId',
      'previousMode',
      'previousVersion',
      'version',
    ]);
    expect(() => app.file.assertAuthorityReady()).not.toThrow();
  });

  it('keeps live authority suspended and old configuration active while the persisted fence is awaited', async () => {
    const app = await fixture();
    let enter!: () => void, release!: () => void;
    const entered = new Promise<void>((resolve) => {
      enter = resolve;
    });
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const invalidate = app.runtime.controller.invalidatePolicy.bind(app.runtime.controller);
    vi.spyOn(app.runtime.controller, 'invalidatePolicy').mockImplementation(async (...args) => {
      enter();
      await released;
      return invalidate(...args);
    });
    const updating = change(app, 'safe');
    await entered;
    expect((await SettingsFile.open(app.file.path)).settings.trusted.policies[0]).toMatchObject({
      mode: 'safe',
      version: 2,
    });
    expect(app.file.settings.trusted.policies[0]).toMatchObject({ mode: 'manual', version: 1 });
    expect(() => app.file.assertAuthorityReady()).toThrow('POLICY_DENIED');
    await expect(app.runtime.api.request(caller, input('during-fence'))).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
    release();
    await updating;
    expect(() => app.file.assertAuthorityReady()).not.toThrow();
    expect(app.file.settings.trusted.policies[0]).toMatchObject({ mode: 'safe', version: 2 });
  });

  it('never publishes failed persistence and requires the same mode intent to repair the sticky fault', async () => {
    const app = await fixture(true),
      invalidate = vi.spyOn(app.runtime.controller, 'invalidatePolicy');
    const updating = change(app, 'safe');
    expect(() => app.file.assertAuthorityReady()).toThrow('POLICY_DENIED');
    await expect(updating).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    expect(invalidate).not.toHaveBeenCalled();
    expect(app.file.settings.trusted.policies[0]).toMatchObject({ mode: 'manual', version: 1 });
    expect(app.file.settings.ownerPolicyChanges).toEqual([]);
    await expect(app.runtime.api.request(caller, input('unpersisted'))).rejects.toMatchObject({
      code: 'SECURITY_STATE_UNPERSISTED',
    });
    await rm(dirname(app.file.path));
    await mkdir(dirname(app.file.path));
    await expect(change(app, 'auto')).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    await change(app, 'safe');
    expect(() => app.file.assertAuthorityReady()).not.toThrow();
    const reopened = await SettingsFile.open(app.file.path);
    expect(reopened.settings.trusted.policies[0]).toMatchObject({ mode: 'safe', version: 2 });
    expect(reopened.settings.ownerPolicyChanges).toHaveLength(1);
  });

  it('keeps a post-persistence cleanup failure suspended and retries the fence before publishing', async () => {
    const app = await fixture();
    const invalidation = vi.spyOn(app.runtime.controller, 'invalidatePolicy');
    invalidation.mockRejectedValueOnce(new Error('Synthetic cleanup failure'));
    await expect(change(app, 'safe')).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    expect((await SettingsFile.open(app.file.path)).settings.trusted.policies[0]).toMatchObject({
      mode: 'safe',
      version: 2,
    });
    expect(app.file.settings.trusted.policies[0]).toMatchObject({ mode: 'manual', version: 1 });
    expect(app.file.settings.ownerPolicyChanges).toEqual([]);
    expect(() => app.file.assertAuthorityReady()).toThrow('SECURITY_STATE_UNPERSISTED');
    const stagedBytes = await readFile(app.file.path, 'utf8');
    await expect(
      app.file.update('unrelated-pairing', (draft) => {
        draft.pairings = [];
      }),
    ).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    await expect(app.file.save()).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    expect(await readFile(app.file.path, 'utf8')).toBe(stagedBytes);
    await change(app, 'safe');
    expect(invalidation).toHaveBeenCalledTimes(2);
    expect(app.file.settings.ownerPolicyChanges).toHaveLength(1);
    expect((await SettingsFile.open(app.file.path)).settings.ownerPolicyChanges).toHaveLength(1);
    expect(() => app.file.assertAuthorityReady()).not.toThrow();
  });

  it('bounds the durable public-field journal to the latest 100 owner changes', async () => {
    const app = await fixture();
    app.file.settings.ownerPolicyChanges = Array.from({ length: 100 }, (_, index) => ({
      ownerId: owner,
      policyId,
      previousMode: 'manual',
      mode: 'safe',
      previousVersion: index + 1,
      version: index + 2,
      changedAt: '2026-01-01T00:00:00.000Z',
    }));
    await change(app, 'safe');
    const journal = (await SettingsFile.open(app.file.path)).settings.ownerPolicyChanges;
    expect(journal).toHaveLength(100);
    expect(journal[0]!.previousVersion).toBe(2);
    expect(journal[99]).toMatchObject({
      previousVersion: 1,
      version: 2,
      previousMode: 'manual',
      mode: 'safe',
    });
  });

  it.each(['wrong owner', 'disabled', 'overflow', 'stale version', 'non-synthetic'] as const)(
    'refuses %s without publishing a mode or journal',
    async (caseName) => {
      const app = await fixture();
      const policy = app.file.settings.trusted.policies[0]!;
      let ownerId = owner,
        expected_version = 1,
        code = 'POLICY_DENIED';
      if (caseName === 'wrong owner') ownerId = 'other_owner';
      if (caseName === 'disabled') policy.enabled = false;
      if (caseName === 'overflow') policy.version = expected_version = Number.MAX_SAFE_INTEGER;
      if (caseName === 'stale version') expected_version = 2;
      if (caseName === 'non-synthetic') {
        (app.file.settings.trusted.accounts[0] as unknown as { synthetic: boolean }).synthetic =
          false;
        code = 'PRODUCTION_CREDENTIALS_DISABLED';
      }
      await expect(
        app.runtime.control.setPolicyMode(ownerId, policyId, { mode: 'safe', expected_version }),
      ).rejects.toMatchObject({ code });
      expect(policy.mode).toBe('manual');
      expect(app.file.settings.ownerPolicyChanges).toEqual([]);
      expect(() => app.file.assertAuthorityReady()).not.toThrow();
    },
  );
});

describe('mode changes fence old authorization and never manufacture Auto delegation', () => {
  it.each(['manual', 'safe'] as const)('%s still requires exact device approval', async (mode) => {
    const app = await fixture();
    if (mode === 'safe') await change(app, 'safe');
    const request = await app.runtime.controller.request(caller, input(mode));
    expect(request.state).toBe('AWAITING_APPROVAL');
    await expect(
      app.runtime.controller.acquireExecution(request.request_id, worker),
    ).rejects.toMatchObject({ code: 'APPROVAL_REQUIRED' });
    expect(Object.values((await app.store.snapshot()).permits)).toHaveLength(0);
  });

  it('invalidates old pending signed bytes and unused permits through the durable mode hook', async () => {
    const app = await fixture();
    const pending = await app.runtime.controller.request(caller, input('pending'));
    const challenge = await app.runtime.controller.createChallenge(
      owner,
      pending.request_id,
      'device_test',
    );
    const { request } = await app.approved('authorized');
    const attempt = await app.runtime.controller.acquireExecution(request.request_id, worker);
    const permit = await app.runtime.controller.issuePermit(
      attempt.attemptId,
      'password',
      'enter_password',
      worker,
    );
    await change(app, 'safe');
    await expect(
      app.runtime.controller.approve({
        challenge_id: challenge.challenge_id,
        device_id: 'device_test',
        signature_base64: sign('sha256', Buffer.from(challenge.payload_base64, 'base64'), {
          key: app.key.privateKey,
          dsaEncoding: 'der',
        }).toString('base64'),
      }),
    ).rejects.toBeDefined();
    await expect(app.runtime.controller.consumePermit(permit.id, worker)).rejects.toBeDefined();
    const state = await app.store.snapshot();
    expect(state.requests[pending.request_id]!.state).toBe('CANCELLED');
    expect(state.requests[request.request_id]!.state).toBe('CANCELLED');
    expect(state.challenges[challenge.challenge_id]!.invalidatedAt).toBeDefined();
    expect(state.permits[permit.id]!.invalidatedAt).toBeDefined();
    expect(state.quarantinedRuntimes[worker.runtimeId]).toBeUndefined();
  });

  it('retires a consumed execution as unknown and quarantines it during mode publication', async () => {
    const app = await fixture(),
      { request } = await app.approved('consumed');
    const attempt = await app.runtime.controller.acquireExecution(request.request_id, worker);
    const permit = await app.runtime.controller.issuePermit(
      attempt.attemptId,
      'password',
      'enter_password',
      worker,
    );
    await app.runtime.controller.consumePermit(permit.id, worker);
    await change(app, 'safe');
    const state = await app.store.snapshot();
    expect(state.requests[request.request_id]).toMatchObject({
      state: 'OUTCOME_UNKNOWN',
      possibleDelivery: true,
    });
    expect(state.attempts[attempt.attemptId]!.state).toBe('OUTCOME_UNKNOWN');
    expect(state.quarantinedRuntimes[worker.runtimeId]).toBe(true);
    await expect(
      app.runtime.controller.issuePermit(attempt.attemptId, 'totp', 'enter_totp', worker),
    ).rejects.toBeDefined();
    expect(Object.values(state.sessions)).toHaveLength(0);
  });

  it('revokes a prior session and retries private browser cleanup handles after a refresh failure', async () => {
    const app = await fixture(),
      { request } = await app.approved('session');
    const attempt = await app.runtime.controller.acquireExecution(request.request_id, worker);
    for (const factor of attempt.factorPlan) {
      const permit = await app.runtime.controller.issuePermit(
        attempt.attemptId,
        factor.factor,
        factor.step,
        worker,
      );
      await app.runtime.controller.consumePermit(permit.id, worker);
      await app.runtime.controller.recordSecretDelivered(permit.id, worker);
    }
    const session = await app.runtime.controller.completeExecution(attempt.attemptId, worker, {
      verifiedAccountId: 'acct_synthetic',
    });
    const end = vi
      .spyOn(app.runtime.worker, 'endSession')
      .mockRejectedValueOnce(new Error('Synthetic close failure'));
    await expect(change(app, 'safe')).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    expect((await app.store.snapshot()).sessions[session.session_ref]!.revokedAt).toBeDefined();
    expect(app.file.settings.trusted.policies[0]!.version).toBe(1);
    await change(app, 'safe');
    expect(end).toHaveBeenCalledTimes(2);
    expect(end).toHaveBeenNthCalledWith(1, session.session_ref);
    expect(end).toHaveBeenNthCalledWith(2, session.session_ref);
    await expect(
      app.runtime.controller.authorizeSessionOperation(
        caller,
        session.session_ref,
        'synthetic.read_profile',
        caller.workloadId,
      ),
    ).rejects.toMatchObject({ code: 'SESSION_EXPIRED' });
    expect(await summary(app)).toEqual({
      id: policyId,
      mode: 'safe',
      version: 2,
      enabled: true,
      auto_delegation_available: false,
    });
    expect(JSON.stringify(await app.runtime.control.overview(owner))).not.toContain(
      session.session_ref,
    );
    expect(() => app.file.assertAuthorityReady()).not.toThrow();
  });

  it('blocks Auto with no delegation and leaves an old-version delegation untouched', async () => {
    const app = await fixture();
    app.file.settings.trusted.delegations.push(delegation(1));
    const before = structuredClone(app.file.settings.trusted.delegations);
    expect((await summary(app)).auto_delegation_available).toBe(false);
    expect(await change(app, 'auto')).toMatchObject({
      mode: 'auto',
      version: 2,
      auto_delegation_available: false,
    });
    expect(app.file.settings.trusted.delegations).toEqual(before);
    expect((await app.runtime.controller.request(caller, input('auto-blocked'))).state).toBe(
      'DENIED',
    );
    expect(Object.values((await app.store.snapshot()).challenges)).toHaveLength(0);
    expect(Object.values((await app.store.snapshot()).permits)).toHaveLength(0);
  });

  it('reports only an exact pre-existing prospective-version delegation and preserves its owner bindings', async () => {
    const app = await fixture();
    app.file.settings.trusted.delegations.push(delegation());
    const before = structuredClone(app.file.settings.trusted.delegations);
    expect((await summary(app)).auto_delegation_available).toBe(true);
    expect(await change(app, 'auto')).toMatchObject({
      mode: 'auto',
      version: 2,
      auto_delegation_available: true,
    });
    expect(app.file.settings.trusted.delegations).toEqual(before);
    const request = await app.runtime.controller.request(caller, input('explicit-auto'));
    expect(request.state).toBe('AUTHORIZED');
    expect((await app.store.snapshot()).requests[request.request_id]!.authorization!.kind).toBe(
      'DELEGATED_AUTO',
    );
  });

  it.each([
    { ownerId: 'other_owner' },
    { clientId: 'other_client' },
    { accountId: 'other_account' },
    { destination: 'https://other.invalid' },
    { adapterId: 'other_adapter' },
    { adapterVersion: '2' },
    { factors: ['totp', 'password'] },
    { actionProfile: 'other_action' },
    { observationProfile: 'other_observation' },
    { workloadId: 'other_workload' },
    { runtimeId: 'other_runtime' },
    { policyId: 'other_policy' },
    { policyVersion: 1 },
    { credentialBindingVersion: 2 },
    { maxSessionSeconds: 0 },
    { maxSessionSeconds: 3601 },
    { expiresAt: '2000-01-01T00:00:00.000Z' },
    { revokedAt: '2026-01-01T00:00:00.000Z' },
  ])('does not advertise mismatched or expired Auto delegation %j', async (patch) => {
    const app = await fixture();
    app.file.settings.trusted.delegations.push({ ...delegation(), ...patch } as Delegation);
    expect((await summary(app)).auto_delegation_available).toBe(false);
  });

  it('does not advertise Auto for a revoked transport or disabled context', async () => {
    const app = await fixture();
    app.file.settings.trusted.delegations.push(delegation());
    app.file.settings.clients[0]!.revokedAt = new Date().toISOString();
    expect((await summary(app)).auto_delegation_available).toBe(false);
    delete app.file.settings.clients[0]!.revokedAt;
    app.file.settings.trusted.contexts[0]!.enabled = false;
    expect((await summary(app)).auto_delegation_available).toBe(false);
  });

  it.each(['empty', 'duplicate'] as const)(
    'does not advertise Auto for %s adapter factors',
    async (caseName) => {
      const app = await fixture(),
        binding = delegation();
      app.file.settings.trusted.adapters[0]!.factors =
        caseName === 'empty'
          ? []
          : [
              { factor: 'password', step: 'enter_password' },
              { factor: 'password', step: 'enter_password' },
            ];
      binding.factors = caseName === 'empty' ? [] : ['password', 'password'];
      app.file.settings.trusted.delegations.push(binding);
      expect((await summary(app)).auto_delegation_available).toBe(false);
    },
  );
});
