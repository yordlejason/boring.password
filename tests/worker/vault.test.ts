import { describe, expect, it } from 'vitest';
import {
  VaultKvV2Provider,
  type VaultCredentialEnrollment,
  type TrustedVaultFetch,
} from '../../services/secret-service/vault-kv-v2.js';
import {
  syntheticVaultTestCapability,
  type VaultReleaseCapability,
} from '../../packages/secret-provider-sdk/release-gate.js';
import { SYNTHETIC_CREDENTIAL } from '../../services/secret-service/synthetic-fixture.js';
import { generateTotp } from '../../services/secret-service/totp.js';
import type { PrivateSecretReceiver, TrustedClock } from '../../services/secret-service/index.js';
import { fakeBinding, fakeBroker } from './helpers.js';

const ORIGIN = 'https://synthetic-vault.invalid';
const TOKEN = 'synthetic-vault-token-only';
const ENROLLMENT: VaultCredentialEnrollment = {
  accountId: 'acct_synthetic',
  credentialBindingVersion: 1,
  mount: 'secret',
  path: ['broker', 'synthetic_account'],
  vaultVersion: 7,
  passwordField: 'password',
  totpSeedField: 'totp_seed',
  totp: SYNTHETIC_CREDENTIAL.totp,
  synthetic: true,
};

function response(
  options: {
    version?: number;
    destroyed?: boolean;
    deletion?: string;
    password?: unknown;
    seed?: unknown;
  } = {},
): Response {
  return new Response(
    JSON.stringify({
      data: {
        data: {
          password: options.password ?? SYNTHETIC_CREDENTIAL.password,
          totp_seed: options.seed ?? SYNTHETIC_CREDENTIAL.totpSeed,
        },
        metadata: {
          version: options.version ?? 7,
          destroyed: options.destroyed ?? false,
          deletion_time: options.deletion ?? '',
        },
      },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function harness(
  fetch: TrustedVaultFetch = async () => response(),
  overrides: {
    enrollment?: VaultCredentialEnrollment;
    clock?: TrustedClock;
    timeoutMs?: number;
  } = {},
) {
  const binding = fakeBinding();
  const broker = fakeBroker(binding, overrides.clock?.now ?? Date.now);
  const calls: { url: string; options: RequestInit }[] = [];
  let tokensRead = 0;
  const received: { factor: string; value: string }[] = [];
  const receiver: PrivateSecretReceiver = {
    async injectPassword(value) {
      received.push({ factor: 'password', value });
    },
    async injectTotp(value) {
      received.push({ factor: 'totp', value });
    },
  };
  const provider = new VaultKvV2Provider({
    releaseCapability: syntheticVaultTestCapability(),
    broker,
    origin: ORIGIN,
    enrollment: overrides.enrollment ?? ENROLLMENT,
    vaultToken: async () => {
      tokensRead += 1;
      return TOKEN;
    },
    fetch: async (url, options) => {
      calls.push({ url, options });
      return fetch(url, options);
    },
    ...(overrides.clock ? { clock: overrides.clock } : {}),
    ...(overrides.timeoutMs ? { timeoutMs: overrides.timeoutMs } : {}),
  });
  return { binding, broker, provider, receiver, received, calls, tokensRead: () => tokensRead };
}

describe('Vault KV v2 gated synthetic provider', () => {
  it('keeps the production release gate closed to booleans, copied handles and real origins', () => {
    const options = {
      broker: fakeBroker(),
      origin: ORIGIN,
      enrollment: ENROLLMENT,
      vaultToken: async () => TOKEN,
      fetch: async () => response(),
    };
    expect(
      () =>
        new VaultKvV2Provider({
          ...options,
          releaseCapability: true as unknown as VaultReleaseCapability,
        }),
    ).toThrow('POLICY_DENIED');
    expect(
      () => new VaultKvV2Provider({ ...options, releaseCapability: {} as VaultReleaseCapability }),
    ).toThrow('POLICY_DENIED');
    const gate = syntheticVaultTestCapability();
    expect(
      () => new VaultKvV2Provider({ ...options, releaseCapability: structuredClone(gate) }),
    ).toThrow('POLICY_DENIED');
    expect(
      () =>
        new VaultKvV2Provider({
          ...options,
          releaseCapability: gate,
          origin: 'https://vault.example.com',
        }),
    ).toThrow('POLICY_DENIED');
    expect(
      () =>
        new VaultKvV2Provider({
          ...options,
          releaseCapability: gate,
          enrollment: { ...ENROLLMENT, synthetic: false },
        }),
    ).toThrow('POLICY_DENIED');
    expect(
      () => new VaultKvV2Provider({ ...options, releaseCapability: gate, fetch: undefined }),
    ).toThrow('POLICY_DENIED');
  });

  it.each([
    'http://synthetic-vault.invalid',
    'https://synthetic-vault.invalid/path',
    'https://user:token@synthetic-vault.invalid',
  ])('refuses unpinned Vault origin %s', (origin) => {
    expect(
      () =>
        new VaultKvV2Provider({
          releaseCapability: syntheticVaultTestCapability(),
          broker: fakeBroker(),
          origin,
          enrollment: ENROLLMENT,
          vaultToken: async () => TOKEN,
          fetch: async () => response(),
        }),
    ).toThrow('DESTINATION_MISMATCH');
  });

  it.each([
    { path: ['..'] },
    { path: ['%2e%2e'] },
    { path: ['account/other'] },
    { path: ['https://evil.test'] },
    { path: [] },
  ])('rejects administrator enrollment path traversal %j', ({ path }) => {
    expect(() => harness(undefined, { enrollment: { ...ENROLLMENT, path } })).toThrow(
      'POLICY_DENIED',
    );
  });

  it('consumes before Vault access, requests the exact version and returns only void', async () => {
    const test = harness();
    const permit = await test.broker.issuePermit(
      test.binding.attemptId,
      'password',
      'enter_password',
    );
    const result = await test.provider.consumePasswordPermit(
      permit.permitId,
      test.binding,
      test.receiver,
    );
    expect(result).toBeUndefined();
    expect(test.tokensRead()).toBe(1);
    expect(test.calls).toHaveLength(1);
    expect(test.calls[0]?.url).toBe(`${ORIGIN}/v1/secret/data/broker/synthetic_account?version=7`);
    expect(test.calls[0]?.options).toMatchObject({
      method: 'GET',
      redirect: 'error',
      cache: 'no-store',
      headers: { 'X-Vault-Token': TOKEN },
    });
    expect(test.broker.consumed).toHaveLength(1);
    expect(test.received).toEqual([{ factor: 'password', value: SYNTHETIC_CREDENTIAL.password }]);
    expect(JSON.stringify({ result, broker: test.broker.events })).not.toContain(
      SYNTHETIC_CREDENTIAL.password,
    );
    await expect(
      test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver),
    ).rejects.toMatchObject({ code: 'POLICY_DENIED' });
    expect(test.calls).toHaveLength(1);
  });

  it('denies a binding mutation before even retrieving the Vault transport credential', async () => {
    const test = harness();
    test.broker.tamper = (permit) => ({ ...permit, credentialBindingVersion: 2 });
    const permit = await test.broker.issuePermit(
      test.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver),
    ).rejects.toMatchObject({ code: 'POLICY_DENIED' });
    expect(test.tokensRead()).toBe(0);
    expect(test.calls).toHaveLength(0);
    expect(test.received).toHaveLength(0);
  });

  it.each([
    { version: 8 },
    { destroyed: true },
    { deletion: '2026-09-30T00:00:00Z' },
    { password: { nested: 'secret' } },
  ])('refuses an unavailable/mismatched exact credential version %j', async (metadata) => {
    const test = harness(async () => response(metadata));
    const permit = await test.broker.issuePermit(
      test.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    expect(test.received).toHaveLength(0);
  });

  it('generates enrolled TOTP immediately before delivery and never sends the seed', async () => {
    let now = 59000;
    const waits: number[] = [];
    const clock: TrustedClock = {
      now: () => now,
      healthy: () => true,
      async wait(milliseconds) {
        waits.push(milliseconds);
        now += milliseconds;
      },
    };
    const totp = { algorithm: 'sha1' as const, digits: 8 as const, period: 30 };
    const test = harness(undefined, { clock, enrollment: { ...ENROLLMENT, totp } });
    const permit = await test.broker.issuePermit(test.binding.attemptId, 'totp', 'enter_totp');
    const result = await test.provider.consumeTotpPermit(
      permit.permitId,
      test.binding,
      test.receiver,
    );
    expect(result).toBeUndefined();
    expect(waits).toEqual([1020]);
    expect(test.received).toEqual([
      { factor: 'totp', value: generateTotp(SYNTHETIC_CREDENTIAL.totpSeed, now, totp) },
    ]);
    expect(test.received[0]?.value).not.toBe(SYNTHETIC_CREDENTIAL.totpSeed);
  });

  it('allows one fetch and private delivery when the same permit races', async () => {
    const test = harness();
    const permit = await test.broker.issuePermit(
      test.binding.attemptId,
      'password',
      'enter_password',
    );
    const outcomes = await Promise.allSettled([
      test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver),
      test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === 'fulfilled')).toHaveLength(1);
    expect(test.calls).toHaveLength(1);
    expect(test.received).toHaveLength(1);
  });

  it('does not follow redirects or copy remote error bodies into outputs', async () => {
    const test = harness(
      async () =>
        new Response(SYNTHETIC_CREDENTIAL.password, {
          status: 302,
          headers: { location: 'https://evil.test/' },
        }),
    );
    const permit = await test.broker.issuePermit(
      test.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED', message: 'AUTH_FAILED' });
    expect(test.calls).toHaveLength(1);
    expect(test.calls[0]?.options.redirect).toBe('error');
    expect(test.received).toHaveLength(0);
  });

  it('scrubs malformed secret-bearing bodies and network errors', async () => {
    for (const fetch of [
      async () =>
        new Response(`invalid-json-${SYNTHETIC_CREDENTIAL.totpSeed}`, {
          headers: { 'content-type': 'application/json' },
        }),
      async () => {
        throw new Error(
          `${TOKEN} ${SYNTHETIC_CREDENTIAL.password} ${SYNTHETIC_CREDENTIAL.totpSeed}`,
        );
      },
    ]) {
      const test = harness(fetch);
      const permit = await test.broker.issuePermit(
        test.binding.attemptId,
        'password',
        'enter_password',
      );
      try {
        await test.provider.consumePasswordPermit(permit.permitId, test.binding, test.receiver);
        throw new Error('EXPECTED_FAILURE');
      } catch (error) {
        expect(error).toMatchObject({ code: 'AUTH_FAILED', message: 'AUTH_FAILED' });
        expect(String(error)).not.toContain(TOKEN);
        expect(String(error)).not.toContain(SYNTHETIC_CREDENTIAL.password);
        expect(String(error)).not.toContain(SYNTHETIC_CREDENTIAL.totpSeed);
      }
      expect(test.received).toHaveLength(0);
    }
  });

  it('aborts before consumption for cancelled input and aborts an in-flight Vault fetch', async () => {
    const cancelled = new AbortController();
    cancelled.abort();
    const test = harness();
    const permit = await test.broker.issuePermit(
      test.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      test.provider.consumePasswordPermit(
        permit.permitId,
        test.binding,
        test.receiver,
        cancelled.signal,
      ),
    ).rejects.toMatchObject({ code: 'INTERACTION_REQUIRED' });
    expect(test.calls).toHaveLength(0);
    expect(test.broker.consumed).toHaveLength(0);
    const stalled = harness(
      async (_url, options) =>
        new Promise((_resolve, reject) => {
          options.signal?.addEventListener('abort', () => reject(new Error(TOKEN)), { once: true });
        }),
      { timeoutMs: 20 },
    );
    const delayedPermit = await stalled.broker.issuePermit(
      stalled.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      stalled.provider.consumePasswordPermit(
        delayedPermit.permitId,
        stalled.binding,
        stalled.receiver,
      ),
    ).rejects.toMatchObject({ code: 'INTERACTION_REQUIRED' });
    expect(stalled.broker.consumed).toHaveLength(1);
    expect(stalled.received).toHaveLength(0);
  });

  it('refuses oversized responses and treats receiver ambiguity as OUTCOME_UNKNOWN', async () => {
    const oversized = harness(
      async () =>
        new Response('x'.repeat(33000), { headers: { 'content-type': 'application/json' } }),
    );
    const permit = await oversized.broker.issuePermit(
      oversized.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      oversized.provider.consumePasswordPermit(
        permit.permitId,
        oversized.binding,
        oversized.receiver,
      ),
    ).rejects.toMatchObject({ code: 'AUTH_FAILED' });
    expect(oversized.received).toHaveLength(0);
    const ambiguous = harness();
    const oneUse = await ambiguous.broker.issuePermit(
      ambiguous.binding.attemptId,
      'password',
      'enter_password',
    );
    await expect(
      ambiguous.provider.consumePasswordPermit(oneUse.permitId, ambiguous.binding, {
        async injectPassword(value) {
          throw new Error(value);
        },
        async injectTotp() {
          throw new Error('UNEXPECTED_FACTOR');
        },
      }),
    ).rejects.toMatchObject({ code: 'OUTCOME_UNKNOWN', message: 'OUTCOME_UNKNOWN' });
  });
});
