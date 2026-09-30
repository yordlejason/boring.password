import { describe, expect, it } from 'vitest';
import type { ConsumedPermit } from '../../services/browser-worker/contracts.js';
import { SyntheticSecretService, type TrustedClock } from '../../services/secret-service/index.js';
import { SYNTHETIC_CREDENTIAL } from '../../services/secret-service/synthetic-fixture.js';
import { generateTotp } from '../../services/secret-service/totp.js';
import { fakeBinding, fakeBroker } from './helpers.js';

function clock(atMs: number, healthy = true): TrustedClock & { waited: number[] } {
  let time = atMs;
  return {
    now: () => time,
    healthy: () => healthy,
    waited: [],
    async wait(milliseconds) {
      this.waited.push(milliseconds);
      time += milliseconds;
    },
  };
}

describe('trusted synthetic secret service', () => {
  it('implements RFC 6238 SHA-1 vectors with enrolled digit/period parameters', () => {
    const parameters = { algorithm: 'sha1' as const, digits: 8 as const, period: 30 };
    for (const [seconds, code] of [
      [59, '94287082'],
      [1111111109, '07081804'],
      [1111111111, '14050471'],
      [1234567890, '89005924'],
      [2000000000, '69279037'],
      [20000000000, '65353130'],
    ] as const) {
      expect(generateTotp(SYNTHETIC_CREDENTIAL.totpSeed, seconds * 1000, parameters)).toBe(code);
    }
  });

  it('consumes a password permit exactly once and returns no plaintext result', async () => {
    const binding = fakeBinding();
    const broker = fakeBroker(binding);
    let received = 0;
    const service = new SyntheticSecretService(broker);
    const channel = service.connectTrustedWorker({
      async injectPassword(value) {
        expect(value).toBe(SYNTHETIC_CREDENTIAL.password);
        received += 1;
      },
      async injectTotp() {
        throw new Error('UNEXPECTED_FACTOR');
      },
    });
    const permit = await broker.issuePermit(binding.attemptId, 'password', 'enter_password');
    expect(await channel.consumePasswordPermit(permit.permitId, binding)).toBeUndefined();
    await expect(channel.consumePasswordPermit(permit.permitId, binding)).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
    expect(received).toBe(1);
  });

  it('waits for sufficient TOTP lifetime and generates only at private delivery', async () => {
    const trustedClock = clock(29000);
    const binding = fakeBinding();
    const broker = fakeBroker(binding, trustedClock.now);
    const service = new SyntheticSecretService(broker, { clock: trustedClock });
    const times: number[] = [];
    const channel = service.connectTrustedWorker({
      async injectPassword() {
        throw new Error('UNEXPECTED_FACTOR');
      },
      async injectTotp(value) {
        expect(broker.consumed).toHaveLength(1);
        expect(value).toBe(
          generateTotp(
            SYNTHETIC_CREDENTIAL.totpSeed,
            trustedClock.now(),
            SYNTHETIC_CREDENTIAL.totp,
          ),
        );
        times.push(trustedClock.now());
      },
    });
    const permit = await broker.issuePermit(binding.attemptId, 'totp', 'enter_totp');
    await channel.consumeTotpPermit(permit.permitId, binding);
    expect(trustedClock.waited).toEqual([1020]);
    expect(times).toEqual([30020]);
    await expect(channel.consumeTotpPermit(permit.permitId, binding)).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
  });

  it('binds a one-use permit by exact metadata regardless of factor-plan object-key order', async () => {
    const binding = fakeBinding();
    const broker = fakeBroker(binding);
    broker.tamper = (permit) => ({
      ...permit,
      factorPlan: permit.factorPlan.map(({ factor, step }) => ({ step, factor })),
    });
    let received = 0;
    const channel = new SyntheticSecretService(broker).connectTrustedWorker({
      async injectPassword() {
        received += 1;
      },
      async injectTotp() {
        throw new Error('UNEXPECTED_FACTOR');
      },
    });
    const permit = await broker.issuePermit(binding.attemptId, 'password', 'enter_password');
    expect(await channel.consumePasswordPermit(permit.permitId, binding)).toBeUndefined();
    expect(received).toBe(1);
    await expect(channel.consumePasswordPermit(permit.permitId, binding)).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
    expect(received).toBe(1);
  });

  it.each([
    ['reversed factor array', { factors: ['totp', 'password'] }],
    ['reversed plan', { factorPlan: [...fakeBinding().factorPlan].reverse() }],
    [
      'missing factor',
      { factorPlan: [{ step: 'enter_password' }, { factor: 'totp', step: 'enter_totp' }] },
    ],
    [
      'missing step',
      { factorPlan: [{ factor: 'password' }, { factor: 'totp', step: 'enter_totp' }] },
    ],
    [
      'extra key',
      {
        factorPlan: [
          { factor: 'password', step: 'enter_password', extra: true },
          { factor: 'totp', step: 'enter_totp' },
        ],
      },
    ],
    [
      'unknown key',
      {
        factorPlan: [
          { factor: 'password', unknown: 'enter_password' },
          { factor: 'totp', step: 'enter_totp' },
        ],
      },
    ],
    [
      'unknown factor',
      {
        factorPlan: [
          { factor: 'recovery', step: 'enter_password' },
          { factor: 'totp', step: 'enter_totp' },
        ],
      },
    ],
    [
      'unknown step',
      {
        factorPlan: [
          { factor: 'password', step: 'enter_recovery' },
          { factor: 'totp', step: 'enter_totp' },
        ],
      },
    ],
    ['missing entry', { factorPlan: [{ factor: 'password', step: 'enter_password' }] }],
    [
      'extra entry',
      { factorPlan: [...fakeBinding().factorPlan, { factor: 'totp', step: 'enter_totp' }] },
    ],
    ['non-array plan', { factorPlan: { factor: 'password', step: 'enter_password' } }],
    ['null entry', { factorPlan: [null, { factor: 'totp', step: 'enter_totp' }] }],
  ])('consumes but refuses %s before private secret delivery', async (_name, changed) => {
    const binding = fakeBinding();
    const broker = fakeBroker(binding);
    broker.tamper = (permit) => ({ ...permit, ...changed }) as ConsumedPermit;
    let received = 0;
    const channel = new SyntheticSecretService(broker).connectTrustedWorker({
      async injectPassword() {
        received += 1;
      },
      async injectTotp() {
        received += 1;
      },
    });
    const permit = await broker.issuePermit(binding.attemptId, 'password', 'enter_password');
    await expect(channel.consumePasswordPermit(permit.permitId, binding)).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
    expect(broker.consumed).toHaveLength(1);
    expect(received).toBe(0);
    await expect(channel.consumePasswordPermit(permit.permitId, binding)).rejects.toMatchObject({
      code: 'POLICY_DENIED',
    });
    expect(received).toBe(0);
  });

  it('blocks an unhealthy clock before consuming or generating', async () => {
    const binding = fakeBinding();
    const broker = fakeBroker(binding);
    const service = new SyntheticSecretService(broker, { clock: clock(10000, false) });
    let released = false;
    const channel = service.connectTrustedWorker({
      async injectPassword() {
        released = true;
      },
      async injectTotp() {
        released = true;
      },
    });
    const permit = await broker.issuePermit(binding.attemptId, 'totp', 'enter_totp');
    await expect(channel.consumeTotpPermit(permit.permitId, binding)).rejects.toMatchObject({
      code: 'INTERACTION_REQUIRED',
    });
    expect(released).toBe(false);
    expect(broker.consumed).toHaveLength(0);
  });

  it.each([
    ['revision', 2],
    ['runtimeGeneration', 2],
    ['executionGeneration', 2],
    ['credentialBindingVersion', 2],
    ['accountId', 'acct_other'],
    ['destination', 'http://127.0.0.1:9999'],
    ['adapterVersion', '2.0.0'],
    ['identityProvider', 'http://127.0.0.1:9999'],
    ['relyingParty', 'http://127.0.0.1:9999'],
    ['observationProfile', 'unrestricted'],
    ['adapterStep', 'enter_totp'],
    ['factor', 'totp'],
    ['sessionActionProfile', 'unrestricted'],
  ])(
    'rejects a consumed permit with mismatched %s without releasing anything',
    async (field, value) => {
      const binding = fakeBinding();
      const broker = fakeBroker(binding);
      broker.tamper = (permit) => ({ ...permit, [field]: value });
      let released = false;
      const service = new SyntheticSecretService(broker);
      const channel = service.connectTrustedWorker({
        async injectPassword() {
          released = true;
        },
        async injectTotp() {
          released = true;
        },
      });
      const permit = await broker.issuePermit(binding.attemptId, 'password', 'enter_password');
      await expect(channel.consumePasswordPermit(permit.permitId, binding)).rejects.toMatchObject({
        code: 'POLICY_DENIED',
      });
      expect(released).toBe(false);
      expect(broker.consumed).toHaveLength(1);
    },
  );

  it('discards raw provider/receiver errors without copying secrets into error output', async () => {
    const binding = fakeBinding();
    const broker = fakeBroker(binding);
    const service = new SyntheticSecretService(broker);
    const channel = service.connectTrustedWorker({
      async injectPassword(value) {
        throw new Error(value);
      },
      async injectTotp() {
        throw new Error(SYNTHETIC_CREDENTIAL.totpSeed);
      },
    });
    const permit = await broker.issuePermit(binding.attemptId, 'password', 'enter_password');
    try {
      await channel.consumePasswordPermit(permit.permitId, binding);
      throw new Error('EXPECTED_FAILURE');
    } catch (error) {
      expect(error).toMatchObject({ code: 'OUTCOME_UNKNOWN', message: 'OUTCOME_UNKNOWN' });
      expect(String(error)).not.toContain(SYNTHETIC_CREDENTIAL.password);
      expect(String(error)).not.toContain(SYNTHETIC_CREDENTIAL.totpSeed);
    }
  });
});
