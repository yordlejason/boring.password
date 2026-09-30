import { describe, expect, it } from 'vitest';
import { authenticateClient, tokenDigest } from '../apps/broker/src/transport-auth.js';
import {
  requestArguments,
  safeError,
  SlidingLimit,
  toolNames,
} from '../apps/broker/src/gateway.js';
describe('agent boundary', () => {
  it('authenticates from transport credentials with a workload binding', () => {
    const token = 'a'.repeat(43),
      client = {
        ownerId: 'owner',
        clientId: 'client',
        workloadId: 'workload',
        tokenHash: tokenDigest(token),
      };
    expect(authenticateClient(`Bearer ${token}`, [client])).toEqual({
      ownerId: 'owner',
      clientId: 'client',
      workloadId: 'workload',
    });
    expect(authenticateClient(`Bearer ${'b'.repeat(43)}`, [client])).toBeUndefined();
    expect(
      authenticateClient(`Bearer ${token}`, [{ ...client, revokedAt: new Date().toISOString() }]),
    ).toBeUndefined();
  });
  it('does not let callers select URLs, selectors, factor plans or runtime identities', () => {
    const input = {
      context_ref: 'ctx',
      account_ref: 'acct',
      operation: 'sign_in',
      workload_ref: 'work',
      purpose: 'test',
      idempotency_key: 'once',
    };
    expect(requestArguments.safeParse(input).success).toBe(true);
    for (const field of [
      'destination',
      'selector',
      'factor_plan',
      'runtime_id',
      'client_id',
      'mode',
    ])
      expect(requestArguments.safeParse({ ...input, [field]: 'attacker' }).success).toBe(false);
  });
  it('provides no administrative or debugging agent tool', () => {
    expect(toolNames).toEqual([
      'auth.capabilities',
      'auth.inspect',
      'auth.request',
      'auth.status',
      'auth.cancel',
      'session.perform',
      'session.end',
    ]);
  });
  it('never serializes raw errors, stack traces or debug state', () => {
    const secret = 'synthetic-error-secret';
    expect(
      JSON.stringify(safeError(Object.assign(new Error(secret), { code: secret, cookie: secret }))),
    ).not.toContain(secret);
    expect(safeError({ code: 'POLICY_DENIED', secret })).toEqual({ error: 'POLICY_DENIED' });
  });
  it('bounds approval spam and releases the limit after its window', () => {
    let now = 0;
    const limit = new SlidingLimit(() => now);
    for (let i = 0; i < 5; i++) limit.check('client-account', 5, 600000);
    expect(() => limit.check('client-account', 5, 600000)).toThrow('RATE_LIMITED');
    now = 600001;
    expect(() => limit.check('client-account', 5, 600000)).not.toThrow();
  });
});
