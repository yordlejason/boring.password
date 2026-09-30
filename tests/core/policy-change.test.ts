import { sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { caller, harness, input, worker } from './fixtures.js';

describe('owner policy changes retire existing authority', () => {
  it('retires pending challenges without converting them into a fresh approval', async () => {
    const h = harness();
    const request = await h.controller.request(caller, input);
    const challenge = await h.controller.createChallenge(
      caller.ownerId,
      request.request_id,
      'device_test',
    );
    const signature = sign(
      'sha256',
      Buffer.from(challenge.payload_base64, 'base64'),
      h.key.privateKey,
    ).toString('base64');
    await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'safe');
    Object.assign(h.config.policies[0]!, { version: 2, mode: 'safe' });
    expect(await h.controller.status(caller, request.request_id)).toMatchObject({
      state: 'CANCELLED',
      reason: 'POLICY_DENIED',
    });
    await expect(
      h.controller.approve({
        challenge_id: challenge.challenge_id,
        device_id: 'device_test',
        signature_base64: signature,
      }),
    ).rejects.toBeDefined();
    const state = await h.store.transaction((state) => structuredClone(state));
    expect(state.challenges[challenge.challenge_id]!.invalidatedAt).toBeDefined();
    expect(state.challenges[challenge.challenge_id]!.consumedAt).toBeUndefined();
    expect(Object.values(state.permits)).toHaveLength(0);
    const audits = state.audit.length;
    await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'safe');
    expect(await h.store.transaction((state) => state.audit.length)).toBe(audits);
  });

  it('closes an authorized request and an unused execution permit without quarantining', async () => {
    const h = harness();
    const { request } = await h.approved();
    const attempt = await h.controller.acquireExecution(request.request_id, worker);
    const permit = await h.controller.issuePermit(
      attempt.attemptId,
      'password',
      'enter_password',
      worker,
    );
    await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'safe');
    Object.assign(h.config.policies[0]!, { version: 2, mode: 'safe' });
    await expect(h.controller.consumePermit(permit.id, worker)).rejects.toBeDefined();
    expect(await h.controller.failExecution(attempt.attemptId, worker)).toMatchObject({
      state: 'CANCELLED',
    });
    const state = await h.store.transaction((state) => structuredClone(state));
    expect(state.attempts[attempt.attemptId]!.state).toBe('CANCELLED');
    expect(state.permits[permit.id]!.invalidatedAt).toBeDefined();
    expect(state.requests[request.request_id]!.possibleDelivery).toBe(false);
    expect(state.quarantinedRuntimes[worker.runtimeId]).toBeUndefined();
    await expect(h.controller.acquireExecution(request.request_id, worker)).rejects.toBeDefined();
  });

  it('quarantines a consumed permit and never reopens the uncertain attempt', async () => {
    const h = harness();
    const { request } = await h.approved();
    const attempt = await h.controller.acquireExecution(request.request_id, worker);
    const permit = await h.controller.issuePermit(
      attempt.attemptId,
      'password',
      'enter_password',
      worker,
    );
    await h.controller.consumePermit(permit.id, worker);
    await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'auto');
    Object.assign(h.config.policies[0]!, { version: 2, mode: 'auto' });
    expect(await h.controller.failExecution(attempt.attemptId, worker)).toMatchObject({
      state: 'OUTCOME_UNKNOWN',
      reason: 'OUTCOME_UNKNOWN',
    });
    await expect(
      h.controller.completeExecution(attempt.attemptId, worker, {
        verifiedAccountId: 'acct_synthetic',
      }),
    ).rejects.toBeDefined();
    await expect(
      h.controller.failExecution(attempt.attemptId, { ...worker, workerId: 'another_worker' }),
    ).rejects.toMatchObject({ code: 'PERMIT_INVALID' });
    const state = await h.store.transaction((state) => structuredClone(state));
    expect(state.attempts[attempt.attemptId]!.state).toBe('OUTCOME_UNKNOWN');
    expect(state.quarantinedRuntimes[worker.runtimeId]).toBe(true);
    expect(Object.values(state.sessions)).toHaveLength(0);
    await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'auto');
    expect((await h.controller.status(caller, request.request_id)).state).toBe('OUTCOME_UNKNOWN');
  });

  it('revokes prior sessions and returns private cleanup handles on a repeated fence', async () => {
    const h = harness();
    const { session } = await h.successfulSession();
    expect(await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'safe')).toEqual({
      sessionRefs: [session.session_ref],
    });
    Object.assign(h.config.policies[0]!, { version: 2, mode: 'safe' });
    await expect(
      h.controller.authorizeSessionOperation(
        caller,
        session.session_ref,
        'synthetic.list_resources',
      ),
    ).rejects.toMatchObject({ code: 'SESSION_EXPIRED' });
    const audits = await h.store.transaction((state) => state.audit.length);
    expect(await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 2, 'safe')).toEqual({
      sessionRefs: [session.session_ref],
    });
    expect(await h.store.transaction((state) => state.audit.length)).toBe(audits);
  });

  it('failure cleanup may retire its exact active attempt after a changed source policy', async () => {
    const h = harness();
    const { request } = await h.approved();
    const attempt = await h.controller.acquireExecution(request.request_id, worker);
    Object.assign(h.config.policies[0]!, { version: 2, mode: 'safe' });
    expect(await h.controller.failExecution(attempt.attemptId, worker)).toMatchObject({
      state: 'FAILED',
    });
    expect(await h.controller.failExecution(attempt.attemptId, worker)).toMatchObject({
      state: 'FAILED',
    });
    await expect(
      h.controller.issuePermit(attempt.attemptId, 'password', 'enter_password', worker),
    ).rejects.toBeDefined();
  });

  it('does not retire another owner/policy or an already current request', async () => {
    const h = harness();
    const request = await h.controller.request(caller, input);
    await expect(
      h.controller.invalidatePolicy('owner_other', 'policy_test', 2, 'safe'),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await h.controller.invalidatePolicy(caller.ownerId, 'policy_test', 1, 'manual');
    expect((await h.controller.status(caller, request.request_id)).state).toBe('AWAITING_APPROVAL');
    expect(h.config.delegations).toHaveLength(0);
  });
});
