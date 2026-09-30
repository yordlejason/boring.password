import { generateKeyPairSync, sign } from 'node:crypto';
import { BrokerController, MemoryStore } from '../../packages/core/index.js';
import type {
  Caller,
  ControllerOptions,
  Delegation,
  RequestInput,
  TransactionStore,
  TrustedConfig,
  WorkerIdentity,
} from '../../packages/core/index.js';

export const caller: Caller = {
  ownerId: 'owner_test',
  clientId: 'client_test',
  workloadId: 'workload_test',
};
export const worker: WorkerIdentity = {
  workerId: 'worker_test',
  runtimeId: 'runtime_test',
  runtimeGeneration: 1,
};
export const input: RequestInput = {
  context_ref: 'ctx_test',
  account_ref: 'acct_synthetic',
  operation: 'sign_in',
  workload_ref: 'workload_test',
  purpose: 'Read synthetic repository metadata.',
  idempotency_key: 'key_test',
};
export function fixtureConfig(): TrustedConfig {
  return {
    clients: [
      { id: 'client_test', ownerId: 'owner_test', displayName: 'Synthetic Client' },
      { id: 'client_other', ownerId: 'owner_test', displayName: 'Other Client' },
    ],
    accounts: [
      {
        id: 'acct_synthetic',
        ownerId: 'owner_test',
        displayName: 'Synthetic Account',
        credentialBindingVersion: 1,
        synthetic: true,
        enabled: true,
      },
      {
        id: 'acct_other',
        ownerId: 'owner_test',
        displayName: 'Another Synthetic Account',
        credentialBindingVersion: 1,
        synthetic: true,
        enabled: true,
      },
    ],
    runtimes: [
      {
        id: 'runtime_test',
        ownerId: 'owner_test',
        generation: 1,
        workerId: 'worker_test',
        protected: true,
        enabled: true,
      },
    ],
    workloads: [
      {
        id: 'workload_test',
        ownerId: 'owner_test',
        clientId: 'client_test',
        runtimeId: 'runtime_test',
        enabled: true,
      },
      {
        id: 'workload_other',
        ownerId: 'owner_test',
        clientId: 'client_test',
        runtimeId: 'runtime_test',
        enabled: true,
      },
    ],
    adapters: [
      {
        id: 'synthetic-login',
        version: '1.0.0',
        allowedOrigins: ['http://127.0.0.1:7777'],
        factors: [
          { factor: 'password', step: 'enter_password' },
          { factor: 'totp', step: 'enter_totp' },
        ],
        reviewed: true,
        synthetic: true,
      },
    ],
    policies: [
      {
        id: 'policy_test',
        ownerId: 'owner_test',
        version: 1,
        mode: 'manual',
        enabled: true,
        maxRequestSeconds: 240,
        maxSessionSeconds: 3600,
      },
    ],
    contexts: [
      {
        id: 'ctx_test',
        targetRef: 'target_test',
        ownerId: 'owner_test',
        clientId: 'client_test',
        runtimeId: 'runtime_test',
        accountIds: ['acct_synthetic', 'acct_other'],
        destination: 'http://127.0.0.1:7777',
        identityProvider: 'http://127.0.0.1:7777',
        relyingParty: 'http://127.0.0.1:7777',
        adapterId: 'synthetic-login',
        adapterVersion: '1.0.0',
        policyId: 'policy_test',
        actionProfile: 'synthetic_read_profile',
        observationProfile: 'synthetic_read_observation',
        enabled: true,
      },
    ],
    devices: [],
    delegations: [],
    actionProfiles: [{ id: 'synthetic_read_profile', operations: ['synthetic.list_resources'] }],
  };
}
export function delegation(): Delegation {
  return {
    id: 'delegation_test',
    ownerId: 'owner_test',
    clientId: 'client_test',
    accountId: 'acct_synthetic',
    destination: 'http://127.0.0.1:7777',
    adapterId: 'synthetic-login',
    adapterVersion: '1.0.0',
    operation: 'sign_in',
    factors: ['password', 'totp'],
    actionProfile: 'synthetic_read_profile',
    observationProfile: 'synthetic_read_observation',
    workloadId: 'workload_test',
    runtimeId: 'runtime_test',
    policyId: 'policy_test',
    policyVersion: 1,
    credentialBindingVersion: 1,
    maxSessionSeconds: 60,
    expiresAt: '2099-01-01T00:00:00.000Z',
  };
}
export function harness(
  options: Partial<ControllerOptions> = {},
  store: TransactionStore = new MemoryStore(),
) {
  const config = fixtureConfig(),
    key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  config.devices.push({
    id: 'device_test',
    ownerId: 'owner_test',
    publicKeyPem: key.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    displayName: 'Synthetic Approval Key',
    assuranceProfile: 'SYNTHETIC_TEST_KEY',
  });
  const controller = new BrokerController(store, config, {
    brokerId: 'broker_test',
    bootEpoch: 'boot_test',
    ...options,
  });
  async function approved(requestInput: RequestInput = input) {
    const request = await controller.request(caller, requestInput);
    const challenge = await controller.createChallenge(
      caller.ownerId,
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
    await controller.approve(approval);
    return { request, challenge, approval };
  }
  async function successfulSession() {
    const { request } = await approved();
    const attempt = await controller.acquireExecution(request.request_id, worker);
    for (const step of attempt.factorPlan) {
      const permit = await controller.issuePermit(
        attempt.attemptId,
        step.factor,
        step.step,
        worker,
      );
      await controller.consumePermit(permit.id, worker);
      await controller.recordSecretDelivered(permit.id, worker);
    }
    const session = await controller.completeExecution(attempt.attemptId, worker, {
      verifiedAccountId: 'acct_synthetic',
    });
    return { request, attempt, session };
  }
  return { controller, config, store, key, approved, successfulSession };
}
