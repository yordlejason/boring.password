import { randomUUID } from 'node:crypto';
import {
  TrustedOperationError,
  type BrokerPort,
  type ConsumedPermit,
  type ExecutionBinding,
  type SecretFactor,
  type WorkerFailureCode,
} from '../../services/browser-worker/contracts.js';

export function fakeBinding(destination = 'http://127.0.0.1:3212'): ExecutionBinding {
  return {
    requestId: 'req_synthetic',
    revision: 1,
    attemptId: 'attempt_synthetic',
    executionGeneration: 1,
    workerId: 'worker_synthetic',
    runtimeId: 'runtime_synthetic',
    runtimeGeneration: 1,
    accountId: 'acct_synthetic',
    credentialBindingVersion: 1,
    destination,
    identityProvider: destination,
    relyingParty: destination,
    adapterId: 'synthetic-login',
    adapterVersion: '1.0.0',
    factors: ['password', 'totp'],
    factorPlan: [
      { factor: 'password', step: 'enter_password' },
      { factor: 'totp', step: 'enter_totp' },
    ],
    sessionActionProfile: 'synthetic_read_profile',
    observationProfile: 'synthetic_read_profile',
  };
}

/** Synthetic-only metadata broker. Real policy/replay/lease behavior is tested by core tests. */
export function fakeBroker(
  binding = fakeBinding(),
  now: () => number = Date.now,
): BrokerPort & {
  consumed: ConsumedPermit[];
  delivered: SecretFactor[];
  failures: WorkerFailureCode[];
  events: string[];
  completed: boolean;
  tamper?: (permit: ConsumedPermit) => ConsumedPermit;
} {
  const permits = new Map<string, ConsumedPermit>();
  const used = new Set<string>();
  let active = false;
  const broker = {
    consumed: [] as ConsumedPermit[],
    delivered: [] as SecretFactor[],
    failures: [] as WorkerFailureCode[],
    events: [] as string[],
    completed: false,
    tamper: undefined as ((permit: ConsumedPermit) => ConsumedPermit) | undefined,
    async acquireExecution(requestId: string) {
      if (active || requestId !== binding.requestId)
        throw new TrustedOperationError('POLICY_DENIED');
      active = true;
      broker.events.push('begin');
      return structuredClone(binding);
    },
    async issuePermit(
      attemptId: string,
      factor: SecretFactor,
      adapterStep: 'enter_password' | 'enter_totp',
    ) {
      if (attemptId !== binding.attemptId) throw new TrustedOperationError('POLICY_DENIED');
      const permitId = `permit_${randomUUID()}`;
      permits.set(permitId, {
        ...structuredClone(binding),
        permitId,
        factor,
        adapterStep,
        expiresAt: now() + 60000,
      });
      broker.events.push(`issue_${factor}`);
      return { permitId };
    },
    async consumePermit(
      permitId: string,
      worker: { workerId: string; runtimeId: string; runtimeGeneration: number },
    ) {
      const permit = permits.get(permitId);
      if (
        !permit ||
        used.has(permitId) ||
        permit.expiresAt <= now() ||
        worker.workerId !== binding.workerId ||
        worker.runtimeId !== binding.runtimeId ||
        worker.runtimeGeneration !== binding.runtimeGeneration
      ) {
        throw new TrustedOperationError('POLICY_DENIED');
      }
      used.add(permitId);
      broker.events.push(`consume_${permit.factor}`);
      broker.consumed.push(permit);
      return broker.tamper ? broker.tamper(structuredClone(permit)) : structuredClone(permit);
    },
    async recordSecretDelivered(attemptId: string, factor: SecretFactor) {
      if (attemptId !== binding.attemptId) throw new TrustedOperationError('POLICY_DENIED');
      broker.delivered.push(factor);
      broker.events.push(`delivered_${factor}`);
    },
    async completeExecution(attemptId: string, verification: { verifiedAccountId: string }) {
      if (attemptId !== binding.attemptId || verification.verifiedAccountId !== binding.accountId)
        throw new TrustedOperationError('ACCOUNT_MISMATCH');
      broker.completed = true;
      broker.events.push('complete');
      return { sessionRef: `session_${randomUUID()}` };
    },
    async crashExecution(_attemptId: string, code: WorkerFailureCode) {
      broker.failures.push(code);
      broker.events.push('fail');
    },
  };
  return broker;
}
