import { createPublicKey } from 'node:crypto';
import {
  BrokerController,
  BrokerError,
  sha256,
  type TransactionStore,
  type WorkerIdentity,
  type RiskClassifier,
  type Policy,
} from '../../../packages/core/index.js';
import { SyntheticBrowserWorker } from '../../../services/browser-worker/index.js';
import type {
  BrokerPort,
  ExecutionBinding,
  WorkerFailureCode,
} from '../../../services/browser-worker/contracts.js';
import { syntheticClassifier } from '../../../services/classifier/index.js';
import type { AgentApi } from './gateway.js';
import type { ControlPlane, OwnerPolicySummary } from './http.js';
import type { SettingsFile } from './config.js';

function policySummary(file: SettingsFile, policy: Policy): OwnerPolicySummary {
  const config = file.settings.trusted;
  // Preview the version that choosing Auto would actually publish. Old-version
  // delegations are never silently rebound when an owner switches modes.
  const autoVersion = policy.mode === 'auto' ? policy.version : policy.version + 1;
  const available =
    file.settings.syntheticOnly === true &&
    policy.enabled &&
    Number.isSafeInteger(autoVersion) &&
    config.delegations.some((delegation) => {
      if (
        delegation.revokedAt ||
        !Number.isFinite(Date.parse(delegation.expiresAt)) ||
        Date.parse(delegation.expiresAt) <= Date.now() ||
        delegation.ownerId !== policy.ownerId ||
        delegation.policyId !== policy.id ||
        delegation.policyVersion !== autoVersion ||
        delegation.operation !== 'sign_in' ||
        !Number.isSafeInteger(delegation.maxSessionSeconds) ||
        delegation.maxSessionSeconds <= 0 ||
        delegation.maxSessionSeconds > policy.maxSessionSeconds
      )
        return false;
      const client = config.clients.find(
        (candidate) =>
          candidate.id === delegation.clientId &&
          candidate.ownerId === policy.ownerId &&
          !candidate.revokedAt,
      );
      const account = config.accounts.find(
        (candidate) =>
          candidate.id === delegation.accountId &&
          candidate.ownerId === policy.ownerId &&
          candidate.enabled &&
          candidate.synthetic === true &&
          Number.isSafeInteger(candidate.credentialBindingVersion) &&
          candidate.credentialBindingVersion > 0 &&
          candidate.credentialBindingVersion === delegation.credentialBindingVersion,
      );
      const workload = config.workloads.find(
        (candidate) =>
          candidate.id === delegation.workloadId &&
          candidate.ownerId === policy.ownerId &&
          candidate.clientId === delegation.clientId &&
          candidate.runtimeId === delegation.runtimeId &&
          candidate.enabled,
      );
      const runtime = config.runtimes.find(
        (candidate) =>
          candidate.id === delegation.runtimeId &&
          candidate.ownerId === policy.ownerId &&
          candidate.enabled &&
          candidate.protected &&
          Number.isSafeInteger(candidate.generation) &&
          candidate.generation > 0,
      );
      const adapter = config.adapters.find(
        (candidate) =>
          candidate.id === delegation.adapterId &&
          candidate.version === delegation.adapterVersion &&
          candidate.synthetic === true &&
          candidate.reviewed,
      );
      if (
        !client ||
        !account ||
        !workload ||
        !runtime ||
        !adapter ||
        !file.settings.clients.some(
          (transport) =>
            transport.ownerId === policy.ownerId &&
            transport.clientId === delegation.clientId &&
            transport.workloadId === delegation.workloadId &&
            !transport.revokedAt,
        ) ||
        !adapter.factors.length ||
        new Set(adapter.factors.map((factor) => factor.factor)).size !== adapter.factors.length ||
        adapter.factors.some((factor) => !factor.step) ||
        adapter.factors.length !== delegation.factors.length ||
        !adapter.factors.every((factor, index) => factor.factor === delegation.factors[index])
      )
        return false;
      let destination: URL;
      try {
        destination = new URL(delegation.destination);
      } catch {
        return false;
      }
      if (
        !['https:', 'http:'].includes(destination.protocol) ||
        destination.origin !== delegation.destination ||
        destination.username ||
        destination.password ||
        destination.search ||
        destination.hash ||
        !adapter.allowedOrigins.includes(delegation.destination)
      )
        return false;
      return config.contexts.some(
        (context) =>
          context.enabled &&
          context.ownerId === policy.ownerId &&
          context.clientId === delegation.clientId &&
          context.policyId === policy.id &&
          context.runtimeId === delegation.runtimeId &&
          context.accountIds.includes(delegation.accountId) &&
          context.destination === delegation.destination &&
          context.adapterId === delegation.adapterId &&
          context.adapterVersion === delegation.adapterVersion &&
          context.actionProfile === delegation.actionProfile &&
          context.observationProfile === delegation.observationProfile &&
          adapter.allowedOrigins.includes(context.identityProvider) &&
          adapter.allowedOrigins.includes(context.relyingParty) &&
          config.actionProfiles.some((profile) => profile.id === context.actionProfile),
      );
    });
  return {
    id: policy.id,
    mode: policy.mode,
    version: policy.version,
    enabled: policy.enabled,
    auto_delegation_available: available,
  };
}

export async function createRuntime(
  file: SettingsFile,
  store: TransactionStore,
  origin: string,
  classifier?: RiskClassifier,
) {
  const config = file.settings.trusted;
  const runtime = config.runtimes[0];
  if (
    !runtime ||
    config.runtimes.length !== 1 ||
    config.contexts.some((c) => c.destination !== origin)
  )
    throw new BrokerError('POLICY_DENIED');
  const identity: WorkerIdentity = {
    workerId: runtime.workerId,
    runtimeId: runtime.id,
    runtimeGeneration: runtime.generation,
  };
  const controller = new BrokerController(store, config, {
    brokerId: file.settings.brokerId,
    leaseSeconds: 120,
    classifier: classifier ?? syntheticClassifier(origin),
  });
  await controller.initialize();
  const permitIds = new Map<string, string>();
  const binding = (attempt: ExecutionBinding): ExecutionBinding => ({
    attemptId: attempt.attemptId,
    requestId: attempt.requestId,
    revision: attempt.revision,
    workerId: attempt.workerId,
    runtimeId: attempt.runtimeId,
    runtimeGeneration: attempt.runtimeGeneration,
    executionGeneration: attempt.executionGeneration,
    accountId: attempt.accountId,
    credentialBindingVersion: attempt.credentialBindingVersion,
    destination: attempt.destination,
    identityProvider: attempt.identityProvider,
    relyingParty: attempt.relyingParty,
    adapterId: attempt.adapterId,
    adapterVersion: attempt.adapterVersion,
    factors: attempt.factors,
    factorPlan: attempt.factorPlan,
    sessionActionProfile: attempt.sessionActionProfile,
    observationProfile: attempt.observationProfile,
  });
  const port: BrokerPort = {
    acquireExecution: async (requestId, worker) => {
      file.assertAuthorityReady();
      const attempt = await controller.acquireExecution(requestId, worker);
      file.assertAuthorityReady();
      return binding(attempt);
    },
    issuePermit: async (attemptId, factor, step) => {
      file.assertAuthorityReady();
      const permit = await controller.issuePermit(attemptId, factor, step, identity);
      file.assertAuthorityReady();
      permitIds.set(`${attemptId}:${factor}`, permit.id);
      return { permitId: permit.id };
    },
    consumePermit: async (permitId, worker) => {
      file.assertAuthorityReady();
      const permit = await controller.consumePermit(permitId, worker);
      file.assertAuthorityReady();
      const attempt = await store.transaction((state) => state.attempts[permit.attemptId]);
      if (!attempt) throw new BrokerError('PERMIT_INVALID');
      file.assertAuthorityReady();
      return {
        ...binding(attempt),
        permitId: permit.id,
        factor: permit.factor,
        adapterStep: permit.adapterStep as 'enter_password' | 'enter_totp',
        expiresAt: Date.parse(permit.expiresAt),
      };
    },
    recordSecretDelivered: async (attemptId, factor) => {
      const permitId = permitIds.get(`${attemptId}:${factor}`);
      if (!permitId) throw new BrokerError('PERMIT_INVALID');
      await controller.recordSecretDelivered(permitId, identity);
    },
    completeExecution: async (attemptId, verification) => {
      file.assertAuthorityReady();
      const result = await controller.completeExecution(attemptId, identity, verification);
      file.assertAuthorityReady();
      for (const factor of ['password', 'totp']) permitIds.delete(`${attemptId}:${factor}`);
      return { sessionRef: result.session_ref };
    },
    crashExecution: async (attemptId, reason: WorkerFailureCode) => {
      if (reason === 'OUTCOME_UNKNOWN') await controller.crashExecution(attemptId, identity);
      else
        await controller.failExecution(
          attemptId,
          identity,
          reason === 'POLICY_DENIED' || reason === 'ADAPTER_UNSUPPORTED' ? 'AUTH_FAILED' : reason,
        );
      for (const factor of ['password', 'totp']) permitIds.delete(`${attemptId}:${factor}`);
    },
  };
  const worker = new SyntheticBrowserWorker({ broker: port, origin, ...identity });
  const executions = new Map<string, Promise<unknown>>();
  const execute = (requestId: string) => {
    if (executions.has(requestId)) return;
    const job = worker
      .authenticate(requestId)
      .catch(() => undefined)
      .finally(() => executions.delete(requestId));
    executions.set(requestId, job);
  };
  const api: AgentApi = {
    capabilities: async (caller) => ({
      ...(await controller.capabilities(caller)),
      remote_biometric_approval: config.devices.some(
        (d) =>
          d.ownerId === caller.ownerId &&
          !d.revokedAt &&
          d.assuranceProfile === 'OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE',
      ),
      synthetic_only: true,
      production_credentials_enabled: false,
    }),
    inspect: (caller, target) => controller.inspect(caller, target),
    request: async (caller, input) => {
      file.assertAuthorityReady();
      const result = await controller.request(caller, input);
      file.assertAuthorityReady();
      if (result.state === 'AUTHORIZED') execute(result.request_id);
      return result;
    },
    status: async (caller, id) => {
      const result = await controller.status(caller, id);
      if (result.state === 'AUTHORIZED') execute(id);
      return result;
    },
    cancel: async (caller, id) => {
      const result = await controller.cancel(caller, id);
      if (result.session_ref) await worker.endSession(result.session_ref);
      return result;
    },
    perform: async (caller, session, operation) => {
      file.assertAuthorityReady();
      await controller.authorizeSessionOperation(caller, session, operation, caller.workloadId);
      const result = await worker.readProfile(session);
      await controller.authorizeSessionOperation(caller, session, operation, caller.workloadId);
      file.assertAuthorityReady();
      return {
        account_id: result.accountRef,
        display_name: result.displayName,
        message: 'Synthetic read access verified.',
      };
    },
    end: async (caller, session) => {
      const result = await controller.endSession(caller, session, caller.workloadId);
      await worker.endSession(session);
      return result;
    },
  };
  const control: ControlPlane = {
    overview: async (ownerId) => {
      const requests = await store.transaction((state) =>
        Object.values(state.requests)
          .filter((r) => r.context.ownerId === ownerId)
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
          .slice(0, 50)
          .map((r) => ({
            request_id: r.id,
            state: r.state,
            destination: r.context.destination,
            account_display_name: r.context.accountDisplayName,
            client_display_name: r.context.clientDisplayName,
            purpose: r.context.purpose,
            session_action_profile: r.context.sessionActionProfile,
          })),
      );
      const devices = file.settings.deviceTransports
        .filter((d) => d.ownerId === ownerId)
        .map((d) => ({
          id: d.id,
          name: d.name,
          status: d.status,
          key_fingerprint: sha256(
            createPublicKey(d.publicKeyPem).export({ format: 'der', type: 'spki' }),
          ),
        }));
      return {
        requests,
        devices,
        policies: config.policies
          .filter((p) => p.ownerId === ownerId)
          .map((p) => policySummary(file, p)),
        synthetic_only: true,
        production_credentials_enabled: false,
      };
    },
    setPolicyMode: async (ownerId, policyId, input) => {
      if (ownerId !== file.settings.ownerId) throw new BrokerError('POLICY_DENIED');
      if (
        !['manual', 'safe', 'auto'].includes(input.mode) ||
        !Number.isSafeInteger(input.expected_version) ||
        input.expected_version < 1
      )
        throw new BrokerError('INVALID_ARGUMENT');
      const mutationKey = `policy-mode:${ownerId}:${policyId}:${input.expected_version}:${input.mode}`;
      const updated = await file.update(
        mutationKey,
        (draft) => {
          file.assertSecurityUpdateAllowed(mutationKey);
          const policy = draft.trusted.policies.find(
            (candidate) => candidate.id === policyId && candidate.ownerId === ownerId,
          );
          if (
            draft.syntheticOnly !== true ||
            draft.trusted.accounts.some((account) => account.synthetic !== true) ||
            draft.trusted.adapters.some((adapter) => adapter.synthetic !== true)
          )
            throw new BrokerError('PRODUCTION_CREDENTIALS_DISABLED');
          if (
            !policy?.enabled ||
            policy.version !== input.expected_version ||
            !Number.isSafeInteger(policy.version) ||
            policy.version < 1
          )
            throw new BrokerError('POLICY_DENIED');
          const changed = policy.mode !== input.mode;
          if (changed) {
            if (policy.version >= Number.MAX_SAFE_INTEGER) throw new BrokerError('POLICY_DENIED');
            const previousMode = policy.mode,
              previousVersion = policy.version;
            policy.mode = input.mode;
            policy.version++;
            draft.ownerPolicyChanges = draft.ownerPolicyChanges.slice(-99);
            draft.ownerPolicyChanges.push({
              ownerId,
              policyId,
              previousMode,
              mode: policy.mode,
              previousVersion,
              version: policy.version,
              changedAt: new Date().toISOString(),
            });
          }
          return { policy: { ...policy }, changed };
        },
        async (_draft, result) => {
          if (!result.changed) return;
          const { sessionRefs } = await controller.invalidatePolicy(
            ownerId,
            policyId,
            result.policy.version,
            result.policy.mode,
          );
          for (const session of sessionRefs) await worker.endSession(session);
        },
      );
      return policySummary(file, updated.policy);
    },
    challenges: async (ownerId, deviceId) => {
      file.assertAuthorityReady();
      const pending = await controller.listPending(ownerId),
        challenges = [];
      for (const request of pending) {
        try {
          challenges.push(await controller.createChallenge(ownerId, request.request_id, deviceId));
        } catch {
          /* Changed or expired requests never produce a stale approval. */
        }
      }
      return challenges;
    },
    approve: async (input) => {
      file.assertAuthorityReady();
      const result = await controller.approve(input);
      file.assertAuthorityReady();
      if (result.state === 'AUTHORIZED') execute(result.request_id);
      return result;
    },
    deny: async (ownerId, challengeId, deviceId) => {
      const bound = await store.transaction(
        (state) => state.challenges[challengeId]?.deviceId === deviceId,
      );
      if (!bound) throw new BrokerError('NOT_FOUND');
      await controller.denyChallenge(ownerId, challengeId);
    },
    confirmDevice: async (ownerId, id) => {
      await file.update(`confirm:${ownerId}:${id}`, (draft) => {
        const device = draft.deviceTransports.find(
          (d) => d.id === id && d.ownerId === ownerId && d.status === 'PENDING_CONFIRMATION',
        );
        if (!device) throw new BrokerError('NOT_FOUND');
        const key = createPublicKey(device.publicKeyPem);
        if (
          draft.trusted.devices.some((d) => d.id === id) ||
          key.asymmetricKeyType !== 'ec' ||
          key.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
        )
          throw new BrokerError('INVALID_ARGUMENT');
        draft.trusted.devices.push({
          id: device.id,
          ownerId,
          publicKeyPem: device.publicKeyPem,
          displayName: device.name,
          assuranceProfile: 'OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE',
        });
        device.status = 'ACTIVE';
      });
    },
    revokeDevice: async (ownerId, id) => {
      await file.update(`revoke:${ownerId}:${id}`, (draft) => {
        const device = draft.deviceTransports.find((d) => d.id === id && d.ownerId === ownerId);
        if (!device) throw new BrokerError('NOT_FOUND');
        const approval = draft.trusted.devices.find((d) => d.id === id && d.ownerId === ownerId);
        if (approval) approval.revokedAt = new Date().toISOString();
        device.status = 'REVOKED';
      });
    },
    denyRequest: async (ownerId, id) => {
      const caller = await store.transaction((state) => {
        const r = state.requests[id];
        if (!r || r.context.ownerId !== ownerId) throw new BrokerError('NOT_FOUND');
        return { ownerId, clientId: r.context.clientId, workloadId: r.context.workloadId };
      });
      await controller.cancel(caller, id);
    },
  };
  const cleanup = setInterval(() => {
    void store
      .transaction((state) =>
        Object.values(state.sessions)
          .filter((s) => s.revokedAt || Date.parse(s.expiresAt) <= Date.now())
          .map((s) => s.id),
      )
      .then(async (refs) => {
        for (const ref of refs) await worker.endSession(ref);
      })
      .catch(() => {});
  }, 5000);
  cleanup.unref();
  return {
    controller,
    worker,
    api,
    control,
    waitForExecution: async (id: string) => {
      await executions.get(id);
    },
    close: async () => {
      clearInterval(cleanup);
      await Promise.allSettled([...executions.values()]);
      await worker.close();
      await store.close?.();
    },
  };
}
