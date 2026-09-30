import { createPublicKey, randomBytes, randomUUID, verify } from 'node:crypto';
import { z } from 'zod';
import { canonicalBytes, canonicalDigest, sha256 } from './canonical.js';
import { BrokerError } from './types.js';
import type {
  ApprovalChallenge,
  ApprovalDevice,
  AuditEvent,
  AuditEventName,
  AuthRequest,
  BrokerState,
  Caller,
  ControllerOptions,
  Delegation,
  ErrorCode,
  ExecutionAttempt,
  Factor,
  Mode,
  ProtectedSession,
  RequestContext,
  RequestInput,
  RequestState,
  SafeStatus,
  SecretPermit,
  TransactionStore,
  TrustedConfig,
  WorkerIdentity,
} from './types.js';

const ref = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[a-zA-Z0-9_.:@-]+$/);
export const requestSchema = z
  .object({
    context_ref: ref,
    account_ref: ref,
    operation: z.literal('sign_in'),
    workload_ref: ref,
    purpose: z.string().min(1).max(1000),
    idempotency_key: ref,
  })
  .strict();
const classifierResult = z
  .object({
    classification: z.literal('safe'),
    reason_codes: z.array(z.string().max(80)).max(20),
    uncertainties: z.array(z.string().max(200)).max(20),
  })
  .strict();
const terminal = new Set<RequestState>([
  'SUCCEEDED',
  'DENIED',
  'FAILED',
  'EXPIRED',
  'CANCELLED',
  'INTERACTION_REQUIRED',
  'OUTCOME_UNKNOWN',
]);
const allowedTransitions: Record<RequestState, RequestState[]> = {
  CREATED: ['INSPECTING', 'DENIED', 'EXPIRED', 'CANCELLED'],
  INSPECTING: ['POLICY_EVALUATING', 'DENIED', 'CANCELLED', 'EXPIRED'],
  POLICY_EVALUATING: [
    'CLASSIFYING',
    'AWAITING_APPROVAL',
    'AUTHORIZED',
    'DENIED',
    'CANCELLED',
    'EXPIRED',
  ],
  CLASSIFYING: ['AWAITING_APPROVAL', 'DENIED', 'CANCELLED', 'EXPIRED'],
  AWAITING_APPROVAL: ['AUTHORIZED', 'DENIED', 'CANCELLED', 'EXPIRED'],
  AUTHORIZED: ['EXECUTING', 'DENIED', 'CANCELLED', 'EXPIRED'],
  EXECUTING: [
    'AUTHORIZED',
    'VERIFYING',
    'FAILED',
    'CANCELLED',
    'EXPIRED',
    'INTERACTION_REQUIRED',
    'OUTCOME_UNKNOWN',
  ],
  VERIFYING: ['SUCCEEDED', 'FAILED', 'CANCELLED', 'EXPIRED', 'OUTCOME_UNKNOWN'],
  SUCCEEDED: [],
  DENIED: [],
  FAILED: [],
  EXPIRED: [],
  CANCELLED: [],
  INTERACTION_REQUIRED: [],
  OUTCOME_UNKNOWN: [],
};
function id(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}
function reject(code: ErrorCode): never {
  throw new BrokerError(code);
}
function sameWorker(binding: WorkerIdentity, worker: WorkerIdentity): boolean {
  return (
    binding.workerId === worker.workerId &&
    binding.runtimeId === worker.runtimeId &&
    binding.runtimeGeneration === worker.runtimeGeneration
  );
}

/** The controller accepts identity derived by the gateway, never agent-chosen authority.
 * Administrative calls are deliberately absent from the MCP tool registry. */
export class BrokerController {
  readonly brokerId: string;
  readonly bootEpoch: string;
  private readonly ready: Promise<void>;
  private readonly clock: () => Date;
  constructor(
    readonly store: TransactionStore,
    readonly config: TrustedConfig,
    private readonly options: ControllerOptions,
  ) {
    this.brokerId = options.brokerId;
    this.bootEpoch = options.bootEpoch ?? id('boot');
    this.clock = options.clock ?? (() => new Date());
    this.ready = this.restart();
  }
  async initialize(): Promise<void> {
    await this.ready;
  }
  private now(): string {
    return this.clock().toISOString();
  }
  private expired(timestamp: string): boolean {
    return Date.parse(timestamp) <= this.clock().getTime();
  }
  private until(seconds: number, limit?: string): string {
    return new Date(
      Math.min(this.clock().getTime() + seconds * 1000, limit ? Date.parse(limit) : Infinity),
    ).toISOString();
  }
  private transition(request: AuthRequest, state: RequestState, reason?: ErrorCode): void {
    if (request.state !== state && !allowedTransitions[request.state].includes(state))
      reject('INVALID_STATE');
    request.state = state;
    request.updatedAt = this.now();
    if (reason) request.reason = reason;
  }
  private audit(
    state: BrokerState,
    event: AuditEventName,
    metadata: Partial<AuditEvent> = {},
  ): void {
    // Build every field explicitly. Even trusted internal callers cannot append debug objects.
    const value: AuditEvent = { id: id('audit'), event, timestamp: this.now() };
    for (const key of [
      'requestId',
      'revision',
      'ownerId',
      'clientId',
      'accountId',
      'destination',
      'mode',
      'deviceId',
      'attemptId',
      'permitId',
      'factor',
      'reason',
      'sessionRef',
      'operation',
      'authorizationKind',
    ] as const) {
      if (metadata[key] !== undefined) Object.assign(value, { [key]: metadata[key] });
    }
    state.audit.push(value);
  }
  private requestAudit(request: AuthRequest): Partial<AuditEvent> {
    return {
      requestId: request.id,
      revision: request.revision,
      ownerId: request.context.ownerId,
      clientId: request.context.clientId,
      accountId: request.context.accountId,
      destination: request.context.destination,
      mode: request.context.mode,
    };
  }
  private caller(caller: Caller): void {
    const client = this.config.clients.find(
      (c) => c.id === caller.clientId && c.ownerId === caller.ownerId && !c.revokedAt,
    );
    if (!client) reject('CALLER_MISMATCH');
  }
  private ownedRequest(state: BrokerState, caller: Caller, requestId: string): AuthRequest {
    this.caller(caller);
    const request = state.requests[requestId];
    if (
      !request ||
      request.context.ownerId !== caller.ownerId ||
      request.context.clientId !== caller.clientId ||
      (caller.workloadId && request.context.workloadId !== caller.workloadId)
    )
      reject('NOT_FOUND');
    return request;
  }
  private resolve(caller: Caller, input: RequestInput): RequestContext {
    this.caller(caller);
    const context = this.config.contexts.find(
      (c) =>
        c.id === input.context_ref &&
        c.ownerId === caller.ownerId &&
        c.clientId === caller.clientId &&
        c.enabled,
    );
    const account = this.config.accounts.find(
      (a) => a.id === input.account_ref && a.ownerId === caller.ownerId && a.enabled,
    );
    const workload = this.config.workloads.find(
      (w) =>
        w.id === input.workload_ref &&
        w.ownerId === caller.ownerId &&
        w.clientId === caller.clientId &&
        w.enabled,
    );
    if (
      !context ||
      !account ||
      !workload ||
      !context.accountIds.includes(account.id) ||
      (caller.workloadId && caller.workloadId !== workload.id)
    )
      reject('POLICY_DENIED');
    if (account.synthetic !== true) reject('PRODUCTION_CREDENTIALS_DISABLED');
    const runtime = this.config.runtimes.find(
      (r) =>
        r.id === context.runtimeId &&
        r.id === workload.runtimeId &&
        r.ownerId === caller.ownerId &&
        r.enabled &&
        r.protected,
    );
    const policy = this.config.policies.find(
      (p) => p.id === context.policyId && p.ownerId === caller.ownerId && p.enabled,
    );
    const adapter = this.config.adapters.find(
      (a) => a.id === context.adapterId && a.version === context.adapterVersion && a.reviewed,
    );
    if (
      !runtime ||
      !policy ||
      !Number.isSafeInteger(runtime.generation) ||
      runtime.generation < 1 ||
      !Number.isSafeInteger(policy.version) ||
      policy.version < 1 ||
      account.credentialBindingVersion < 1 ||
      policy.maxRequestSeconds <= 0 ||
      policy.maxSessionSeconds <= 0
    )
      reject('POLICY_DENIED');
    if (!adapter || adapter.synthetic !== true) reject('ADAPTER_UNSUPPORTED');
    let origin: string;
    try {
      const url = new URL(context.destination);
      if (
        !['https:', 'http:'].includes(url.protocol) ||
        url.username ||
        url.password ||
        url.pathname !== '/' ||
        url.search ||
        url.hash
      )
        reject('DESTINATION_MISMATCH');
      origin = url.origin;
    } catch {
      reject('DESTINATION_MISMATCH');
    }
    if (
      !adapter.allowedOrigins.includes(origin!) ||
      context.destination !== origin! ||
      !adapter.allowedOrigins.includes(context.identityProvider) ||
      !adapter.allowedOrigins.includes(context.relyingParty)
    )
      reject('DESTINATION_MISMATCH');
    if (
      !adapter.factors.length ||
      adapter.factors.some((s) => !['password', 'totp'].includes(s.factor) || !s.step) ||
      new Set(adapter.factors.map((s) => s.factor)).size !== adapter.factors.length
    )
      reject('ADAPTER_UNSUPPORTED');
    const actionProfile = this.config.actionProfiles.find((p) => p.id === context.actionProfile);
    if (!actionProfile) reject('POLICY_DENIED');
    const client = this.config.clients.find((c) => c.id === caller.clientId)!;
    return {
      ownerId: caller.ownerId,
      clientId: caller.clientId,
      clientDisplayName: client.displayName,
      workloadId: workload.id,
      runtimeId: runtime.id,
      runtimeGeneration: runtime.generation,
      workerId: runtime.workerId,
      contextId: context.id,
      accountId: account.id,
      accountDisplayName: account.displayName,
      credentialBindingVersion: account.credentialBindingVersion,
      destination: origin!,
      identityProvider: context.identityProvider,
      relyingParty: context.relyingParty,
      operation: input.operation,
      adapterId: adapter.id,
      adapterVersion: adapter.version,
      factorPlan: structuredClone(adapter.factors),
      sessionActionProfile: context.actionProfile,
      actionProfileDigest: canonicalDigest(actionProfile),
      observationProfile: context.observationProfile,
      policyId: policy.id,
      policyVersion: policy.version,
      mode: policy.mode,
      maxSessionSeconds: policy.maxSessionSeconds,
      purpose: input.purpose,
    };
  }
  private validateCurrent(request: AuthRequest, state: BrokerState): void {
    if (state.bootEpoch !== this.bootEpoch) reject('APPROVAL_INVALID');
    if (this.expired(request.expiresAt)) reject('REQUEST_EXPIRED');
    const current = this.resolve(
      { ownerId: request.context.ownerId, clientId: request.context.clientId },
      {
        context_ref: request.context.contextId,
        account_ref: request.context.accountId,
        operation: request.context.operation,
        workload_ref: request.context.workloadId,
        purpose: request.context.purpose,
        idempotency_key: request.idempotencyKey,
      },
    );
    if (canonicalDigest(current) !== request.contextDigest) reject('POLICY_DENIED');
    if (state.quarantinedRuntimes[request.context.runtimeId]) reject('RUNTIME_QUARANTINED');
  }
  private matchingDelegation(request: AuthRequest): Delegation | undefined {
    const c = request.context;
    return this.config.delegations.find(
      (d) =>
        !d.revokedAt &&
        !this.expired(d.expiresAt) &&
        d.ownerId === c.ownerId &&
        d.clientId === c.clientId &&
        d.accountId === c.accountId &&
        d.destination === c.destination &&
        d.adapterId === c.adapterId &&
        d.adapterVersion === c.adapterVersion &&
        d.operation === c.operation &&
        canonicalDigest(d.factors) === canonicalDigest(c.factorPlan.map((s) => s.factor)) &&
        d.actionProfile === c.sessionActionProfile &&
        d.observationProfile === c.observationProfile &&
        d.workloadId === c.workloadId &&
        d.runtimeId === c.runtimeId &&
        d.policyId === c.policyId &&
        d.policyVersion === c.policyVersion &&
        d.credentialBindingVersion === c.credentialBindingVersion &&
        d.maxSessionSeconds > 0 &&
        d.maxSessionSeconds <= c.maxSessionSeconds,
    );
  }
  private validateAuthorization(request: AuthRequest, state: BrokerState): void {
    this.validateCurrent(request, state);
    const authorization = request.authorization;
    if (!authorization || authorization.bootEpoch !== this.bootEpoch) reject('APPROVAL_REQUIRED');
    if (authorization.kind === 'OWNER_DEVICE') {
      const device = this.config.devices.find(
        (d) =>
          d.id === authorization.deviceId && d.ownerId === request.context.ownerId && !d.revokedAt,
      );
      const challenge = state.challenges[authorization.challengeId ?? ''];
      if (
        !device ||
        !challenge?.consumedAt ||
        challenge.invalidatedAt ||
        challenge.revision !== request.revision ||
        challenge.contextDigest !== request.contextDigest
      )
        reject('APPROVAL_INVALID');
    } else if (this.matchingDelegation(request)?.id !== authorization.delegationId)
      reject('POLICY_DENIED');
  }
  private statusValue(request: AuthRequest): SafeStatus {
    const result: SafeStatus = {
      request_id: request.id,
      revision: request.revision,
      state: request.state,
      next_action:
        request.state === 'AWAITING_APPROVAL'
          ? 'APPROVE'
          : terminal.has(request.state)
            ? 'NONE'
            : 'WAIT',
    };
    if (request.reason) result.reason = request.reason;
    if (request.sessionRef && request.state === 'SUCCEEDED')
      result.session_ref = request.sessionRef;
    return result;
  }
  private invalidate(state: BrokerState, requestId: string): void {
    for (const challenge of Object.values(state.challenges))
      if (challenge.requestId === requestId && !challenge.consumedAt)
        challenge.invalidatedAt = this.now();
    for (const permit of Object.values(state.permits))
      if (permit.requestId === requestId && !permit.consumedAt) permit.invalidatedAt = this.now();
  }
  private async restart(): Promise<void> {
    await this.store.transaction((state) => {
      if (state.bootEpoch === this.bootEpoch) return;
      const restoring = state.bootEpoch !== undefined;
      for (const request of Object.values(state.requests)) {
        if (terminal.has(request.state)) continue;
        const consumed = Object.values(state.permits).some(
          (p) => p.requestId === request.id && p.consumedAt,
        );
        if (consumed || request.possibleDelivery || request.deliveredFactors.length) {
          request.state = 'OUTCOME_UNKNOWN';
          request.reason = 'OUTCOME_UNKNOWN';
          state.quarantinedRuntimes[request.context.runtimeId] = true;
        } else {
          request.state = 'CANCELLED';
          request.reason = 'APPROVAL_INVALID';
        }
        request.updatedAt = this.now();
        this.invalidate(state, request.id);
      }
      for (const challenge of Object.values(state.challenges)) challenge.invalidatedAt = this.now();
      for (const permit of Object.values(state.permits)) permit.invalidatedAt = this.now();
      for (const attempt of Object.values(state.attempts))
        if (attempt.state === 'ACTIVE')
          attempt.state =
            state.requests[attempt.requestId]?.state === 'OUTCOME_UNKNOWN'
              ? 'OUTCOME_UNKNOWN'
              : 'CANCELLED';
      for (const session of Object.values(state.sessions)) session.revokedAt = this.now();
      state.bootEpoch = this.bootEpoch;
      if (restoring) this.audit(state, 'BROKER_RESTARTED');
    });
  }
  async capabilities(caller: Caller): Promise<Record<string, boolean>> {
    await this.ready;
    this.caller(caller);
    return {
      protected_browser: true,
      password: true,
      totp: true,
      remote_biometric_approval: true,
      native_macos_auth: false,
      oauth: false,
      production_credentials: false,
    };
  }
  async inspect(
    caller: Caller,
    targetRef: string,
  ): Promise<{
    context_ref: string;
    authentication_required: true;
    destination: string;
    supported_accounts: Array<{ account_ref: string; display_name: string }>;
  }> {
    await this.ready;
    this.caller(caller);
    const context = this.config.contexts.find(
      (c) =>
        c.targetRef === targetRef &&
        c.ownerId === caller.ownerId &&
        c.clientId === caller.clientId &&
        c.enabled,
    );
    if (!context) reject('NOT_FOUND');
    return {
      context_ref: context.id,
      authentication_required: true,
      destination: context.destination,
      supported_accounts: this.config.accounts
        .filter(
          (a) =>
            context.accountIds.includes(a.id) &&
            a.ownerId === caller.ownerId &&
            a.enabled &&
            a.synthetic === true,
        )
        .map((a) => ({ account_ref: a.id, display_name: a.displayName })),
    };
  }
  async request(caller: Caller, raw: RequestInput): Promise<SafeStatus> {
    await this.ready;
    const parsed = requestSchema.safeParse(raw);
    if (!parsed.success) reject('INVALID_ARGUMENT');
    const input = parsed.data;
    const result = await this.store.transaction((state) => {
      if (state.bootEpoch !== this.bootEpoch) reject('APPROVAL_INVALID');
      const context = this.resolve(caller, input),
        digest = canonicalDigest({ input, context });
      const previous = Object.values(state.requests).find(
        (r) =>
          r.context.ownerId === caller.ownerId &&
          r.context.clientId === caller.clientId &&
          r.idempotencyKey === input.idempotency_key,
      );
      if (previous) {
        if (previous.inputDigest !== digest) reject('IDEMPOTENCY_CONFLICT');
        return { request: previous, created: false };
      }
      const policy = this.config.policies.find((p) => p.id === context.policyId)!;
      const request: AuthRequest = {
        id: id('req'),
        revision: 1,
        state: 'CREATED',
        context,
        contextDigest: canonicalDigest(context),
        inputDigest: digest,
        idempotencyKey: input.idempotency_key,
        createdAt: this.now(),
        expiresAt: this.until(policy.maxRequestSeconds),
        updatedAt: this.now(),
        executionGeneration: 0,
        deliveredFactors: [],
        possibleDelivery: false,
      };
      state.requests[request.id] = request;
      this.transition(request, 'INSPECTING');
      this.transition(request, 'POLICY_EVALUATING');
      if (state.quarantinedRuntimes[context.runtimeId])
        this.transition(request, 'DENIED', 'RUNTIME_QUARANTINED');
      else if (context.mode === 'manual') this.transition(request, 'AWAITING_APPROVAL');
      else if (context.mode === 'safe') this.transition(request, 'CLASSIFYING');
      else if (context.mode === 'auto') {
        const delegation = this.matchingDelegation(request);
        if (!delegation) this.transition(request, 'DENIED', 'POLICY_DENIED');
        else {
          request.authorization = {
            kind: 'DELEGATED_AUTO',
            delegationId: delegation.id,
            bootEpoch: this.bootEpoch,
          };
          this.transition(request, 'AUTHORIZED');
        }
      } else this.transition(request, 'DENIED', 'POLICY_DENIED');
      this.audit(state, 'AUTH_REQUEST_CREATED', this.requestAudit(request));
      if (request.state === 'DENIED')
        this.audit(state, 'AUTH_REQUEST_DENIED', {
          ...this.requestAudit(request),
          reason: request.reason,
        });
      return { request, created: true };
    });
    if (result.created && result.request.state === 'CLASSIFYING')
      await this.classify(result.request);
    return this.status(caller, result.request.id);
  }
  private async classify(request: AuthRequest): Promise<void> {
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let safe = false;
    try {
      if (this.options.classifier) {
        const timeout = new Promise<never>((_, rejectTimeout) => {
          timer = setTimeout(() => {
            abort.abort();
            rejectTimeout(new Error('CLASSIFIER_TIMEOUT'));
          }, this.options.classifierTimeoutMs ?? 1500);
        });
        const output = await Promise.race([
          this.options.classifier(
            {
              destination: request.context.destination,
              operation: request.context.operation,
              factors: request.context.factorPlan.map((s) => s.factor),
              action_profile: request.context.sessionActionProfile,
              purpose: request.context.purpose,
            },
            abort.signal,
          ),
          timeout,
        ]);
        const parsed = classifierResult.safeParse(output);
        safe = parsed.success && parsed.data.uncertainties.length === 0;
      }
    } catch {
      safe = false;
    } finally {
      if (timer) clearTimeout(timer);
      abort.abort();
    }
    await this.store.transaction((state) => {
      const current = state.requests[request.id];
      if (!current || current.state !== 'CLASSIFYING' || current.revision !== request.revision)
        return;
      try {
        this.validateCurrent(current, state);
      } catch {
        safe = false;
      }
      this.transition(
        current,
        safe ? 'AWAITING_APPROVAL' : 'DENIED',
        safe ? undefined : 'CLASSIFIER_BLOCKED',
      );
      if (!safe)
        this.audit(state, 'AUTH_REQUEST_DENIED', {
          ...this.requestAudit(current),
          reason: 'CLASSIFIER_BLOCKED',
        });
    });
  }
  async status(caller: Caller, requestId: string): Promise<SafeStatus> {
    await this.ready;
    return this.store.transaction((state) => {
      const request = this.ownedRequest(state, caller, requestId);
      if (!terminal.has(request.state) && this.expired(request.expiresAt)) {
        if (request.possibleDelivery) {
          request.state = 'OUTCOME_UNKNOWN';
          request.reason = 'OUTCOME_UNKNOWN';
          state.quarantinedRuntimes[request.context.runtimeId] = true;
        } else this.transition(request, 'EXPIRED', 'REQUEST_EXPIRED');
        this.invalidate(state, request.id);
        for (const attempt of Object.values(state.attempts))
          if (attempt.requestId === request.id && attempt.state === 'ACTIVE')
            attempt.state = request.possibleDelivery ? 'OUTCOME_UNKNOWN' : 'FAILED';
      }
      return this.statusValue(request);
    });
  }
  async cancel(
    caller: Caller,
    requestId: string,
  ): Promise<SafeStatus & { credential_delivery: string; delivered_factors: Factor[] }> {
    await this.ready;
    return this.store.transaction((state) => {
      const request = this.ownedRequest(state, caller, requestId);
      if (!terminal.has(request.state)) {
        this.transition(request, 'CANCELLED');
        this.invalidate(state, request.id);
        for (const attempt of Object.values(state.attempts))
          if (attempt.requestId === request.id && attempt.state === 'ACTIVE')
            attempt.state = 'CANCELLED';
        if (request.possibleDelivery) state.quarantinedRuntimes[request.context.runtimeId] = true;
        this.audit(state, 'AUTH_REQUEST_CANCELLED', this.requestAudit(request));
      }
      if (request.sessionRef && state.sessions[request.sessionRef])
        state.sessions[request.sessionRef]!.revokedAt = this.now();
      return {
        ...this.statusValue(request),
        credential_delivery: request.deliveredFactors.length
          ? `${request.deliveredFactors.map((f) => f.toUpperCase()).join('_AND_')}_ALREADY_DELIVERED`
          : request.possibleDelivery
            ? 'POSSIBLY_DELIVERED'
            : 'NOT_DELIVERED',
        delivered_factors: [...request.deliveredFactors],
      };
    });
  }

  /** Owner-side policy fencing, called after durable settings preparation and
   * before publishing the new policy. No approval or delegation is created.
   * Returned session references are private cleanup handles, never UI output. */
  async invalidatePolicy(
    ownerId: string,
    policyId: string,
    nextVersion: number,
    nextMode: Mode,
  ): Promise<{ sessionRefs: string[] }> {
    await this.ready;
    const policy = this.config.policies.find((p) => p.id === policyId && p.ownerId === ownerId);
    if (!policy) reject('NOT_FOUND');
    if (
      !Number.isSafeInteger(nextVersion) ||
      nextVersion < policy.version ||
      !['manual', 'safe', 'auto'].includes(nextMode)
    )
      reject('INVALID_ARGUMENT');
    return this.store.transaction((state) => {
      const sessionRefs: string[] = [];
      for (const request of Object.values(state.requests)) {
        const context = request.context;
        if (
          context.ownerId !== ownerId ||
          context.policyId !== policyId ||
          (context.policyVersion === nextVersion && context.mode === nextMode)
        )
          continue;
        this.invalidate(state, request.id);
        for (const session of Object.values(state.sessions)) {
          if (session.requestId !== request.id) continue;
          sessionRefs.push(session.id);
          // Retry cleanup even if the prior transaction already revoked it.
          if (session.revokedAt) continue;
          session.revokedAt = this.now();
          this.audit(state, 'SESSION_ENDED', {
            sessionRef: session.id,
            ownerId,
            clientId: context.clientId,
          });
        }
        if (terminal.has(request.state)) continue;
        const exposed =
          request.possibleDelivery ||
          Object.values(state.permits).some(
            (permit) => permit.requestId === request.id && Boolean(permit.consumedAt),
          );
        for (const attempt of Object.values(state.attempts)) {
          if (attempt.requestId === request.id && attempt.state === 'ACTIVE')
            attempt.state = exposed ? 'OUTCOME_UNKNOWN' : 'CANCELLED';
        }
        this.transition(
          request,
          exposed ? 'OUTCOME_UNKNOWN' : 'CANCELLED',
          exposed ? 'OUTCOME_UNKNOWN' : 'POLICY_DENIED',
        );
        if (exposed) state.quarantinedRuntimes[context.runtimeId] = true;
        this.audit(state, exposed ? 'AUTH_REQUEST_FAILED' : 'AUTH_REQUEST_CANCELLED', {
          ...this.requestAudit(request),
          reason: exposed ? 'OUTCOME_UNKNOWN' : 'POLICY_DENIED',
        });
      }
      return { sessionRefs };
    });
  }
  async createChallenge(
    ownerId: string,
    requestId: string,
    deviceId: string,
  ): Promise<{
    challenge_id: string;
    payload_base64: string;
    payload_digest: string;
    review: Record<string, unknown>;
  }> {
    await this.ready;
    return this.store.transaction((state) => {
      const request = state.requests[requestId],
        device = this.config.devices.find(
          (d) => d.id === deviceId && d.ownerId === ownerId && !d.revokedAt,
        );
      if (!request || request.context.ownerId !== ownerId || !device) reject('NOT_FOUND');
      this.validateCurrent(request, state);
      if (request.state !== 'AWAITING_APPROVAL') reject('INVALID_STATE');
      const existing = Object.values(state.challenges).find(
        (c) =>
          c.requestId === requestId &&
          c.revision === request.revision &&
          c.deviceId === deviceId &&
          !c.consumedAt &&
          !c.invalidatedAt &&
          !this.expired(c.expiresAt),
      );
      if (existing)
        return {
          challenge_id: existing.id,
          payload_base64: existing.payloadBase64,
          payload_digest: existing.payloadDigest,
          review: JSON.parse(
            Buffer.from(existing.payloadBase64, 'base64').toString('utf8'),
          ) as Record<string, unknown>,
        };
      const c = request.context,
        nonce = randomBytes(32).toString('base64url'),
        now = this.now();
      const payload = {
        version: 1,
        action: 'authorize_authentication',
        broker_id: this.brokerId,
        boot_epoch: this.bootEpoch,
        owner_id: ownerId,
        device_id: deviceId,
        request_id: requestId,
        revision: request.revision,
        nonce,
        issued_at: now,
        expires_at: request.expiresAt,
        client_id: c.clientId,
        workload_id: c.workloadId,
        runtime_id: c.runtimeId,
        runtime_generation: c.runtimeGeneration,
        account_id: c.accountId,
        credential_binding_version: c.credentialBindingVersion,
        destination: c.destination,
        operation: c.operation,
        adapter_id: c.adapterId,
        adapter_version: c.adapterVersion,
        factors: c.factorPlan.map((s) => s.factor),
        policy_id: c.policyId,
        policy_version: c.policyVersion,
        session_action_profile: c.sessionActionProfile,
        review_digest: canonicalDigest({ purpose: c.purpose }),
        purpose: c.purpose,
        client_display_name: c.clientDisplayName,
        account_display_name: c.accountDisplayName,
      };
      const bytes = canonicalBytes(payload),
        challenge: ApprovalChallenge = {
          id: id('challenge'),
          requestId,
          revision: request.revision,
          deviceId,
          nonce,
          payloadBase64: bytes.toString('base64'),
          payloadDigest: sha256(bytes),
          contextDigest: request.contextDigest,
          bootEpoch: this.bootEpoch,
          createdAt: now,
          expiresAt: request.expiresAt,
        };
      state.challenges[challenge.id] = challenge;
      this.audit(state, 'APPROVAL_CHALLENGE_CREATED', { ...this.requestAudit(request), deviceId });
      return {
        challenge_id: challenge.id,
        payload_base64: challenge.payloadBase64,
        payload_digest: challenge.payloadDigest,
        review: payload,
      };
    });
  }
  async approve(input: {
    challenge_id: string;
    device_id: string;
    signature_base64: string;
  }): Promise<SafeStatus> {
    await this.ready;
    return this.store.transaction((state) => {
      const challenge = state.challenges[input.challenge_id];
      if (
        !challenge ||
        challenge.deviceId !== input.device_id ||
        challenge.bootEpoch !== this.bootEpoch ||
        challenge.invalidatedAt ||
        this.expired(challenge.expiresAt)
      )
        reject('APPROVAL_INVALID');
      if (challenge.consumedAt) reject('APPROVAL_REPLAY');
      let payload: Record<string, unknown>;
      try {
        payload = JSON.parse(
          Buffer.from(challenge.payloadBase64, 'base64').toString('utf8'),
        ) as Record<string, unknown>;
      } catch {
        reject('APPROVAL_INVALID');
      }
      if (
        payload!.broker_id !== this.brokerId ||
        payload!.boot_epoch !== this.bootEpoch ||
        payload!.device_id !== input.device_id ||
        sha256(Buffer.from(challenge.payloadBase64, 'base64')) !== challenge.payloadDigest
      )
        reject('APPROVAL_INVALID');
      const request = state.requests[challenge.requestId]!;
      this.validateCurrent(request, state);
      if (
        request.state !== 'AWAITING_APPROVAL' ||
        request.revision !== challenge.revision ||
        request.contextDigest !== challenge.contextDigest
      )
        reject('APPROVAL_INVALID');
      const device = this.config.devices.find(
        (d) => d.id === input.device_id && d.ownerId === request.context.ownerId && !d.revokedAt,
      );
      if (!device) reject('APPROVAL_INVALID');
      let valid = false;
      try {
        const key = createPublicKey(device.publicKeyPem);
        const signature = Buffer.from(input.signature_base64, 'base64');
        valid =
          key.asymmetricKeyType === 'ec' &&
          key.asymmetricKeyDetails?.namedCurve === 'prime256v1' &&
          signature.toString('base64') === input.signature_base64 &&
          verify(
            'sha256',
            Buffer.from(challenge.payloadBase64, 'base64'),
            { key, dsaEncoding: 'der' },
            signature,
          );
      } catch {
        valid = false;
      }
      if (!valid) reject('APPROVAL_INVALID');
      challenge.consumedAt = this.now();
      request.authorization = {
        kind: 'OWNER_DEVICE',
        deviceId: device.id,
        challengeId: challenge.id,
        bootEpoch: this.bootEpoch,
      };
      this.transition(request, 'AUTHORIZED');
      this.audit(state, 'AUTH_REQUEST_APPROVED', {
        ...this.requestAudit(request),
        deviceId: device.id,
        authorizationKind: 'OWNER_DEVICE',
      });
      return this.statusValue(request);
    });
  }
  async listPending(
    ownerId: string,
  ): Promise<Array<{ request_id: string; revision: number; state: RequestState }>> {
    await this.ready;
    return this.store.transaction((state) =>
      Object.values(state.requests)
        .filter(
          (r) =>
            r.context.ownerId === ownerId &&
            r.state === 'AWAITING_APPROVAL' &&
            !this.expired(r.expiresAt),
        )
        .map((r) => ({ request_id: r.id, revision: r.revision, state: r.state })),
    );
  }
  async denyChallenge(ownerId: string, challengeId: string): Promise<void> {
    await this.ready;
    await this.store.transaction((state) => {
      const challenge = state.challenges[challengeId],
        request = challenge && state.requests[challenge.requestId];
      if (!challenge || !request || request.context.ownerId !== ownerId) reject('NOT_FOUND');
      if (request.state !== 'AWAITING_APPROVAL') reject('INVALID_STATE');
      this.transition(request, 'DENIED', 'POLICY_DENIED');
      this.invalidate(state, request.id);
      this.audit(state, 'AUTH_REQUEST_DENIED', {
        ...this.requestAudit(request),
        reason: 'POLICY_DENIED',
      });
    });
  }
  registerDevice(ownerId: string, device: ApprovalDevice): void {
    if (device.ownerId !== ownerId || this.config.devices.some((d) => d.id === device.id))
      reject('INVALID_ARGUMENT');
    try {
      const key = createPublicKey(device.publicKeyPem);
      if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
        reject('INVALID_ARGUMENT');
    } catch {
      reject('INVALID_ARGUMENT');
    }
    this.config.devices.push(structuredClone(device));
  }
  revokeDevice(ownerId: string, deviceId: string): void {
    const device = this.config.devices.find((d) => d.id === deviceId && d.ownerId === ownerId);
    if (!device) reject('NOT_FOUND');
    device.revokedAt = this.now();
  }
  async reviseRequest(
    ownerId: string,
    requestId: string,
    input: RequestInput,
  ): Promise<SafeStatus> {
    await this.ready;
    const parsed = requestSchema.safeParse(input);
    if (!parsed.success) reject('INVALID_ARGUMENT');
    const request = await this.store.transaction((state) => {
      const request = state.requests[requestId];
      if (!request || request.context.ownerId !== ownerId) reject('NOT_FOUND');
      if (terminal.has(request.state) || request.possibleDelivery) reject('INVALID_STATE');
      const context = this.resolve({ ownerId, clientId: request.context.clientId }, parsed.data);
      if (parsed.data.idempotency_key !== request.idempotencyKey) reject('IDEMPOTENCY_CONFLICT');
      this.invalidate(state, requestId);
      for (const attempt of Object.values(state.attempts))
        if (attempt.requestId === requestId && attempt.state === 'ACTIVE')
          attempt.state = 'CANCELLED';
      request.revision++;
      request.context = context;
      request.contextDigest = canonicalDigest(context);
      request.inputDigest = canonicalDigest({ input: parsed.data, context });
      delete request.authorization;
      delete request.reason;
      request.state =
        context.mode === 'safe'
          ? 'CLASSIFYING'
          : context.mode === 'manual'
            ? 'AWAITING_APPROVAL'
            : 'DENIED';
      request.updatedAt = this.now();
      if (context.mode === 'auto') {
        const delegation = this.matchingDelegation(request);
        if (delegation) {
          request.state = 'AUTHORIZED';
          request.authorization = {
            kind: 'DELEGATED_AUTO',
            delegationId: delegation.id,
            bootEpoch: this.bootEpoch,
          };
        } else request.reason = 'POLICY_DENIED';
      }
      this.audit(state, 'REQUEST_REVISED', this.requestAudit(request));
      return request;
    });
    if (request.state === 'CLASSIFYING') await this.classify(request);
    return this.status({ ownerId, clientId: request.context.clientId }, requestId);
  }
  async acquireExecution(requestId: string, worker: WorkerIdentity): Promise<ExecutionAttempt> {
    await this.ready;
    const outcome = await this.store.transaction((state) => {
      const request = state.requests[requestId];
      if (!request) reject('NOT_FOUND');
      this.validateAuthorization(request, state);
      if (!sameWorker(request.context, worker)) reject('PERMIT_INVALID');
      if (request.state === 'EXECUTING') {
        const prior = Object.values(state.attempts).find(
          (a) => a.requestId === requestId && a.state === 'ACTIVE',
        );
        if (!prior || !this.expired(prior.leaseExpiresAt)) reject('LEASE_CONFLICT');
        if (
          Object.values(state.permits).some((p) => p.attemptId === prior.attemptId && p.consumedAt)
        ) {
          prior.state = 'OUTCOME_UNKNOWN';
          this.transition(request, 'OUTCOME_UNKNOWN', 'OUTCOME_UNKNOWN');
          this.invalidate(state, requestId);
          state.quarantinedRuntimes[worker.runtimeId] = true;
          this.audit(state, 'AUTH_REQUEST_FAILED', {
            ...this.requestAudit(request),
            attemptId: prior.attemptId,
            reason: 'OUTCOME_UNKNOWN',
          });
          return { error: 'OUTCOME_UNKNOWN' as const };
        }
        prior.state = 'FAILED';
        this.invalidate(state, requestId);
        this.transition(request, 'AUTHORIZED');
      }
      if (request.state !== 'AUTHORIZED')
        reject(request.state === 'AWAITING_APPROVAL' ? 'APPROVAL_REQUIRED' : 'INVALID_STATE');
      for (const active of Object.values(state.attempts))
        if (active.runtimeId === worker.runtimeId && active.state === 'ACTIVE') {
          // Never steal another request's runtime, even after its lease expires.
          reject('LEASE_CONFLICT');
        }
      const c = request.context;
      request.executionGeneration++;
      const attempt: ExecutionAttempt = {
        attemptId: id('attempt'),
        requestId,
        revision: request.revision,
        workerId: worker.workerId,
        runtimeId: c.runtimeId,
        runtimeGeneration: c.runtimeGeneration,
        executionGeneration: request.executionGeneration,
        accountId: c.accountId,
        credentialBindingVersion: c.credentialBindingVersion,
        destination: c.destination,
        identityProvider: c.identityProvider,
        relyingParty: c.relyingParty,
        adapterId: c.adapterId,
        adapterVersion: c.adapterVersion,
        factorPlan: structuredClone(c.factorPlan),
        factors: c.factorPlan.map((s) => s.factor),
        sessionActionProfile: c.sessionActionProfile,
        observationProfile: c.observationProfile,
        leaseExpiresAt: this.until(this.options.leaseSeconds ?? 30, request.expiresAt),
        createdAt: this.now(),
        bootEpoch: this.bootEpoch,
        state: 'ACTIVE',
      };
      state.attempts[attempt.attemptId] = attempt;
      this.transition(request, 'EXECUTING');
      this.audit(state, 'EXECUTION_STARTED', {
        ...this.requestAudit(request),
        attemptId: attempt.attemptId,
        authorizationKind: request.authorization!.kind,
      });
      return attempt;
    });
    if ('error' in outcome) reject(outcome.error!);
    return outcome;
  }
  private activeAttempt(
    state: BrokerState,
    attemptId: string,
    worker: WorkerIdentity,
    requireAuthorization = true,
  ): { attempt: ExecutionAttempt; request: AuthRequest } {
    const attempt = state.attempts[attemptId];
    if (!attempt || !sameWorker(attempt, worker)) reject('PERMIT_INVALID');
    const request = state.requests[attempt.requestId]!;
    if (
      attempt.state !== 'ACTIVE' ||
      attempt.bootEpoch !== this.bootEpoch ||
      attempt.revision !== request.revision ||
      attempt.executionGeneration !== request.executionGeneration ||
      this.expired(attempt.leaseExpiresAt) ||
      request.state !== 'EXECUTING'
    )
      reject('PERMIT_INVALID');
    if (requireAuthorization) this.validateAuthorization(request, state);
    return { attempt, request };
  }
  async renewExecution(attemptId: string, worker: WorkerIdentity): Promise<ExecutionAttempt> {
    await this.ready;
    return this.store.transaction((state) => {
      const { attempt, request } = this.activeAttempt(state, attemptId, worker);
      attempt.leaseExpiresAt = this.until(this.options.leaseSeconds ?? 30, request.expiresAt);
      return attempt;
    });
  }
  async issuePermit(
    attemptId: string,
    factor: Factor,
    adapterStep: string,
    worker: WorkerIdentity,
  ): Promise<SecretPermit> {
    await this.ready;
    return this.store.transaction((state) => {
      const { attempt, request } = this.activeAttempt(state, attemptId, worker);
      const plan = request.context.factorPlan;
      const previous = Object.values(state.permits).filter((p) => p.attemptId === attemptId);
      const next = plan.find((s) => !previous.some((p) => p.factor === s.factor && p.deliveredAt));
      if (
        !next ||
        next.factor !== factor ||
        next.step !== adapterStep ||
        previous.some((p) => p.factor === factor)
      )
        reject('PERMIT_INVALID');
      const permit: SecretPermit = {
        id: id('permit'),
        requestId: request.id,
        revision: request.revision,
        attemptId,
        workerId: worker.workerId,
        runtimeId: worker.runtimeId,
        runtimeGeneration: worker.runtimeGeneration,
        executionGeneration: attempt.executionGeneration,
        accountId: request.context.accountId,
        credentialBindingVersion: request.context.credentialBindingVersion,
        destination: request.context.destination,
        factor,
        adapterStep,
        createdAt: this.now(),
        expiresAt: this.until(15, attempt.leaseExpiresAt),
        bootEpoch: this.bootEpoch,
      };
      state.permits[permit.id] = permit;
      this.audit(state, 'SECRET_PERMIT_ISSUED', {
        ...this.requestAudit(request),
        attemptId,
        permitId: permit.id,
        factor,
      });
      return permit;
    });
  }
  async consumePermit(permitId: string, worker: WorkerIdentity): Promise<SecretPermit> {
    await this.ready;
    return this.store.transaction((state) => {
      const permit = state.permits[permitId];
      if (
        !permit ||
        permit.invalidatedAt ||
        permit.bootEpoch !== this.bootEpoch ||
        this.expired(permit.expiresAt)
      )
        reject('PERMIT_INVALID');
      if (permit.consumedAt) reject('PERMIT_CONSUMED');
      const { attempt, request } = this.activeAttempt(state, permit.attemptId, worker);
      if (
        !sameWorker(permit, worker) ||
        permit.revision !== request.revision ||
        permit.executionGeneration !== attempt.executionGeneration ||
        permit.credentialBindingVersion !== request.context.credentialBindingVersion ||
        permit.destination !== request.context.destination ||
        !request.context.factorPlan.some(
          (s) => s.factor === permit.factor && s.step === permit.adapterStep,
        )
      )
        reject('PERMIT_INVALID');
      permit.consumedAt = this.now();
      request.possibleDelivery = true;
      this.audit(state, 'SECRET_PERMIT_CONSUMED', {
        ...this.requestAudit(request),
        attemptId: attempt.attemptId,
        permitId,
        factor: permit.factor,
      });
      return permit;
    });
  }
  async recordSecretDelivered(permitId: string, worker: WorkerIdentity): Promise<void> {
    await this.ready;
    await this.store.transaction((state) => {
      const permit = state.permits[permitId];
      if (
        !permit ||
        !permit.consumedAt ||
        !sameWorker(permit, worker) ||
        permit.bootEpoch !== this.bootEpoch
      )
        reject('PERMIT_INVALID');
      if (permit.deliveredAt) return;
      permit.deliveredAt = this.now();
      const request = state.requests[permit.requestId]!;
      if (!request.deliveredFactors.includes(permit.factor))
        request.deliveredFactors.push(permit.factor);
      request.possibleDelivery = true;
      this.audit(state, 'SECRET_DELIVERED', {
        ...this.requestAudit(request),
        permitId,
        factor: permit.factor,
        attemptId: permit.attemptId,
      });
    });
  }
  async completeExecution(
    attemptId: string,
    worker: WorkerIdentity,
    result: { verifiedAccountId: string },
  ): Promise<{ session_ref: string }> {
    await this.ready;
    const outcome = await this.store.transaction((state) => {
      const { attempt, request } = this.activeAttempt(state, attemptId, worker);
      const missing = request.context.factorPlan.some(
        (s) =>
          !Object.values(state.permits).some(
            (p) =>
              p.attemptId === attemptId &&
              p.factor === s.factor &&
              p.adapterStep === s.step &&
              p.consumedAt &&
              p.deliveredAt,
          ),
      );
      if (missing) reject('INVALID_STATE');
      this.transition(request, 'VERIFYING');
      if (result.verifiedAccountId !== request.context.accountId) {
        this.transition(request, 'FAILED', 'ACCOUNT_MISMATCH');
        attempt.state = 'FAILED';
        state.quarantinedRuntimes[attempt.runtimeId] = true;
        this.audit(state, 'AUTH_REQUEST_FAILED', {
          ...this.requestAudit(request),
          reason: 'ACCOUNT_MISMATCH',
        });
        return { error: 'ACCOUNT_MISMATCH' as const };
      }
      const c = request.context,
        maxSession =
          request.authorization?.kind === 'DELEGATED_AUTO'
            ? Math.min(c.maxSessionSeconds, this.matchingDelegation(request)!.maxSessionSeconds)
            : c.maxSessionSeconds;
      const delegationLimit =
        request.authorization?.kind === 'DELEGATED_AUTO'
          ? this.matchingDelegation(request)!.expiresAt
          : undefined;
      const session: ProtectedSession = {
        id: id('session'),
        requestId: request.id,
        ownerId: c.ownerId,
        clientId: c.clientId,
        workloadId: c.workloadId,
        accountId: c.accountId,
        runtimeId: c.runtimeId,
        runtimeGeneration: c.runtimeGeneration,
        workerId: c.workerId,
        actionProfile: c.sessionActionProfile,
        observationProfile: c.observationProfile,
        createdAt: this.now(),
        expiresAt: this.until(maxSession, delegationLimit),
      };
      state.sessions[session.id] = session;
      request.sessionRef = session.id;
      attempt.state = 'SUCCEEDED';
      this.transition(request, 'SUCCEEDED');
      this.audit(state, 'AUTH_REQUEST_SUCCEEDED', {
        ...this.requestAudit(request),
        sessionRef: session.id,
        attemptId,
      });
      return { session_ref: session.id };
    });
    if ('error' in outcome) reject(outcome.error!);
    return outcome;
  }
  async crashExecution(attemptId: string, worker: WorkerIdentity): Promise<SafeStatus> {
    await this.ready;
    return this.store.transaction((state) => {
      const attempt = state.attempts[attemptId];
      if (!attempt || !sameWorker(attempt, worker)) reject('PERMIT_INVALID');
      const request = state.requests[attempt.requestId]!;
      if (attempt.state !== 'ACTIVE') return this.statusValue(request);
      const consumed = Object.values(state.permits).some(
        (p) => p.attemptId === attemptId && p.consumedAt,
      );
      this.invalidate(state, request.id);
      if (consumed) {
        attempt.state = 'OUTCOME_UNKNOWN';
        this.transition(request, 'OUTCOME_UNKNOWN', 'OUTCOME_UNKNOWN');
        state.quarantinedRuntimes[attempt.runtimeId] = true;
      } else {
        attempt.state = 'FAILED';
        this.transition(request, 'AUTHORIZED');
      }
      this.audit(state, 'AUTH_REQUEST_FAILED', {
        ...this.requestAudit(request),
        attemptId,
        reason: consumed ? 'OUTCOME_UNKNOWN' : 'AUTH_FAILED',
      });
      return this.statusValue(request);
    });
  }
  async failExecution(
    attemptId: string,
    worker: WorkerIdentity,
    reason:
      | 'AUTH_FAILED'
      | 'DESTINATION_MISMATCH'
      | 'ACCOUNT_MISMATCH'
      | 'INTERACTION_REQUIRED'
      | 'OUTCOME_UNKNOWN' = 'AUTH_FAILED',
  ): Promise<SafeStatus> {
    await this.ready;
    return this.store.transaction((state) => {
      const previous = state.attempts[attemptId];
      if (!previous || !sameWorker(previous, worker)) reject('PERMIT_INVALID');
      const existing = state.requests[previous.requestId];
      if (
        !existing ||
        previous.bootEpoch !== this.bootEpoch ||
        previous.revision !== existing.revision ||
        previous.executionGeneration !== existing.executionGeneration
      )
        reject('PERMIT_INVALID');
      // Failure cleanup releases no authority. An exact worker may observe an
      // already fenced attempt, or close its active one after policy revocation.
      if (previous.state !== 'ACTIVE') return this.statusValue(existing);
      const { attempt, request } = this.activeAttempt(state, attemptId, worker, false);
      attempt.state = reason === 'OUTCOME_UNKNOWN' ? 'OUTCOME_UNKNOWN' : 'FAILED';
      this.transition(
        request,
        reason === 'OUTCOME_UNKNOWN'
          ? 'OUTCOME_UNKNOWN'
          : reason === 'INTERACTION_REQUIRED'
            ? 'INTERACTION_REQUIRED'
            : 'FAILED',
        reason,
      );
      this.invalidate(state, request.id);
      if (request.possibleDelivery || reason !== 'AUTH_FAILED')
        state.quarantinedRuntimes[attempt.runtimeId] = true;
      this.audit(state, 'AUTH_REQUEST_FAILED', {
        ...this.requestAudit(request),
        attemptId,
        reason,
      });
      return this.statusValue(request);
    });
  }
  private ownedSession(
    state: BrokerState,
    caller: Caller,
    sessionRef: string,
    workloadId?: string,
  ): ProtectedSession {
    this.caller(caller);
    const session = state.sessions[sessionRef];
    if (
      !session ||
      session.ownerId !== caller.ownerId ||
      session.clientId !== caller.clientId ||
      (caller.workloadId && caller.workloadId !== session.workloadId) ||
      (workloadId && workloadId !== session.workloadId)
    )
      reject('NOT_FOUND');
    if (session.revokedAt || this.expired(session.expiresAt)) reject('SESSION_EXPIRED');
    const runtime = this.config.runtimes.find(
      (r) =>
        r.id === session.runtimeId &&
        r.enabled &&
        r.protected &&
        r.generation === session.runtimeGeneration,
    );
    const workload = this.config.workloads.find(
      (w) =>
        w.id === session.workloadId &&
        w.enabled &&
        w.ownerId === caller.ownerId &&
        w.clientId === caller.clientId,
    );
    const account = this.config.accounts.find(
      (a) => a.id === session.accountId && a.enabled && a.ownerId === caller.ownerId,
    );
    if (!runtime || !workload || !account || state.quarantinedRuntimes[session.runtimeId])
      reject('SESSION_EXPIRED');
    const request = state.requests[session.requestId]!;
    // Recheck the source policy/delegation/device without applying the shorter login request TTL.
    const expires = request.expiresAt;
    request.expiresAt = session.expiresAt;
    try {
      this.validateAuthorization(request, state);
    } finally {
      request.expiresAt = expires;
    }
    return session;
  }
  async authorizeSessionOperation(
    caller: Caller,
    sessionRef: string,
    operation: string,
    workloadId?: string,
  ): Promise<ProtectedSession> {
    await this.ready;
    return this.store.transaction((state) => {
      const session = this.ownedSession(state, caller, sessionRef, workloadId);
      const profile = this.config.actionProfiles.find((p) => p.id === session.actionProfile);
      if (!profile?.operations.includes(operation)) reject('POLICY_DENIED');
      this.audit(state, 'SESSION_OPERATION_AUTHORIZED', {
        sessionRef,
        operation,
        ownerId: caller.ownerId,
        clientId: caller.clientId,
        accountId: session.accountId,
      });
      return session;
    });
  }
  async endSession(
    caller: Caller,
    sessionRef: string,
    workloadId?: string,
  ): Promise<{ ended: true }> {
    await this.ready;
    return this.store.transaction((state) => {
      this.caller(caller);
      const session = state.sessions[sessionRef];
      if (
        !session ||
        session.ownerId !== caller.ownerId ||
        session.clientId !== caller.clientId ||
        (caller.workloadId && caller.workloadId !== session.workloadId) ||
        (workloadId && workloadId !== session.workloadId)
      )
        reject('NOT_FOUND');
      session.revokedAt = this.now();
      this.audit(state, 'SESSION_ENDED', {
        sessionRef,
        ownerId: caller.ownerId,
        clientId: caller.clientId,
      });
      return { ended: true };
    });
  }
  async auditEvents(ownerId: string): Promise<AuditEvent[]> {
    await this.ready;
    return this.store.transaction((state) =>
      state.audit.filter(
        (e) =>
          e.ownerId === ownerId ||
          (e.requestId && state.requests[e.requestId]?.context.ownerId === ownerId) ||
          e.event === 'BROKER_RESTARTED',
      ),
    );
  }
}
