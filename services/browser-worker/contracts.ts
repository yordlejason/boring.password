export type SecretFactor = 'password' | 'totp';
export type AdapterStep = 'enter_password' | 'enter_totp';

/** Trusted channel metadata. None of these types contain authentication material. */
export interface WorkerBinding {
  workerId: string;
  runtimeId: string;
  runtimeGeneration: number;
}

export interface ExecutionBinding extends WorkerBinding {
  requestId: string;
  revision: number;
  attemptId: string;
  executionGeneration: number;
  accountId: string;
  credentialBindingVersion: number;
  destination: string;
  identityProvider: string;
  relyingParty: string;
  adapterId: string;
  adapterVersion: string;
  factors: readonly SecretFactor[];
  factorPlan: readonly { factor: SecretFactor; step: string }[];
  sessionActionProfile: string;
  observationProfile: string;
}

export interface ConsumedPermit extends ExecutionBinding {
  permitId: string;
  factor: SecretFactor;
  adapterStep: AdapterStep;
  expiresAt: number;
}

export type WorkerFailureCode =
  | 'AUTH_FAILED'
  | 'DESTINATION_MISMATCH'
  | 'ACCOUNT_MISMATCH'
  | 'ADAPTER_UNSUPPORTED'
  | 'INTERACTION_REQUIRED'
  | 'OUTCOME_UNKNOWN'
  | 'POLICY_DENIED';

export interface ProtectedSessionResult {
  sessionRef: string;
}

/** Implemented by the broker, exclusively for authenticated trusted workers. */
export interface BrokerPort {
  acquireExecution(requestId: string, worker: WorkerBinding): Promise<ExecutionBinding>;
  issuePermit(
    attemptId: string,
    factor: SecretFactor,
    adapterStep: AdapterStep,
  ): Promise<{ permitId: string }>;
  consumePermit(permitId: string, worker: WorkerBinding): Promise<ConsumedPermit>;
  recordSecretDelivered(attemptId: string, factor: SecretFactor): Promise<void>;
  completeExecution(
    attemptId: string,
    verification: { verifiedAccountId: string },
  ): Promise<ProtectedSessionResult>;
  crashExecution(attemptId: string, reason: WorkerFailureCode): Promise<void>;
}

export class TrustedOperationError extends Error {
  constructor(readonly code: WorkerFailureCode) {
    super(code);
    this.name = 'TrustedOperationError';
  }
}
