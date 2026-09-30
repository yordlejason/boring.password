export type Mode = 'manual' | 'safe' | 'auto';
export type Factor = 'password' | 'totp';
export type RequestState =
  | 'CREATED'
  | 'INSPECTING'
  | 'POLICY_EVALUATING'
  | 'CLASSIFYING'
  | 'AWAITING_APPROVAL'
  | 'AUTHORIZED'
  | 'EXECUTING'
  | 'VERIFYING'
  | 'SUCCEEDED'
  | 'DENIED'
  | 'FAILED'
  | 'EXPIRED'
  | 'CANCELLED'
  | 'INTERACTION_REQUIRED'
  | 'OUTCOME_UNKNOWN';
export type ErrorCode =
  | 'INVALID_ARGUMENT'
  | 'NOT_FOUND'
  | 'CALLER_MISMATCH'
  | 'IDEMPOTENCY_CONFLICT'
  | 'POLICY_DENIED'
  | 'CLASSIFIER_BLOCKED'
  | 'APPROVAL_REQUIRED'
  | 'APPROVAL_INVALID'
  | 'APPROVAL_REPLAY'
  | 'ADAPTER_UNSUPPORTED'
  | 'DESTINATION_MISMATCH'
  | 'ACCOUNT_MISMATCH'
  | 'AUTH_FAILED'
  | 'INTERACTION_REQUIRED'
  | 'OUTCOME_UNKNOWN'
  | 'SESSION_EXPIRED'
  | 'PERMIT_INVALID'
  | 'PERMIT_CONSUMED'
  | 'LEASE_CONFLICT'
  | 'RUNTIME_QUARANTINED'
  | 'REQUEST_EXPIRED'
  | 'INVALID_STATE'
  | 'PRODUCTION_CREDENTIALS_DISABLED';
export class BrokerError extends Error {
  constructor(public readonly code: ErrorCode) {
    super(code);
    this.name = 'BrokerError';
  }
}
export interface Caller {
  ownerId: string;
  clientId: string;
  workloadId?: string;
}
export interface Client {
  id: string;
  ownerId: string;
  displayName: string;
  revokedAt?: string;
}
export interface Account {
  id: string;
  ownerId: string;
  displayName: string;
  credentialBindingVersion: number;
  synthetic: true;
  enabled: boolean;
}
export interface Runtime {
  id: string;
  ownerId: string;
  generation: number;
  workerId: string;
  protected: boolean;
  enabled: boolean;
}
export interface Workload {
  id: string;
  ownerId: string;
  clientId: string;
  runtimeId: string;
  enabled: boolean;
}
export interface FactorStep {
  factor: Factor;
  step: string;
}
export interface Adapter {
  id: string;
  version: string;
  allowedOrigins: string[];
  factors: FactorStep[];
  reviewed: boolean;
  synthetic: true;
}
export interface Policy {
  id: string;
  ownerId: string;
  version: number;
  mode: Mode;
  enabled: boolean;
  maxRequestSeconds: number;
  maxSessionSeconds: number;
}
export interface Context {
  id: string;
  targetRef: string;
  ownerId: string;
  clientId: string;
  runtimeId: string;
  accountIds: string[];
  destination: string;
  identityProvider: string;
  relyingParty: string;
  adapterId: string;
  adapterVersion: string;
  policyId: string;
  actionProfile: string;
  observationProfile: string;
  enabled: boolean;
}
export interface ApprovalDevice {
  id: string;
  ownerId: string;
  publicKeyPem: string;
  displayName: string;
  assuranceProfile: 'OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE' | 'SYNTHETIC_TEST_KEY';
  revokedAt?: string;
}
export interface Delegation {
  id: string;
  ownerId: string;
  clientId: string;
  accountId: string;
  destination: string;
  adapterId: string;
  adapterVersion: string;
  operation: 'sign_in';
  factors: Factor[];
  actionProfile: string;
  observationProfile: string;
  workloadId: string;
  runtimeId: string;
  policyId: string;
  policyVersion: number;
  credentialBindingVersion: number;
  maxSessionSeconds: number;
  expiresAt: string;
  revokedAt?: string;
}
export interface ActionProfile {
  id: string;
  operations: string[];
}
export interface TrustedConfig {
  clients: Client[];
  accounts: Account[];
  runtimes: Runtime[];
  workloads: Workload[];
  adapters: Adapter[];
  policies: Policy[];
  contexts: Context[];
  devices: ApprovalDevice[];
  delegations: Delegation[];
  actionProfiles: ActionProfile[];
}
export interface RequestInput {
  context_ref: string;
  account_ref: string;
  operation: 'sign_in';
  workload_ref: string;
  purpose: string;
  idempotency_key: string;
}
export interface RequestContext {
  ownerId: string;
  clientId: string;
  clientDisplayName: string;
  workloadId: string;
  runtimeId: string;
  runtimeGeneration: number;
  workerId: string;
  contextId: string;
  accountId: string;
  accountDisplayName: string;
  credentialBindingVersion: number;
  destination: string;
  identityProvider: string;
  relyingParty: string;
  operation: 'sign_in';
  adapterId: string;
  adapterVersion: string;
  factorPlan: FactorStep[];
  sessionActionProfile: string;
  actionProfileDigest: string;
  observationProfile: string;
  policyId: string;
  policyVersion: number;
  mode: Mode;
  maxSessionSeconds: number;
  purpose: string;
}
export interface Authorization {
  kind: 'OWNER_DEVICE' | 'DELEGATED_AUTO';
  deviceId?: string;
  delegationId?: string;
  challengeId?: string;
  bootEpoch: string;
}
export interface AuthRequest {
  id: string;
  revision: number;
  state: RequestState;
  context: RequestContext;
  contextDigest: string;
  idempotencyKey: string;
  inputDigest: string;
  createdAt: string;
  expiresAt: string;
  updatedAt: string;
  reason?: ErrorCode;
  authorization?: Authorization;
  executionGeneration: number;
  deliveredFactors: Factor[];
  possibleDelivery: boolean;
  sessionRef?: string;
}
export interface ApprovalChallenge {
  id: string;
  requestId: string;
  revision: number;
  deviceId: string;
  nonce: string;
  payloadBase64: string;
  payloadDigest: string;
  contextDigest: string;
  bootEpoch: string;
  createdAt: string;
  expiresAt: string;
  consumedAt?: string;
  invalidatedAt?: string;
}
export interface ExecutionBinding {
  attemptId: string;
  requestId: string;
  revision: number;
  workerId: string;
  runtimeId: string;
  runtimeGeneration: number;
  executionGeneration: number;
  accountId: string;
  credentialBindingVersion: number;
  destination: string;
  identityProvider: string;
  relyingParty: string;
  adapterId: string;
  adapterVersion: string;
  factorPlan: FactorStep[];
  factors: Factor[];
  sessionActionProfile: string;
  observationProfile: string;
}
export interface WorkerIdentity {
  workerId: string;
  runtimeId: string;
  runtimeGeneration: number;
}
export interface ExecutionAttempt extends ExecutionBinding {
  leaseExpiresAt: string;
  createdAt: string;
  bootEpoch: string;
  state: 'ACTIVE' | 'SUCCEEDED' | 'FAILED' | 'CANCELLED' | 'OUTCOME_UNKNOWN';
}
export interface SecretPermit {
  id: string;
  requestId: string;
  revision: number;
  attemptId: string;
  workerId: string;
  runtimeId: string;
  runtimeGeneration: number;
  executionGeneration: number;
  accountId: string;
  credentialBindingVersion: number;
  destination: string;
  factor: Factor;
  adapterStep: string;
  createdAt: string;
  expiresAt: string;
  bootEpoch: string;
  consumedAt?: string;
  deliveredAt?: string;
  invalidatedAt?: string;
}
export interface ProtectedSession {
  id: string;
  requestId: string;
  ownerId: string;
  clientId: string;
  workloadId: string;
  accountId: string;
  runtimeId: string;
  runtimeGeneration: number;
  workerId: string;
  actionProfile: string;
  observationProfile: string;
  createdAt: string;
  expiresAt: string;
  revokedAt?: string;
}
export type AuditEventName =
  | 'AUTH_REQUEST_CREATED'
  | 'AUTH_REQUEST_DENIED'
  | 'APPROVAL_CHALLENGE_CREATED'
  | 'AUTH_REQUEST_APPROVED'
  | 'EXECUTION_STARTED'
  | 'SECRET_PERMIT_ISSUED'
  | 'SECRET_PERMIT_CONSUMED'
  | 'SECRET_DELIVERED'
  | 'AUTH_REQUEST_SUCCEEDED'
  | 'AUTH_REQUEST_FAILED'
  | 'AUTH_REQUEST_CANCELLED'
  | 'REQUEST_REVISED'
  | 'BROKER_RESTARTED'
  | 'SESSION_OPERATION_AUTHORIZED'
  | 'SESSION_ENDED';
export interface AuditEvent {
  id: string;
  event: AuditEventName;
  timestamp: string;
  requestId?: string;
  revision?: number;
  ownerId?: string;
  clientId?: string;
  accountId?: string;
  destination?: string;
  mode?: Mode;
  deviceId?: string;
  attemptId?: string;
  permitId?: string;
  factor?: Factor;
  reason?: ErrorCode;
  sessionRef?: string;
  operation?: string;
  authorizationKind?: Authorization['kind'];
}
export interface BrokerState {
  bootEpoch?: string;
  requests: Record<string, AuthRequest>;
  challenges: Record<string, ApprovalChallenge>;
  attempts: Record<string, ExecutionAttempt>;
  permits: Record<string, SecretPermit>;
  sessions: Record<string, ProtectedSession>;
  audit: AuditEvent[];
  quarantinedRuntimes: Record<string, boolean>;
}
export interface TransactionStore {
  transaction<T>(fn: (state: BrokerState) => T | Promise<T>): Promise<T>;
  close?(): Promise<void>;
}
export interface ClassifierContext {
  destination: string;
  operation: 'sign_in';
  factors: Factor[];
  action_profile: string;
  purpose: string;
}
export type RiskClassifier = (context: ClassifierContext, signal: AbortSignal) => Promise<unknown>;
export interface ControllerOptions {
  brokerId: string;
  bootEpoch?: string;
  classifier?: RiskClassifier;
  classifierTimeoutMs?: number;
  leaseSeconds?: number;
  clock?: () => Date;
}
export interface SafeStatus {
  request_id: string;
  revision: number;
  state: RequestState;
  next_action: 'APPROVE' | 'WAIT' | 'NONE';
  reason?: ErrorCode;
  session_ref?: string;
}
