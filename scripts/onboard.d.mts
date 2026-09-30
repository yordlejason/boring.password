export interface OnboardingOptions {
  iphone: boolean;
  pair: boolean;
  refresh: boolean;
  status: boolean;
  device?: string;
  host?: string;
  ip?: string;
  team?: string;
}
export interface ListenerConfig {
  host: string;
  ip: string;
  bind: string;
  tlsPort: number;
  ownerPort: number;
  agentPort: number;
}
export class OnboardingError extends Error {
  code: string;
  constructor(code: string);
}
export function parseOptions(args: string[]): OnboardingOptions;
export function publicListenerConfig(environment: string): ListenerConfig;
export function localBrokerHost(label: string): string;
export function selectPhone(inventory: unknown, selector?: string): Record<string, any>;
export function prepareDraft(
  config: ListenerConfig,
  fingerprint: string,
  pairing?: { expires_at: string; pairing_code: string },
  now?: number,
): {
  version: number;
  broker_url: string;
  certificate_sha256: string;
  pairing_code?: string;
  expires_at: string;
};
export function privateText(file: string): Promise<string>;
export function canReusePairingDraft(
  saved: unknown,
  config: ListenerConfig,
  fingerprint: string,
  settings: unknown,
  deviceIdentifier: string,
  now?: number,
): boolean;
export function phoneEnrollmentStage(
  receipt: unknown,
  config: ListenerConfig,
  fingerprint: string,
  devices: { id: string; key_fingerprint: string; status: string }[],
  launchedAt: number,
  now?: number,
): 'UNPAIRED' | 'ACTIVE' | 'PENDING_CONFIRMATION';
export function main(args?: string[]): Promise<Record<string, unknown>>;
