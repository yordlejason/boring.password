import { TrustedOperationError } from '../../services/browser-worker/contracts.js';

declare const releaseCapabilityBrand: unique symbol;
export interface VaultReleaseCapability {
  readonly [releaseCapabilityBrand]: true;
}
interface CapabilityRecord {
  origin: string;
  syntheticOnly: boolean;
}
const recognized = new WeakMap<object, CapabilityRecord>();

/**
 * Production gate is intentionally unconfigured. There is NO production issuer
 * in this repository or deployed bootstrap. Adding one requires documented
 * release-gate evidence and independent owner-controlled trusted-host review.
 * A boolean, deserialized object or agent request can never enable this provider.
 */
export function assertVaultReleaseCapability(
  capability: VaultReleaseCapability,
  origin: string,
  synthetic: boolean,
): void {
  const record =
    capability && typeof capability === 'object' ? recognized.get(capability) : undefined;
  if (!record || record.origin !== origin || (record.syntheticOnly && !synthetic)) {
    throw new TrustedOperationError('POLICY_DENIED');
  }
}

/** Tests only: .invalid origin and fake fetch are mandatory in the provider. */
export function syntheticVaultTestCapability(): VaultReleaseCapability {
  const capability = Object.freeze({}) as VaultReleaseCapability;
  recognized.set(capability, { origin: 'https://synthetic-vault.invalid', syntheticOnly: true });
  return capability;
}
