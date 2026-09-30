import type { ExecutionBinding, SecretFactor } from '../../services/browser-worker/contracts.js';
import type { PrivateSecretReceiver } from '../../services/secret-service/index.js';
import { TrustedOperationError } from '../../services/browser-worker/contracts.js';

declare const secretHandleBrand: unique symbol;

/** Opaque and callback-scoped. There is deliberately no value/getter/toJSON API. */
export interface SecretHandle {
  readonly [secretHandleBrand]: true;
  readonly factor: SecretFactor;
}

export interface SecretProvider {
  consumePasswordPermit(
    permitId: string,
    expected: ExecutionBinding,
    receiver: PrivateSecretReceiver,
    signal?: AbortSignal,
  ): Promise<void>;
  consumeTotpPermit(
    permitId: string,
    expected: ExecutionBinding,
    receiver: PrivateSecretReceiver,
    signal?: AbortSignal,
  ): Promise<void>;
}

const material = new WeakMap<SecretHandle, Buffer>();

/** Trusted secret-service implementation detail. Never return a handle to a controller. */
export async function withScopedSecretInput(
  factor: SecretFactor,
  value: string,
  receiver: PrivateSecretReceiver,
): Promise<void> {
  const handle = Object.freeze({ factor }) as SecretHandle;
  const bytes = Buffer.from(value, 'utf8');
  material.set(handle, bytes);
  try {
    const active = material.get(handle);
    if (!active) throw new TrustedOperationError('POLICY_DENIED');
    // Remove before calling the sink: even a reentrant trusted callback cannot
    // deliver this handle a second time. No handle is exposed to the sink.
    material.delete(handle);
    if (factor === 'password') await receiver.injectPassword(active.toString('utf8'));
    else await receiver.injectTotp(active.toString('utf8'));
  } finally {
    material.delete(handle);
    bytes.fill(0);
    // JS strings cannot be reliably erased. Run real providers only on the
    // separate trusted service host after the production isolation release gate.
  }
}
