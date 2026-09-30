import { z } from 'zod';
import type { BrokerPort, ExecutionBinding, SecretFactor } from '../browser-worker/contracts.js';
import { TrustedOperationError } from '../browser-worker/contracts.js';
import {
  assertExactPermit,
  systemTrustedClock,
  type PrivateSecretReceiver,
  type TrustedClock,
} from './index.js';
import { generateTotp, totpLifetimeMs, type TotpParameters } from './totp.js';
import {
  withScopedSecretInput,
  type SecretProvider,
} from '../../packages/secret-provider-sdk/index.js';
import {
  assertVaultReleaseCapability,
  type VaultReleaseCapability,
} from '../../packages/secret-provider-sdk/release-gate.js';

export interface VaultCredentialEnrollment {
  accountId: string;
  credentialBindingVersion: number;
  /** Administrator-pinned segments, never caller-supplied URLs or Vault paths. */
  mount: string;
  path: readonly string[];
  vaultVersion: number;
  passwordField: string;
  totpSeedField: string;
  totp: TotpParameters;
  synthetic: boolean;
}

export type TrustedVaultFetch = (url: string, options: RequestInit) => Promise<Response>;
const responseSchema = z.object({
  data: z.object({
    data: z.record(z.string(), z.unknown()),
    metadata: z.object({
      version: z.number().int().positive(),
      destroyed: z.boolean(),
      deletion_time: z.string(),
    }),
  }),
});
const segment = /^[a-zA-Z0-9_-]{1,128}$/;

function abortable<T>(pending: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new TrustedOperationError('INTERACTION_REQUIRED'));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    pending.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort));
  });
}

async function boundedResponse(response: Response, signal: AbortSignal): Promise<unknown> {
  const maximum = 32768;
  const length = response.headers.get('content-length');
  if ((length && (!/^\d+$/.test(length) || Number(length) > maximum)) || !response.body) {
    throw new TrustedOperationError('AUTH_FAILED');
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await abortable(reader.read(), signal);
      if (done) break;
      total += value.length;
      chunks.push(value);
      if (total > maximum) throw new TrustedOperationError('AUTH_FAILED');
    }
    const bytes = Buffer.concat(
      chunks.map((chunk) => Buffer.from(chunk)),
      total,
    );
    try {
      return JSON.parse(bytes.toString('utf8')) as unknown;
    } finally {
      bytes.fill(0);
    }
  } finally {
    chunks.forEach((chunk) => chunk.fill(0));
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

/**
 * HashiCorp Vault KV v2, using its exact-version read API:
 * https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version
 * No production release capability is issued by bootstrap. This source is
 * covered with synthetic fake-fetch tests; it is NOT a production vault rollout.
 * Run any future real instance exclusively inside the isolated secret service.
 */
export class VaultKvV2Provider implements SecretProvider {
  readonly #broker: BrokerPort;
  readonly #origin: string;
  readonly #enrollment: Readonly<VaultCredentialEnrollment>;
  readonly #token: () => Promise<string>;
  readonly #fetch: TrustedVaultFetch;
  readonly #clock: TrustedClock;
  readonly #timeoutMs: number;
  readonly #minimumLifetimeMs: number;

  constructor(options: {
    releaseCapability: VaultReleaseCapability;
    broker: BrokerPort;
    origin: string;
    enrollment: VaultCredentialEnrollment;
    vaultToken: () => Promise<string>;
    fetch?: TrustedVaultFetch;
    clock?: TrustedClock;
    timeoutMs?: number;
    minimumTotpLifetimeMs?: number;
  }) {
    let url: URL;
    try {
      url = new URL(options.origin);
    } catch {
      throw new TrustedOperationError('DESTINATION_MISMATCH');
    }
    if (
      url.protocol !== 'https:' ||
      url.origin !== options.origin ||
      url.username ||
      url.password
    ) {
      throw new TrustedOperationError('DESTINATION_MISMATCH');
    }
    assertVaultReleaseCapability(
      options.releaseCapability,
      options.origin,
      options.enrollment.synthetic,
    );
    // The only available capability is synthetic and may never make a real
    // network request. A future production issuer must remove this test fence
    // under the independently reviewed production release procedure.
    if (
      options.origin !== 'https://synthetic-vault.invalid' ||
      !options.enrollment.synthetic ||
      !options.fetch
    ) {
      throw new TrustedOperationError('POLICY_DENIED');
    }
    const enrollment = options.enrollment;
    if (
      !segment.test(enrollment.mount) ||
      !Array.isArray(enrollment.path) ||
      !enrollment.path.length ||
      enrollment.path.length > 10 ||
      enrollment.path.some((part) => !segment.test(part)) ||
      !segment.test(enrollment.passwordField) ||
      !segment.test(enrollment.totpSeedField) ||
      !Number.isSafeInteger(enrollment.vaultVersion) ||
      enrollment.vaultVersion < 1 ||
      !Number.isSafeInteger(enrollment.credentialBindingVersion) ||
      enrollment.credentialBindingVersion < 1 ||
      !['sha1', 'sha256', 'sha512'].includes(enrollment.totp.algorithm) ||
      ![6, 8].includes(enrollment.totp.digits) ||
      !Number.isSafeInteger(enrollment.totp.period) ||
      enrollment.totp.period < 1 ||
      enrollment.totp.period > 300
    ) {
      throw new TrustedOperationError('POLICY_DENIED');
    }
    this.#broker = options.broker;
    this.#origin = options.origin;
    this.#enrollment = Object.freeze({
      ...enrollment,
      path: Object.freeze([...enrollment.path]),
      totp: Object.freeze({ ...enrollment.totp }),
    });
    this.#token = options.vaultToken;
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? systemTrustedClock();
    this.#timeoutMs = options.timeoutMs ?? 5000;
    this.#minimumLifetimeMs = options.minimumTotpLifetimeMs ?? 5000;
    if (
      this.#timeoutMs < 1 ||
      this.#timeoutMs > 15000 ||
      this.#minimumLifetimeMs < 1 ||
      this.#minimumLifetimeMs >= enrollment.totp.period * 1000
    ) {
      throw new TrustedOperationError('POLICY_DENIED');
    }
  }

  async consumePasswordPermit(
    permitId: string,
    expected: ExecutionBinding,
    receiver: PrivateSecretReceiver,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#consume(permitId, expected, 'password', receiver, signal);
  }

  async consumeTotpPermit(
    permitId: string,
    expected: ExecutionBinding,
    receiver: PrivateSecretReceiver,
    signal?: AbortSignal,
  ): Promise<void> {
    await this.#consume(permitId, expected, 'totp', receiver, signal);
  }

  async #consume(
    permitId: string,
    expected: ExecutionBinding,
    factor: SecretFactor,
    receiver: PrivateSecretReceiver,
    externalSignal?: AbortSignal,
  ): Promise<void> {
    let releaseStarted = false;
    try {
      const signal = externalSignal
        ? AbortSignal.any([externalSignal, AbortSignal.timeout(this.#timeoutMs)])
        : AbortSignal.timeout(this.#timeoutMs);
      if (signal.aborted || !this.#clock.healthy())
        throw new TrustedOperationError('INTERACTION_REQUIRED');
      const permit = await this.#broker.consumePermit(permitId, expected);
      assertExactPermit(permit, expected, factor, this.#clock.now());
      const enrollment = this.#enrollment;
      if (
        permit.accountId !== enrollment.accountId ||
        permit.credentialBindingVersion !== enrollment.credentialBindingVersion
      ) {
        throw new TrustedOperationError('POLICY_DENIED');
      }
      const token = await abortable(this.#token(), signal);
      if (!token || token.length > 4096 || !/^[a-zA-Z0-9._:-]+$/.test(token))
        throw new TrustedOperationError('AUTH_FAILED');
      if (signal.aborted) throw new TrustedOperationError('INTERACTION_REQUIRED');
      const path = [enrollment.mount, 'data', ...enrollment.path].map(encodeURIComponent).join('/');
      const target = `${this.#origin}/v1/${path}?version=${enrollment.vaultVersion}`;
      const response = await abortable(
        this.#fetch(target, {
          method: 'GET',
          redirect: 'error',
          cache: 'no-store',
          signal,
          headers: { 'X-Vault-Token': token, accept: 'application/json' },
        }),
        signal,
      );
      if (
        response.status !== 200 ||
        response.redirected ||
        (response.url && response.url !== target) ||
        !response.headers.get('content-type')?.toLowerCase().includes('application/json')
      ) {
        throw new TrustedOperationError('AUTH_FAILED');
      }
      const parsed = responseSchema.safeParse(await boundedResponse(response, signal));
      if (
        !parsed.success ||
        parsed.data.data.metadata.version !== enrollment.vaultVersion ||
        parsed.data.data.metadata.destroyed ||
        parsed.data.data.metadata.deletion_time !== ''
      ) {
        throw new TrustedOperationError('AUTH_FAILED');
      }
      const record = parsed.data.data.data;
      const secret =
        record[factor === 'password' ? enrollment.passwordField : enrollment.totpSeedField];
      if (typeof secret !== 'string' || !secret || secret.length > 8192)
        throw new TrustedOperationError('AUTH_FAILED');
      if (factor === 'totp') {
        const remaining = totpLifetimeMs(this.#clock.now(), enrollment.totp.period);
        if (remaining < this.#minimumLifetimeMs)
          await abortable(this.#clock.wait(remaining + 20), signal);
      }
      if (signal.aborted || !this.#clock.healthy() || permit.expiresAt <= this.#clock.now()) {
        throw new TrustedOperationError('INTERACTION_REQUIRED');
      }
      const input =
        factor === 'password' ? secret : generateTotp(secret, this.#clock.now(), enrollment.totp);
      if (
        factor === 'totp' &&
        totpLifetimeMs(this.#clock.now(), enrollment.totp.period) < this.#minimumLifetimeMs
      ) {
        throw new TrustedOperationError('INTERACTION_REQUIRED');
      }
      // The Vault record and its TOTP seed are confined to this service. Only
      // an ephemeral password/code reaches the registered private worker sink.
      releaseStarted = true;
      await withScopedSecretInput(factor, input, receiver);
    } catch (error) {
      if (error instanceof TrustedOperationError) throw error;
      throw new TrustedOperationError(releaseStarted ? 'OUTCOME_UNKNOWN' : 'AUTH_FAILED');
    }
  }
}
