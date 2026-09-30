import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
import type {
  BrokerPort,
  ConsumedPermit,
  ExecutionBinding,
  SecretFactor,
} from '../browser-worker/contracts.js';
import { TrustedOperationError } from '../browser-worker/contracts.js';
import { SYNTHETIC_CREDENTIAL } from './synthetic-fixture.js';
import { generateTotp, totpLifetimeMs } from './totp.js';

export interface TrustedClock {
  now(): number;
  healthy(): boolean;
  wait(milliseconds: number): Promise<void>;
}

/** Detects clock jumps; production deployments additionally require monitored time synchronization. */
export function systemTrustedClock(): TrustedClock {
  const wall = Date.now();
  const monotonic = performance.now();
  return {
    now: () => Date.now(),
    healthy: () => Math.abs(Date.now() - wall - (performance.now() - monotonic)) < 1000,
    wait: (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  };
}

export interface PrivateSecretReceiver {
  /** This callback is trusted-worker-only and must never be exposed by MCP/HTTP. */
  injectPassword(value: string): Promise<void>;
  injectTotp(value: string): Promise<void>;
}

export interface TrustedSecretChannel {
  consumePasswordPermit(permitId: string, expected: ExecutionBinding): Promise<void>;
  consumeTotpPermit(permitId: string, expected: ExecutionBinding): Promise<void>;
}

export function assertExactPermit(
  permit: ConsumedPermit,
  expected: ExecutionBinding,
  factor: SecretFactor,
  now: number,
): void {
  const fields = [
    'requestId',
    'revision',
    'attemptId',
    'executionGeneration',
    'workerId',
    'runtimeId',
    'runtimeGeneration',
    'accountId',
    'credentialBindingVersion',
    'destination',
    'adapterId',
    'identityProvider',
    'relyingParty',
    'adapterVersion',
    'sessionActionProfile',
    'observationProfile',
  ] as const;
  if (
    fields.some((key) => permit[key] !== expected[key]) ||
    permit.factor !== factor ||
    permit.adapterStep !== (factor === 'password' ? 'enter_password' : 'enter_totp') ||
    permit.expiresAt <= now ||
    !isDeepStrictEqual(permit.factors, expected.factors) ||
    // Trusted metadata may cross JSONB/JSON boundaries; object-key insertion
    // order is irrelevant, but factor/step sequence and exact shape still bind.
    !isDeepStrictEqual(permit.factorPlan, expected.factorPlan)
  ) {
    throw new TrustedOperationError('POLICY_DENIED');
  }
}

/**
 * Synthetic implementation of a trusted secret service. This is not a general vault API.
 * The controller receives only metadata; the fixed test seed stays here. JavaScript
 * cannot guarantee erasure of strings, so production requires an isolated service host.
 */
export class SyntheticSecretService {
  readonly #broker: BrokerPort;
  readonly #clock: TrustedClock;
  readonly #minimumTotpLifetimeMs: number;

  constructor(
    broker: BrokerPort,
    options: { clock?: TrustedClock; minimumTotpLifetimeMs?: number } = {},
  ) {
    this.#broker = broker;
    this.#clock = options.clock ?? systemTrustedClock();
    this.#minimumTotpLifetimeMs = options.minimumTotpLifetimeMs ?? 5000;
    if (
      this.#minimumTotpLifetimeMs <= 0 ||
      this.#minimumTotpLifetimeMs >= SYNTHETIC_CREDENTIAL.totp.period * 1000
    ) {
      throw new TrustedOperationError('POLICY_DENIED');
    }
  }

  /** Wiring is performed by the trusted host, never by an agent-facing request. */
  connectTrustedWorker(receiver: PrivateSecretReceiver): TrustedSecretChannel {
    return Object.freeze({
      consumePasswordPermit: async (permitId: string, expected: ExecutionBinding) => {
        await this.#consume(permitId, expected, 'password', receiver);
      },
      consumeTotpPermit: async (permitId: string, expected: ExecutionBinding) => {
        await this.#consume(permitId, expected, 'totp', receiver);
      },
    });
  }

  async #consume(
    permitId: string,
    expected: ExecutionBinding,
    factor: SecretFactor,
    receiver: PrivateSecretReceiver,
  ): Promise<void> {
    let releaseStarted = false;
    try {
      if (!this.#clock.healthy()) throw new TrustedOperationError('INTERACTION_REQUIRED');
      if (factor === 'totp') {
        const remaining = totpLifetimeMs(this.#clock.now(), SYNTHETIC_CREDENTIAL.totp.period);
        if (remaining < this.#minimumTotpLifetimeMs) await this.#clock.wait(remaining + 20);
        if (!this.#clock.healthy()) throw new TrustedOperationError('INTERACTION_REQUIRED');
      }
      // Consumption happens before exact-version resolution, and cannot be retried.
      const permit = await this.#broker.consumePermit(permitId, {
        workerId: expected.workerId,
        runtimeId: expected.runtimeId,
        runtimeGeneration: expected.runtimeGeneration,
      });
      assertExactPermit(permit, expected, factor, this.#clock.now());
      if (
        permit.accountId !== SYNTHETIC_CREDENTIAL.accountId ||
        permit.credentialBindingVersion !== SYNTHETIC_CREDENTIAL.version
      ) {
        throw new TrustedOperationError('POLICY_DENIED');
      }
      if (factor === 'password') {
        releaseStarted = true;
        await receiver.injectPassword(SYNTHETIC_CREDENTIAL.password);
      } else {
        const now = this.#clock.now();
        if (
          !this.#clock.healthy() ||
          totpLifetimeMs(now, SYNTHETIC_CREDENTIAL.totp.period) < this.#minimumTotpLifetimeMs
        ) {
          throw new TrustedOperationError('INTERACTION_REQUIRED');
        }
        const code = generateTotp(SYNTHETIC_CREDENTIAL.totpSeed, now, SYNTHETIC_CREDENTIAL.totp);
        releaseStarted = true;
        await receiver.injectTotp(code);
      }
    } catch (error) {
      // Never forward a provider, DOM, Playwright, IPC, or raw exception message.
      if (error instanceof TrustedOperationError) throw error;
      throw new TrustedOperationError(releaseStarted ? 'OUTCOME_UNKNOWN' : 'AUTH_FAILED');
    }
  }
}
