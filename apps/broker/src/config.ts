import { randomBytes } from 'node:crypto';
import { readFile, writeFile, rename, mkdir, stat, open, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { z } from 'zod';
import { tokenDigest } from './transport-auth.js';

const id = z
    .string()
    .min(1)
    .max(200)
    .regex(/^[a-zA-Z0-9_.:-]+$/),
  version = z.number().int().positive();
const revoked = { revokedAt: z.string().datetime().optional() };
export const trustedConfigSchema = z
  .object({
    clients: z.array(
      z.object({ id, ownerId: id, displayName: z.string().max(200), ...revoked }).strict(),
    ),
    accounts: z.array(
      z
        .object({
          id,
          ownerId: id,
          displayName: z.string().max(200),
          credentialBindingVersion: version,
          synthetic: z.literal(true),
          enabled: z.boolean(),
        })
        .strict(),
    ),
    runtimes: z.array(
      z
        .object({
          id,
          ownerId: id,
          generation: version,
          workerId: id,
          protected: z.boolean(),
          enabled: z.boolean(),
        })
        .strict(),
    ),
    workloads: z.array(
      z.object({ id, ownerId: id, clientId: id, runtimeId: id, enabled: z.boolean() }).strict(),
    ),
    adapters: z.array(
      z
        .object({
          id,
          version: z.string(),
          allowedOrigins: z.array(z.string().url()),
          factors: z.array(
            z
              .object({
                factor: z.enum(['password', 'totp']),
                step: z.enum(['enter_password', 'enter_totp']),
              })
              .strict(),
          ),
          reviewed: z.boolean(),
          synthetic: z.literal(true),
        })
        .strict(),
    ),
    policies: z.array(
      z
        .object({
          id,
          ownerId: id,
          version,
          mode: z.enum(['manual', 'safe', 'auto']),
          enabled: z.boolean(),
          maxRequestSeconds: z.number().int().min(1).max(600),
          maxSessionSeconds: z.number().int().min(1).max(3600),
        })
        .strict(),
    ),
    contexts: z.array(
      z
        .object({
          id,
          targetRef: id,
          ownerId: id,
          clientId: id,
          runtimeId: id,
          accountIds: z.array(id),
          destination: z.string().url(),
          identityProvider: z.string().url(),
          relyingParty: z.string().url(),
          adapterId: id,
          adapterVersion: z.string(),
          policyId: id,
          actionProfile: id,
          observationProfile: id,
          enabled: z.boolean(),
        })
        .strict(),
    ),
    devices: z.array(
      z
        .object({
          id,
          ownerId: id,
          publicKeyPem: z.string().max(2048),
          displayName: z.string().max(200),
          assuranceProfile: z.enum([
            'OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE',
            'SYNTHETIC_TEST_KEY',
          ]),
          ...revoked,
        })
        .strict(),
    ),
    delegations: z.array(
      z
        .object({
          id,
          ownerId: id,
          clientId: id,
          accountId: id,
          destination: z.string().url(),
          adapterId: id,
          adapterVersion: z.string(),
          operation: z.literal('sign_in'),
          factors: z.array(z.enum(['password', 'totp'])),
          actionProfile: id,
          observationProfile: id,
          workloadId: id,
          runtimeId: id,
          policyId: id,
          policyVersion: version,
          credentialBindingVersion: version,
          maxSessionSeconds: z.number().int().positive().max(3600),
          expiresAt: z.string().datetime(),
          ...revoked,
        })
        .strict(),
    ),
    actionProfiles: z.array(
      z.object({ id, operations: z.array(z.literal('synthetic.read_profile')) }).strict(),
    ),
  })
  .strict();
const digest = z.string().regex(/^[0-9a-f]{64}$/);
export const settingsSchema = z
  .object({
    version: z.literal(1),
    brokerId: id,
    ownerId: id,
    syntheticOnly: z.literal(true),
    adminTokenHash: digest,
    clients: z.array(
      z
        .object({ ownerId: id, clientId: id, workloadId: id, tokenHash: digest, ...revoked })
        .strict(),
    ),
    trusted: trustedConfigSchema,
    pairings: z
      .array(
        z
          .object({
            id,
            codeHash: digest,
            expiresAt: z.string().datetime(),
            consumedAt: z.string().datetime().optional(),
          })
          .strict(),
      )
      .default([]),
    deviceTransports: z
      .array(
        z
          .object({
            id,
            ownerId: id,
            name: z.string().max(200),
            publicKeyPem: z.string().max(2048),
            tokenHash: digest,
            status: z.enum(['PENDING_CONFIRMATION', 'ACTIVE', 'REVOKED']),
            createdAt: z.string().datetime(),
          })
          .strict(),
      )
      .default([]),
    ownerPolicyChanges: z
      .array(
        z
          .object({
            ownerId: id,
            policyId: id,
            previousMode: z.enum(['manual', 'safe', 'auto']),
            mode: z.enum(['manual', 'safe', 'auto']),
            previousVersion: version,
            version,
            changedAt: z.string().datetime(),
          })
          .strict(),
      )
      .max(100)
      .default([]),
  })
  .strict();
export type Settings = z.infer<typeof settingsSchema>;
export const newToken = () => randomBytes(32).toString('base64url');
export function syntheticTrustedConfig(
  origin = 'http://127.0.0.1:3212',
  mode: 'manual' | 'safe' | 'auto' = 'manual',
): z.infer<typeof trustedConfigSchema> {
  return {
    clients: [{ id: 'client_local', ownerId: 'owner_local', displayName: 'Paired local client' }],
    accounts: [
      {
        id: 'acct_synthetic',
        ownerId: 'owner_local',
        displayName: 'Synthetic test account',
        credentialBindingVersion: 1,
        synthetic: true,
        enabled: true,
      },
    ],
    runtimes: [
      {
        id: 'runtime_synthetic',
        ownerId: 'owner_local',
        generation: 1,
        workerId: 'worker_synthetic',
        protected: true,
        enabled: true,
      },
    ],
    workloads: [
      {
        id: 'workload_local',
        ownerId: 'owner_local',
        clientId: 'client_local',
        runtimeId: 'runtime_synthetic',
        enabled: true,
      },
    ],
    adapters: [
      {
        id: 'synthetic-login',
        version: '1.0.0',
        allowedOrigins: [origin],
        factors: [
          { factor: 'password', step: 'enter_password' },
          { factor: 'totp', step: 'enter_totp' },
        ],
        reviewed: true,
        synthetic: true,
      },
    ],
    policies: [
      {
        id: 'policy_synthetic',
        ownerId: 'owner_local',
        version: 1,
        mode,
        enabled: true,
        maxRequestSeconds: 300,
        maxSessionSeconds: 600,
      },
    ],
    contexts: [
      {
        id: 'ctx_synthetic',
        targetRef: 'browser_target_synthetic',
        ownerId: 'owner_local',
        clientId: 'client_local',
        runtimeId: 'runtime_synthetic',
        accountIds: ['acct_synthetic'],
        destination: origin,
        identityProvider: origin,
        relyingParty: origin,
        adapterId: 'synthetic-login',
        adapterVersion: '1.0.0',
        policyId: 'policy_synthetic',
        actionProfile: 'synthetic_read_profile',
        observationProfile: 'synthetic_read_profile',
        enabled: true,
      },
    ],
    devices: [],
    delegations: [],
    actionProfiles: [{ id: 'synthetic_read_profile', operations: ['synthetic.read_profile'] }],
  };
}
export function newSettings(adminToken: string, clientToken: string): Settings {
  return settingsSchema.parse({
    version: 1,
    brokerId: 'broker_local',
    ownerId: 'owner_local',
    syntheticOnly: true,
    adminTokenHash: tokenDigest(adminToken),
    clients: [
      {
        ownerId: 'owner_local',
        clientId: 'client_local',
        workloadId: 'workload_local',
        tokenHash: tokenDigest(clientToken),
      },
    ],
    trusted: syntheticTrustedConfig(),
    pairings: [],
    deviceTransports: [],
  });
}
export class SettingsFile {
  private queue: Promise<void> = Promise.resolve();
  private pendingUpdates = 0;
  private readonly persistenceFaults = new Set<string>();
  constructor(
    readonly path: string,
    readonly settings: Settings,
  ) {}
  static async open(path: string): Promise<SettingsFile> {
    const info = await stat(path);
    if ((info.mode & 0o077) !== 0) throw new Error('CONFIG_PERMISSIONS');
    const settings = settingsSchema.parse(JSON.parse(await readFile(path, 'utf8')));
    return new SettingsFile(path, settings);
  }
  assertAuthorityReady(): void {
    if (this.persistenceFaults.size)
      throw Object.assign(new Error('SECURITY_STATE_UNPERSISTED'), {
        code: 'SECURITY_STATE_UNPERSISTED',
      });
    if (this.pendingUpdates)
      throw Object.assign(new Error('POLICY_DENIED'), { code: 'POLICY_DENIED' });
  }
  /** Only the failed security intent may repair its staged settings. Unrelated
   * writes must not overwrite an already persisted, unpublished change. */
  assertSecurityUpdateAllowed(mutationKey: string): void {
    if ([...this.persistenceFaults].some((key) => key !== mutationKey))
      throw Object.assign(new Error('SECURITY_STATE_UNPERSISTED'), {
        code: 'SECURITY_STATE_UNPERSISTED',
      });
  }
  async save(): Promise<void> {
    await this.update('save', () => {});
  }
  /** Stage changes under a serialized writer, persist, then publish to the live
   * controller. Authority is suspended while updates or IO failures are pending. */
  update<T>(
    mutationKey: string,
    change: (draft: Settings) => T,
    afterPersist?: (draft: Settings, result: T) => Promise<void>,
  ): Promise<T> {
    this.pendingUpdates++;
    const operation = this.queue
      .catch(() => {})
      .then(async () => {
        this.assertSecurityUpdateAllowed(mutationKey);
        const draft = structuredClone(this.settings);
        const result = change(draft);
        settingsSchema.parse(draft);
        try {
          await this.write(draft);
          if (afterPersist) await afterPersist(draft, result);
        } catch {
          this.persistenceFaults.add(mutationKey);
          throw Object.assign(new Error('SECURITY_STATE_UNPERSISTED'), {
            code: 'SECURITY_STATE_UNPERSISTED',
          });
        }
        // Keep the controller's trusted-config object identity, replacing its arrays
        // only after the proposed trust change has been durably written.
        const trusted = this.settings.trusted;
        Object.assign(trusted, draft.trusted);
        Object.assign(this.settings, draft, { trusted });
        // Only a successful retry of the same security intent repairs its fault.
        // Unrelated pairing/configuration writes cannot reactivate failed revocations.
        this.persistenceFaults.delete(mutationKey);
        return result;
      });
    const completed = operation.finally(() => {
      this.pendingUpdates--;
    });
    this.queue = completed.then(
      () => {},
      () => {},
    );
    return completed;
  }
  private async write(settings: Settings): Promise<void> {
    const bytes = JSON.stringify(settingsSchema.parse(settings), null, 2) + '\n';
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const temporary = `${this.path}.${randomBytes(8).toString('hex')}.tmp`;
    const handle = await open(temporary, 'wx', 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
      await handle.close();
      await rename(temporary, this.path);
    } catch (error) {
      await handle.close().catch(() => {});
      await unlink(temporary).catch(() => {});
      throw error;
    }
  }
}
