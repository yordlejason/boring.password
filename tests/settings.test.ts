import { describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, rm, mkdir } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { MemoryStore } from '../packages/core/index.js';
import {
  SettingsFile,
  newSettings,
  newToken,
  syntheticTrustedConfig,
} from '../apps/broker/src/config.js';
import { createRuntime } from '../apps/broker/src/runtime.js';
import { tokenDigest } from '../apps/broker/src/transport-auth.js';

async function fixture(blocked = false) {
  const dir = await mkdtemp(join(tmpdir(), 'boring-login-settings-')),
    settings = newSettings(newToken(), newToken());
  settings.trusted = syntheticTrustedConfig();
  const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  settings.deviceTransports.push({
    id: 'device_test',
    ownerId: settings.ownerId,
    name: 'Test device',
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    tokenHash: tokenDigest(newToken()),
    status: 'PENDING_CONFIRMATION',
    createdAt: new Date().toISOString(),
  });
  const path = blocked ? join(dir, 'regular-file', 'config.json') : join(dir, 'config.json');
  if (blocked) await writeFile(join(dir, 'regular-file'), 'blocker');
  const file = new SettingsFile(path, settings),
    runtime = await createRuntime(file, new MemoryStore(), 'http://127.0.0.1:3212');
  return {
    file,
    runtime,
    close: async () => {
      await runtime.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
}
describe('durable device trust changes', () => {
  it('persists before publishing confirmation, preserves core config identity, and rejects competing confirmation', async () => {
    const app = await fixture();
    try {
      const identity = app.file.settings.trusted;
      const results = await Promise.allSettled([
        app.runtime.control.confirmDevice('owner_local', 'device_test'),
        app.runtime.control.confirmDevice('owner_local', 'device_test'),
      ]);
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
      expect(app.file.settings.trusted).toBe(identity);
      expect(app.runtime.controller.config.devices).toHaveLength(1);
      expect((await SettingsFile.open(app.file.path)).settings.deviceTransports[0]?.status).toBe(
        'ACTIVE',
      );
      expect(() => app.file.assertAuthorityReady()).not.toThrow();
    } finally {
      await app.close();
    }
  });
  it('a failed confirmation never activates a key and suspends authority until a successful save', async () => {
    const app = await fixture(true);
    try {
      const updating = app.runtime.control.confirmDevice('owner_local', 'device_test');
      expect(() => app.file.assertAuthorityReady()).toThrow('POLICY_DENIED');
      await expect(updating).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
      expect(app.file.settings.deviceTransports[0]?.status).toBe('PENDING_CONFIRMATION');
      expect(app.runtime.controller.config.devices).toHaveLength(0);
      expect(() => app.file.assertAuthorityReady()).toThrow('SECURITY_STATE_UNPERSISTED');
      await expect(
        app.runtime.api.request(
          { ownerId: 'owner_local', clientId: 'client_local', workloadId: 'workload_local' },
          {
            context_ref: 'ctx_synthetic',
            account_ref: 'acct_synthetic',
            operation: 'sign_in',
            workload_ref: 'workload_local',
            purpose: 'test',
            idempotency_key: 'one',
          },
        ),
      ).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
    } finally {
      await app.close();
    }
  });
  it('failed revocation suspends all authority instead of acknowledging an unpersisted change', async () => {
    const app = await fixture(true);
    try {
      const device = app.file.settings.deviceTransports[0]!;
      device.status = 'ACTIVE';
      app.file.settings.trusted.devices.push({
        id: device.id,
        ownerId: device.ownerId,
        publicKeyPem: device.publicKeyPem,
        displayName: device.name,
        assuranceProfile: 'SYNTHETIC_TEST_KEY',
      });
      await expect(
        app.runtime.control.revokeDevice('owner_local', 'device_test'),
      ).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
      expect(() => app.file.assertAuthorityReady()).toThrow('SECURITY_STATE_UNPERSISTED');
      await expect(
        app.runtime.control.challenges('owner_local', 'device_test'),
      ).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
      // Restore IO: unrelated settings writes must not supersede a failed
      // security intent. The exact owner revocation remains the repair path.
      await rm(dirname(app.file.path));
      await mkdir(dirname(app.file.path));
      await expect(
        app.file.update('unrelated-pairing', (draft) => {
          draft.pairings.push({
            id: 'new_pairing',
            codeHash: tokenDigest(newToken()),
            expiresAt: new Date(Date.now() + 300000).toISOString(),
          });
        }),
      ).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
      expect(app.file.settings.pairings).toHaveLength(0);
      expect(() => app.file.assertAuthorityReady()).toThrow('SECURITY_STATE_UNPERSISTED');
      await app.runtime.control.revokeDevice('owner_local', 'device_test');
      expect(() => app.file.assertAuthorityReady()).not.toThrow();
      expect(app.file.settings.deviceTransports[0]?.status).toBe('REVOKED');
      expect(app.runtime.controller.config.devices[0]?.revokedAt).toBeDefined();
    } finally {
      await app.close();
    }
  });
  it('failed staged enrollment leaves the pairing code unconsumed and creates no orphan token', async () => {
    const app = await fixture(true);
    try {
      app.file.settings.pairings.push({
        id: 'pairing_test',
        codeHash: tokenDigest(newToken()),
        expiresAt: new Date(Date.now() + 300000).toISOString(),
      });
      await expect(
        app.file.update('enroll:test', (draft) => {
          draft.pairings[0]!.consumedAt = new Date().toISOString();
          draft.deviceTransports.push({ ...draft.deviceTransports[0]!, id: 'orphan_device' });
        }),
      ).rejects.toMatchObject({ code: 'SECURITY_STATE_UNPERSISTED' });
      expect(app.file.settings.pairings[0]?.consumedAt).toBeUndefined();
      expect(app.file.settings.deviceTransports).toHaveLength(1);
    } finally {
      await app.close();
    }
  });
});
