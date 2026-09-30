import { generateKeyPairSync, sign } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { chromium } from 'playwright';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { startSyntheticSite } from '../../adapters/synthetic-login/site.js';
import {
  SettingsFile,
  newSettings,
  newToken,
  syntheticTrustedConfig,
} from '../../apps/broker/src/config.js';
import { createRuntime } from '../../apps/broker/src/runtime.js';
import { PostgresStore, type QueryPool } from '../../packages/core/index.js';

// Local PostgreSQL-engine/Chromium regression. This does not claim an external
// PostgreSQL deployment or physical biometric approval; the key is test-only.
describe.runIf(existsSync(chromium.executablePath()))('JSONB-backed protected runtime', () => {
  it('completes signed approval, one-use permits, browser login and restricted read through the real bridge', async () => {
    const site = await startSyntheticSite();
    const directory = await mkdtemp(join(tmpdir(), 'boring-login-jsonb-runtime-'));
    const database = new PGlite();
    let runtime: Awaited<ReturnType<typeof createRuntime>> | undefined;
    try {
      const settings = newSettings(newToken(), newToken());
      settings.trusted = syntheticTrustedConfig(site.origin, 'manual');
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      settings.trusted.devices.push({
        id: 'device_synthetic_jsonb',
        ownerId: 'owner_local',
        publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        displayName: 'Synthetic JSONB protocol key',
        assuranceProfile: 'SYNTHETIC_TEST_KEY',
      });
      const file = new SettingsFile(join(directory, 'broker.json'), settings);
      await file.save();
      const pool: QueryPool = {
        query: async (sql, values) =>
          (await database.query(sql, values)) as { rows: Array<Record<string, unknown>> },
      };
      runtime = await createRuntime(file, new PostgresStore(pool), site.origin);
      const caller = {
        ownerId: 'owner_local',
        clientId: 'client_local',
        workloadId: 'workload_local',
      };
      const inspected = z
        .object({ context_ref: z.string() })
        .parse(await runtime.api.inspect(caller, 'browser_target_synthetic'));
      const request = z.object({ request_id: z.string(), state: z.string() }).parse(
        await runtime.api.request(caller, {
          context_ref: inspected.context_ref,
          account_ref: 'acct_synthetic',
          operation: 'sign_in',
          workload_ref: caller.workloadId,
          purpose: 'Verify synthetic PostgreSQL JSONB browser integration.',
          idempotency_key: 'jsonb_runtime',
        }),
      );
      expect(request.state).toBe('AWAITING_APPROVAL');
      const challenge = await runtime.controller.createChallenge(
        caller.ownerId,
        request.request_id,
        'device_synthetic_jsonb',
      );
      await runtime.control.approve({
        challenge_id: challenge.challenge_id,
        device_id: 'device_synthetic_jsonb',
        signature_base64: sign('sha256', Buffer.from(challenge.payload_base64, 'base64'), {
          key: privateKey,
          dsaEncoding: 'der',
        }).toString('base64'),
      });
      await runtime.waitForExecution(request.request_id);
      const status = await runtime.controller.status(caller, request.request_id);
      expect(status.state).toBe('SUCCEEDED');
      if (status.state !== 'SUCCEEDED' || !status.session_ref)
        throw new Error('AUTHENTICATION_EXPECTED');
      expect(
        await runtime.api.perform(caller, status.session_ref, 'synthetic.read_profile'),
      ).toEqual({
        account_id: 'acct_synthetic',
        display_name: 'Synthetic Owner',
        message: 'Synthetic read access verified.',
      });
      expect(site.submissions()).toEqual({ password: 1, totp: 1 });
      const plan = (
        await database.query<{ plan: Array<Record<string, string>> }>(
          "SELECT body->'factorPlan' AS plan FROM execution_attempts WHERE request_id=$1",
          [request.request_id],
        )
      ).rows[0]!.plan;
      expect(Object.keys(plan[0]!)).toEqual(['step', 'factor']);
      expect(
        (
          await database.query<{ count: number }>(
            'SELECT count(*)::int AS count FROM secret_permit_consumptions',
          )
        ).rows[0]!.count,
      ).toBe(2);
      await runtime.api.end(caller, status.session_ref);
      await expect(
        runtime.api.perform(caller, status.session_ref, 'synthetic.read_profile'),
      ).rejects.toMatchObject({ code: 'SESSION_EXPIRED' });
    } finally {
      await runtime?.close();
      await database.close();
      await site.close();
      await rm(directory, { recursive: true, force: true });
    }
  });
});
