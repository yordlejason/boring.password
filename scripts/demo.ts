import { generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  SettingsFile,
  newSettings,
  newToken,
  syntheticTrustedConfig,
} from '../apps/broker/src/config.js';
import { createRuntime } from '../apps/broker/src/runtime.js';
import { MemoryStore } from '../packages/core/index.js';
import { startSyntheticSite } from '../adapters/synthetic-login/site.js';

export async function runSyntheticFlow(mode: 'manual' | 'safe' | 'auto') {
  const site = await startSyntheticSite(),
    directory = await mkdtemp(join(tmpdir(), 'boring-login-demo-'));
  const settings = newSettings(newToken(), newToken());
  settings.trusted = syntheticTrustedConfig(site.origin, mode);
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  settings.trusted.devices.push({
    id: 'device_synthetic',
    ownerId: 'owner_local',
    publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
    displayName: 'Synthetic protocol key',
    assuranceProfile: 'SYNTHETIC_TEST_KEY',
  });
  if (mode === 'auto')
    settings.trusted.delegations.push({
      id: 'delegation_synthetic',
      ownerId: 'owner_local',
      clientId: 'client_local',
      accountId: 'acct_synthetic',
      destination: site.origin,
      adapterId: 'synthetic-login',
      adapterVersion: '1.0.0',
      operation: 'sign_in',
      factors: ['password', 'totp'],
      actionProfile: 'synthetic_read_profile',
      observationProfile: 'synthetic_read_profile',
      workloadId: 'workload_local',
      runtimeId: 'runtime_synthetic',
      policyId: 'policy_synthetic',
      policyVersion: 1,
      credentialBindingVersion: 1,
      maxSessionSeconds: 600,
      expiresAt: new Date(Date.now() + 600000).toISOString(),
    });
  const file = new SettingsFile(join(directory, 'broker.json'), settings),
    store = new MemoryStore();
  await file.save();
  const runtime = await createRuntime(file, store, site.origin),
    caller = { ownerId: 'owner_local', clientId: 'client_local', workloadId: 'workload_local' };
  try {
    const inspected = await runtime.controller.inspect(caller, 'browser_target_synthetic');
    const request = (await runtime.api.request(caller, {
      context_ref: inspected.context_ref,
      account_ref: 'acct_synthetic',
      operation: 'sign_in',
      workload_ref: caller.workloadId,
      purpose: 'Read the synthetic test profile.',
      idempotency_key: `demo_${mode}`,
    })) as { request_id: string; state: string };
    const initialState = request.state;
    if (mode !== 'auto') {
      const challenge = await runtime.controller.createChallenge(
        caller.ownerId,
        request.request_id,
        'device_synthetic',
      );
      const signature = sign('sha256', Buffer.from(challenge.payload_base64, 'base64'), {
        key: privateKey,
        dsaEncoding: 'der',
      }).toString('base64');
      await runtime.control.approve({
        challenge_id: challenge.challenge_id,
        device_id: 'device_synthetic',
        signature_base64: signature,
      });
    }
    await runtime.waitForExecution(request.request_id);
    const status = await runtime.controller.status(caller, request.request_id);
    if (status.state !== 'SUCCEEDED' || !status.session_ref)
      throw new Error(`SYNTHETIC_FLOW_${status.state}`);
    const profile = await runtime.api.perform(caller, status.session_ref, 'synthetic.read_profile');
    await runtime.api.end(caller, status.session_ref);
    return {
      mode,
      initialState,
      status,
      profile,
      submissions: site.submissions(),
      audit: await runtime.controller.auditEvents(caller.ownerId),
    };
  } finally {
    await runtime.close();
    await site.close();
    await rm(directory, { recursive: true, force: true });
  }
}
if (process.argv[1]?.endsWith('/demo.ts')) {
  for (const mode of ['manual', 'safe', 'auto'] as const) {
    const flow = await runSyntheticFlow(mode);
    process.stdout.write(
      `${mode}: ${flow.initialState} → ${flow.status.state} → permitted profile read → session ended\n`,
    );
  }
  process.stdout.write(
    'Synthetic signing keys only. Physical-device biometrics and production isolation remain unverified.\n',
  );
}
