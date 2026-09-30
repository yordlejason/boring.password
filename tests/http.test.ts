import { afterEach, describe, expect, it } from 'vitest';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { SettingsFile, newSettings, newToken } from '../apps/broker/src/config.js';
import {
  createHttpServices,
  listen,
  closeServer,
  type ControlPlane,
  type OwnerPolicyModeUpdate,
} from '../apps/broker/src/http.js';
import type { AgentApi } from '../apps/broker/src/gateway.js';
import { tokenDigest } from '../apps/broker/src/transport-auth.js';
const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
});
async function setup() {
  const dir = await mkdtemp(join(tmpdir(), 'boring-login-http-'));
  cleanups.push(() => rm(dir, { recursive: true, force: true }));
  const ownerToken = newToken(),
    clientToken = newToken(),
    file = new SettingsFile(join(dir, 'config.json'), newSettings(ownerToken, clientToken));
  await file.save();
  const secret = 'SYNTHETIC-should-not-escape';
  const api: AgentApi = {
    capabilities: async () => ({
      protected_browser: true,
      password: true,
      totp: true,
      remote_biometric_approval: false,
      native_macos_auth: false,
      oauth: false,
      synthetic_only: true,
      production_credentials_enabled: false,
      secret,
    }),
    inspect: async () => ({
      context_ref: 'ctx_synthetic',
      authentication_required: true,
      destination: 'http://127.0.0.1:3212',
      supported_accounts: [],
      secret,
    }),
    request: async () => ({ request_id: 'req_test', state: 'AWAITING_APPROVAL', secret }),
    status: async () => ({
      request_id: 'req_test',
      state: 'EXECUTING',
      next_action: 'WAIT',
      secret,
    }),
    cancel: async () => ({
      request_id: 'req_test',
      state: 'CANCELLED',
      credential_delivery: 'PASSWORD_ALREADY_DELIVERED',
      secret,
    }),
    perform: async () => ({
      account_id: 'acct_synthetic',
      display_name: 'Synthetic Owner',
      message: 'test',
      secret,
    }),
    end: async () => ({ ended: true, secret }),
  };
  const policyUpdates: Array<{ ownerId: string; id: string; input: OwnerPolicyModeUpdate }> = [];
  const control: ControlPlane = {
    overview: async () => ({ requests: [], devices: [], policies: [] }),
    challenges: async () => [],
    approve: async () => ({ accepted: true }),
    deny: async () => {},
    confirmDevice: async () => {},
    revokeDevice: async () => {},
    denyRequest: async () => {},
    setPolicyMode: async (ownerId, id, input) => {
      policyUpdates.push({ ownerId, id, input: structuredClone(input) });
      return {
        id,
        mode: input.mode,
        version: input.expected_version + 1,
        enabled: true,
        auto_delegation_available: false,
        secret,
      };
    },
  };
  const servers = createHttpServices(api, control, file);
  const agentPort = await listen(servers.agent),
    adminPort = await listen(servers.admin);
  cleanups.push(
    () => closeServer(servers.agent),
    () => closeServer(servers.admin),
  );
  return {
    file,
    ownerToken,
    clientToken,
    agent: `http://127.0.0.1:${agentPort}`,
    admin: `http://127.0.0.1:${adminPort}`,
    secret,
    policyUpdates,
  };
}
describe('HTTP and MCP isolation', () => {
  it('negotiates with the official MCP client and strips debug fields from all output', async () => {
    const app = await setup();
    const client = new Client({ name: 'attacker-controlled-name', version: '1.0.0' });
    cleanups.push(() => client.close());
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${app.agent}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${app.clientToken}` } },
      }),
    );
    const listed = await client.listTools();
    expect(listed.tools).toHaveLength(7);
    const calls: [string, Record<string, unknown>][] = [
      ['auth.capabilities', {}],
      ['auth.inspect', { target_ref: 'browser_target_synthetic' }],
      [
        'auth.request',
        {
          context_ref: 'ctx_synthetic',
          account_ref: 'acct_synthetic',
          operation: 'sign_in',
          workload_ref: 'workload_local',
          purpose: 'test',
          idempotency_key: 'once',
        },
      ],
      ['auth.status', { request_id: 'req_test' }],
      ['auth.cancel', { request_id: 'req_test' }],
      [
        'session.perform',
        { session_ref: 'session_test', operation: 'synthetic.read_profile', arguments: {} },
      ],
      ['session.end', { session_ref: 'session_test' }],
    ];
    for (const [name, args] of calls) {
      const result = await client.callTool({ name, arguments: args });
      expect(result.isError).not.toBe(true);
      expect(JSON.stringify(result)).not.toContain(app.secret);
    }
    const refused = await client.callTool({
      name: 'auth.request',
      arguments: {
        context_ref: 'ctx_synthetic',
        account_ref: 'acct_synthetic',
        operation: 'sign_in',
        workload_ref: 'other',
        purpose: 'test',
        idempotency_key: 'twice',
      },
    });
    expect(refused.isError).toBe(true);
    expect(JSON.stringify(refused)).toContain('CALLER_MISMATCH');
  });
  it('cannot use agent credentials for owner routes or owner credentials for MCP', async () => {
    const app = await setup();
    expect(
      (
        await fetch(`${app.admin}/admin/overview`, {
          headers: { Authorization: `Bearer ${app.clientToken}` },
        })
      ).ok,
    ).toBe(false);
    expect(
      (
        await fetch(`${app.agent}/mcp`, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${app.ownerToken}`,
            'Content-Type': 'application/json',
          },
          body: '{}',
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await fetch(`${app.agent}/admin/overview`, {
          headers: { Authorization: `Bearer ${app.clientToken}` },
        })
      ).status,
    ).toBe(404);
    for (const path of ['/cdp', '/cookies', '/storage', '/trace', '/secrets', '/device/enroll'])
      expect((await fetch(`${app.agent}${path}`)).status).toBe(404);
  });
  it('requires one-use owner pairing and keeps enrollment pending until confirmation', async () => {
    const app = await setup(),
      headers = { Authorization: `Bearer ${app.ownerToken}`, 'Content-Type': 'application/json' };
    const pairing = await (
      await fetch(`${app.admin}/admin/pairings`, { method: 'POST', headers, body: '{}' })
    ).json();
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const input = {
      pairing_code: pairing.pairing_code,
      device_name: 'Synthetic device',
      public_key: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      key_algorithm: 'P256_SHA256_DER',
      assurance_profile: 'OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE',
    };
    const enroll = () =>
      fetch(`${app.admin}/device/enroll`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
    const [a, b] = await Promise.all([enroll(), enroll()]);
    expect([a.status, b.status].sort()).toEqual([201, 400]);
    const result = await (a.status === 201 ? a : b).json();
    expect(result.status).toBe('PENDING_CONFIRMATION');
    const challenges = await (
      await fetch(`${app.admin}/device/challenges`, {
        headers: { Authorization: `Bearer ${result.device_token}` },
      })
    ).json();
    expect(challenges).toEqual({ status: 'PENDING_CONFIRMATION', challenges: [] });
    expect(app.file.settings.trusted.devices).toHaveLength(0);
  });
  it('isolates policy mode changes to the authenticated owner listener and allowlists its response', async () => {
    const app = await setup(),
      deviceToken = newToken();
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    app.file.settings.deviceTransports.push({
      id: 'device_test',
      ownerId: app.file.settings.ownerId,
      name: 'Synthetic device',
      publicKeyPem: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      tokenHash: tokenDigest(deviceToken),
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
    });
    const body = JSON.stringify({ mode: 'safe', expected_version: 1 });
    for (const token of [undefined, app.clientToken, deviceToken]) {
      const response = await fetch(`${app.admin}/admin/policies/policy_synthetic/mode`, {
        method: 'POST',
        body,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      });
      expect(await response.json()).toEqual({ error: 'CALLER_MISMATCH' });
    }
    expect(app.policyUpdates).toHaveLength(0);
    expect(
      (
        await fetch(`${app.agent}/admin/policies/policy_synthetic/mode`, {
          method: 'POST',
          body,
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${app.clientToken}`,
          },
        })
      ).status,
    ).toBe(404);
    const response = await fetch(`${app.admin}/admin/policies/policy_synthetic/mode`, {
      method: 'POST',
      body,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${app.ownerToken}` },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      id: 'policy_synthetic',
      mode: 'safe',
      version: 2,
      enabled: true,
      auto_delegation_available: false,
    });
    expect(app.policyUpdates).toEqual([
      {
        ownerId: 'owner_local',
        id: 'policy_synthetic',
        input: { mode: 'safe', expected_version: 1 },
      },
    ]);
  });
  it('rejects malformed or extra policy input and hostile browser origin before a mode update', async () => {
    const app = await setup(),
      headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${app.ownerToken}` };
    for (const input of [
      {},
      { mode: 'unsafe', expected_version: 1 },
      { mode: 'safe', expected_version: '1' },
      { mode: 'safe', expected_version: true },
      { mode: 'safe', expected_version: 0 },
      { mode: 'safe', expected_version: 1.5 },
      { mode: 'safe', expected_version: Number.MAX_SAFE_INTEGER + 1 },
      { mode: 'safe', expected_version: 1, secret: 'SYNTHETIC-invalid-extra' },
    ]) {
      const response = await fetch(`${app.admin}/admin/policies/policy_synthetic/mode`, {
        method: 'POST',
        headers,
        body: JSON.stringify(input),
      });
      expect(await response.json()).toEqual({ error: 'INVALID_ARGUMENT' });
    }
    const invalidId = await fetch(`${app.admin}/admin/policies/invalid!/mode`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ mode: 'manual', expected_version: 1 }),
    });
    expect(await invalidId.json()).toEqual({ error: 'INVALID_ARGUMENT' });
    const origin = await fetch(`${app.admin}/admin/policies/policy_synthetic/mode`, {
      method: 'POST',
      headers: { ...headers, Origin: 'https://attacker.invalid' },
      body: JSON.stringify({ mode: 'auto', expected_version: 1 }),
    });
    expect(origin.status).toBe(403);
    const host = await new Promise<number>((resolve, reject) => {
      const request = httpRequest(
        `${app.admin}/admin/policies/policy_synthetic/mode`,
        {
          method: 'POST',
          headers: { ...headers, Host: 'attacker.invalid' },
        },
        (response) => {
          response.resume();
          resolve(response.statusCode!);
        },
      );
      request.on('error', reject);
      request.end(JSON.stringify({ mode: 'auto', expected_version: 1 }));
    });
    expect(host).toBe(403);
    expect(app.policyUpdates).toHaveLength(0);
  });
  it('rejects DNS rebinding, cross-origin browser calls and malformed JSON without echo', async () => {
    const app = await setup();
    const rebindingStatus = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(
        `${app.agent}/health`,
        { headers: { Host: 'attacker.invalid' } },
        (res) => {
          res.resume();
          resolve(res.statusCode!);
        },
      );
      req.on('error', reject);
      req.end();
    });
    expect(rebindingStatus).toBe(403);
    expect(
      (
        await fetch(`${app.admin}/admin/overview`, {
          headers: {
            Origin: 'https://attacker.invalid',
            Authorization: `Bearer ${app.ownerToken}`,
          },
        })
      ).status,
    ).toBe(403);
    const malformed = await fetch(`${app.agent}/mcp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"secret":"do-not-echo"',
    });
    expect(await malformed.text()).not.toContain('do-not-echo');
  });
});
