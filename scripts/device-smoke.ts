import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { randomUUID } from 'node:crypto';
import { lstat, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { z } from 'zod';

// Synthetic physical-device test driver. It has only paired agent authority:
// it cannot enroll/confirm a device, approve, change policy, or retrieve secrets.
const requestFile = resolve('.local/device-smoke-request');
const client = new Client({ name: 'boring.login-device-smoke', version: '0.1.0' });
const opaqueRef = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[a-zA-Z0-9_-]+$/);
const states = z.object({
  request_id: opaqueRef,
  state: z.enum([
    'CREATED',
    'INSPECTING',
    'POLICY_EVALUATING',
    'CLASSIFYING',
    'AWAITING_APPROVAL',
    'AUTHORIZED',
    'EXECUTING',
    'VERIFYING',
    'SUCCEEDED',
    'DENIED',
    'FAILED',
    'EXPIRED',
    'CANCELLED',
    'INTERACTION_REQUIRED',
    'OUTCOME_UNKNOWN',
  ]),
  session_ref: z.string().optional(),
});
async function privateText(path: string): Promise<string> {
  const info = await lstat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0 || info.size > 4096)
    throw new Error('PRIVATE_FILE_REQUIRED');
  return (await readFile(path, 'utf8')).trim();
}
async function currentRequestID(): Promise<string> {
  return opaqueRef.parse(await privateText(requestFile));
}
function reportState(payload: unknown, requestID: string): void {
  const status = states.parse(payload);
  if (status.request_id !== requestID) throw new Error('INVALID_RESPONSE');
  // This explicit observation allowlist never prints session refs, delivery
  // metadata, server payloads or a raw MCP/provider exception.
  process.stdout.write(JSON.stringify({ request_id: requestID, state: status.state }) + '\n');
}
async function call(name: string, args: Record<string, unknown> = {}) {
  const result = await client.callTool({ name, arguments: args });
  if (result.isError) throw new Error('BROKER_REFUSED');
  const content = result.content as Array<{ type: string; text?: string }>;
  if (content.length !== 1 || content[0]?.type !== 'text' || !content[0].text)
    throw new Error('INVALID_RESPONSE');
  return JSON.parse(content[0].text) as unknown;
}

try {
  const command = z.enum(['request', 'wait', 'status', 'cancel']).parse(process.argv[2]);
  const token = await privateText(resolve('.local/client-token'));
  await client.connect(
    new StreamableHTTPClientTransport(new URL('http://127.0.0.1:3210/mcp'), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    }),
  );
  const capabilities = z
    .object({ synthetic_only: z.literal(true), production_credentials_enabled: z.literal(false) })
    .parse(await call('auth.capabilities'));
  void capabilities;
  if (command === 'request') {
    const context = z
      .object({ context_ref: z.string() })
      .parse(await call('auth.inspect', { target_ref: 'browser_target_synthetic' }));
    const request = states.parse(
      await call('auth.request', {
        context_ref: context.context_ref,
        account_ref: 'acct_synthetic',
        operation: 'sign_in',
        workload_ref: 'workload_local',
        purpose:
          'Physical-device test: sign in to the local synthetic account and read its test profile.',
        idempotency_key: `device_test_${randomUUID()}`,
      }),
    );
    await writeFile(requestFile, request.request_id + '\n', { mode: 0o600 });
    process.stdout.write(`Synthetic request ${request.request_id}: ${request.state}\n`);
    process.stdout.write(
      'Review it on the paired physical iPhone. No approval is simulated by this driver.\n',
    );
  } else if (command === 'wait') {
    const requestID = await currentRequestID();
    const deadline = Date.now() + 180_000;
    let previous = '';
    while (Date.now() < deadline) {
      const status = states.parse(await call('auth.status', { request_id: requestID }));
      if (status.request_id !== requestID) throw new Error('INVALID_RESPONSE');
      if (status.state !== previous) {
        process.stdout.write(`Synthetic device test: ${status.state}\n`);
        previous = status.state;
      }
      if (status.state === 'SUCCEEDED') {
        if (!status.session_ref) throw new Error('INVALID_RESPONSE');
        try {
          z.object({ account_id: z.literal('acct_synthetic') }).parse(
            await call('session.perform', {
              session_ref: status.session_ref,
              operation: 'synthetic.read_profile',
              arguments: {},
            }),
          );
        } finally {
          await call('session.end', { session_ref: status.session_ref });
        }
        process.stdout.write('Restricted synthetic profile read passed; session ended.\n');
        break;
      }
      if (
        [
          'DENIED',
          'FAILED',
          'EXPIRED',
          'CANCELLED',
          'INTERACTION_REQUIRED',
          'OUTCOME_UNKNOWN',
        ].includes(status.state)
      )
        throw new Error('DEVICE_TEST_NOT_SUCCEEDED');
      await new Promise<void>((done) => setTimeout(done, 3_000));
    }
    if (previous !== 'SUCCEEDED') throw new Error('DEVICE_TEST_WAIT_TIMEOUT');
  } else if (command === 'status') {
    const requestID = await currentRequestID();
    reportState(await call('auth.status', { request_id: requestID }), requestID);
  } else if (command === 'cancel') {
    const requestID = await currentRequestID();
    reportState(await call('auth.cancel', { request_id: requestID }), requestID);
  }
} catch {
  process.stderr.write(
    'Device test did not complete. Use: npx tsx scripts/device-smoke.ts request|wait|status|cancel. Check broker/device state in the owner console.\n',
  );
  process.exitCode = 1;
} finally {
  await client.close().catch(() => undefined);
}
