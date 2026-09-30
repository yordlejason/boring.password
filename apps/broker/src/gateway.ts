import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';

export interface AgentPrincipal {
  ownerId: string;
  clientId: string;
  workloadId: string;
}
export interface AgentApi {
  capabilities(principal: AgentPrincipal): Promise<unknown>;
  inspect(principal: AgentPrincipal, targetRef: string): Promise<unknown>;
  request(principal: AgentPrincipal, input: RequestArguments): Promise<unknown>;
  status(principal: AgentPrincipal, requestId: string): Promise<unknown>;
  cancel(principal: AgentPrincipal, requestId: string): Promise<unknown>;
  perform(principal: AgentPrincipal, sessionRef: string, operation: string): Promise<unknown>;
  end(principal: AgentPrincipal, sessionRef: string): Promise<unknown>;
}
const ref = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[a-zA-Z0-9_.:-]+$/);
export const requestArguments = z
  .object({
    context_ref: ref,
    account_ref: ref,
    operation: z.literal('sign_in'),
    workload_ref: ref,
    purpose: z.string().min(1).max(1000),
    idempotency_key: ref,
  })
  .strict();
export type RequestArguments = z.infer<typeof requestArguments>;
const states = z.enum([
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
]);
const codes = z.enum([
  'INVALID_ARGUMENT',
  'NOT_FOUND',
  'CALLER_MISMATCH',
  'IDEMPOTENCY_CONFLICT',
  'POLICY_DENIED',
  'CLASSIFIER_BLOCKED',
  'APPROVAL_REQUIRED',
  'APPROVAL_INVALID',
  'APPROVAL_REPLAY',
  'ADAPTER_UNSUPPORTED',
  'DESTINATION_MISMATCH',
  'ACCOUNT_MISMATCH',
  'INTERACTION_REQUIRED',
  'AUTH_FAILED',
  'OUTCOME_UNKNOWN',
  'SESSION_EXPIRED',
  'PERMIT_INVALID',
  'PERMIT_CONSUMED',
  'LEASE_CONFLICT',
  'RUNTIME_QUARANTINED',
  'REQUEST_EXPIRED',
  'INVALID_STATE',
  'PRODUCTION_CREDENTIALS_DISABLED',
  'SECURITY_STATE_UNPERSISTED',
  'RATE_LIMITED',
  'INTERNAL_ERROR',
]);
const statusResult = z.object({
  request_id: ref,
  revision: z.number().int().optional(),
  state: states,
  next_action: z.enum(['WAIT', 'APPROVE', 'NONE']).optional(),
  reason: codes.optional(),
  session_ref: ref.optional(),
});
const cancelResult = statusResult.extend({
  credential_delivery: z
    .enum([
      'NOT_DELIVERED',
      'POSSIBLY_DELIVERED',
      'PASSWORD_ALREADY_DELIVERED',
      'TOTP_ALREADY_DELIVERED',
      'PASSWORD_AND_TOTP_ALREADY_DELIVERED',
      'SECRETS_ALREADY_DELIVERED',
    ])
    .optional(),
});
export const toolNames = [
  'auth.capabilities',
  'auth.inspect',
  'auth.request',
  'auth.status',
  'auth.cancel',
  'session.perform',
  'session.end',
] as const;
export function safeError(error: unknown): { error: z.infer<typeof codes> } {
  const parsed = codes.safeParse(
    typeof error === 'object' && error !== null && 'code' in error ? error.code : undefined,
  );
  return { error: parsed.success ? parsed.data : 'INTERNAL_ERROR' };
}
export class SlidingLimit {
  private readonly entries = new Map<string, number[]>();
  constructor(private readonly now: () => number = Date.now) {}
  check(key: string, count: number, windowMs: number): void {
    const now = this.now();
    // Also bound attacker-controlled key retention.
    if (this.entries.size > 10000)
      for (const [k, ts] of this.entries)
        if ((ts.at(-1) ?? 0) < now - 900000) this.entries.delete(k);
    if (this.entries.size > 20000 && !this.entries.has(key))
      throw Object.assign(new Error('RATE_LIMITED'), { code: 'RATE_LIMITED' });
    const retained = (this.entries.get(key) ?? []).filter((t) => t > now - windowMs);
    if (retained.length >= count)
      throw Object.assign(new Error('RATE_LIMITED'), { code: 'RATE_LIMITED' });
    retained.push(now);
    this.entries.set(key, retained);
  }
}
/** One server per authenticated HTTP request; client-supplied names are never authority. */
export function createAgentServer(
  api: AgentApi,
  principal: AgentPrincipal,
  limits = new SlidingLimit(),
): McpServer {
  const server = new McpServer({ name: 'boring.login', version: '0.1.0' });
  const respond = async (operation: () => Promise<unknown>, schema: z.ZodType) => {
    try {
      limits.check(`tools:${principal.ownerId}:${principal.clientId}`, 240, 60000);
      const data = schema.parse(await operation()); // Explicit observation allowlist strips unknown fields.
      return { content: [{ type: 'text' as const, text: JSON.stringify(data) }] };
    } catch (error) {
      return {
        isError: true,
        content: [{ type: 'text' as const, text: JSON.stringify(safeError(error)) }],
      };
    }
  };
  server.registerTool(
    'auth.capabilities',
    {
      description: 'Supported, gated authentication capabilities for this caller.',
      inputSchema: z.object({}).strict(),
    },
    () =>
      respond(
        () => api.capabilities(principal),
        z.object({
          protected_browser: z.boolean(),
          password: z.boolean(),
          totp: z.boolean(),
          remote_biometric_approval: z.boolean(),
          native_macos_auth: z.literal(false),
          oauth: z.literal(false),
          synthetic_only: z.literal(true),
          production_credentials_enabled: z.literal(false),
        }),
      ),
  );
  server.registerTool(
    'auth.inspect',
    {
      description: 'Inspect a broker-enrolled target. No page source or credential access.',
      inputSchema: z.object({ target_ref: ref }).strict(),
    },
    ({ target_ref }) =>
      respond(
        () => api.inspect(principal, target_ref),
        z.object({
          context_ref: ref,
          authentication_required: z.boolean(),
          destination: z.string().max(2048),
          supported_accounts: z
            .array(z.object({ account_ref: ref, display_name: z.string().max(200) }))
            .max(50),
        }),
      ),
  );
  server.registerTool(
    'auth.request',
    {
      description:
        'Request authentication for an enrolled context; the broker derives the destination and factors.',
      inputSchema: requestArguments,
    },
    (input) =>
      respond(async () => {
        if (input.workload_ref !== principal.workloadId)
          throw Object.assign(new Error('CALLER_MISMATCH'), { code: 'CALLER_MISMATCH' });
        limits.check(
          `auth:${principal.ownerId}:${principal.clientId}:${input.account_ref}`,
          5,
          600000,
        );
        return api.request(principal, input);
      }, statusResult),
  );
  server.registerTool(
    'auth.status',
    {
      description: 'Get sanitized progress or an opaque restricted session reference.',
      inputSchema: z.object({ request_id: ref }).strict(),
    },
    ({ request_id }) => respond(() => api.status(principal, request_id), statusResult),
  );
  server.registerTool(
    'auth.cancel',
    {
      description:
        'Cancel remaining authentication steps and report whether credential delivery occurred.',
      inputSchema: z.object({ request_id: ref }).strict(),
    },
    ({ request_id }) => respond(() => api.cancel(principal, request_id), cancelResult),
  );
  server.registerTool(
    'session.perform',
    {
      description:
        'Perform the named read operation permitted by this session. Arbitrary scripting and security pages are unavailable.',
      inputSchema: z
        .object({
          session_ref: ref,
          operation: z.literal('synthetic.read_profile'),
          arguments: z.object({}).strict(),
        })
        .strict(),
    },
    ({ session_ref, operation }) =>
      respond(
        () => api.perform(principal, session_ref, operation),
        z.object({
          account_id: ref,
          display_name: z.string().max(200),
          message: z.string().max(200),
        }),
      ),
  );
  server.registerTool(
    'session.end',
    {
      description: 'Revoke this caller’s access and destroy the managed browser context.',
      inputSchema: z.object({ session_ref: ref }).strict(),
    },
    ({ session_ref }) =>
      respond(() => api.end(principal, session_ref), z.object({ ended: z.literal(true) })),
  );
  return server;
}
