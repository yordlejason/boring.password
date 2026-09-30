import express, { type Request, type Response } from 'express';
import { createServer, type Server } from 'node:http';
import { createPublicKey, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { NodeStreamableHTTPServerTransport } from '@modelcontextprotocol/node';
import { z } from 'zod';
import { createAgentServer, safeError, SlidingLimit, type AgentApi } from './gateway.js';
import { authenticateClient, bearer, digestMatches, tokenDigest } from './transport-auth.js';
import { newToken, type SettingsFile } from './config.js';
import type { Mode } from '../../../packages/core/index.js';

export interface OwnerPolicySummary {
  id: string;
  mode: Mode;
  version: number;
  enabled: boolean;
  auto_delegation_available: boolean;
}
export interface OwnerPolicyModeUpdate {
  mode: Mode;
  expected_version: number;
}

export interface ControlPlane {
  overview(ownerId: string): Promise<unknown>;
  challenges(
    ownerId: string,
    deviceId: string,
  ): Promise<Array<{ challenge_id: string; payload_base64: string; payload_digest: string }>>;
  approve(input: {
    challenge_id: string;
    device_id: string;
    signature_base64: string;
  }): Promise<unknown>;
  deny(ownerId: string, challengeId: string, deviceId: string): Promise<void>;
  confirmDevice(ownerId: string, deviceId: string): Promise<void>;
  revokeDevice(ownerId: string, deviceId: string): Promise<void>;
  denyRequest(ownerId: string, requestId: string): Promise<void>;
  setPolicyMode(
    ownerId: string,
    policyId: string,
    input: OwnerPolicyModeUpdate,
  ): Promise<OwnerPolicySummary>;
}
const identifier = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9_.:-]+$/);
const asyncRoute =
  (fn: (req: Request, res: Response) => Promise<unknown>) => (req: Request, res: Response) => {
    void fn(req, res).catch((error) => {
      if (!res.headersSent) res.status(400).json(safeError(error));
    });
  };
function fail(code: string): never {
  throw Object.assign(new Error(code), { code });
}
function securedApp(allowedHostnames: string[]) {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    let host: string;
    try {
      host = new URL(`http://${req.headers.host}`).hostname;
    } catch {
      res.status(403).json({ error: 'POLICY_DENIED' });
      return;
    }
    if (!allowedHostnames.includes(host)) {
      res.status(403).json({ error: 'POLICY_DENIED' });
      return;
    }
    const origin = req.headers.origin;
    // Browser requests must originate on this listener. Do not trust forwarded headers.
    if (
      origin &&
      origin !== `http://${req.headers.host}` &&
      origin !== `https://${req.headers.host}`
    ) {
      res.status(403).json({ error: 'POLICY_DENIED' });
      return;
    }
    res.set({
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy':
        "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    });
    next();
  });
  app.use(express.json({ limit: '32kb', strict: true }));
  return app;
}
export function createHttpServices(
  api: AgentApi,
  control: ControlPlane,
  file: SettingsFile,
  allowedHostnames = ['127.0.0.1', 'localhost'],
) {
  const limits = new SlidingLimit();
  const agent = securedApp(allowedHostnames),
    admin = securedApp(allowedHostnames);
  agent.get('/health', (_req, res) =>
    res.json({ status: 'ok', synthetic_only: true, production_credentials_enabled: false }),
  );
  agent.post(
    '/mcp',
    asyncRoute(async (req, res) => {
      const principal = authenticateClient(req.headers.authorization, file.settings.clients);
      if (!principal) {
        res.status(401).json({ error: 'AUTH_REQUIRED' });
        return;
      }
      file.assertAuthorityReady();
      // Reject browser-origin calls, including same-origin: MCP is a paired non-browser channel.
      if (req.headers.origin) {
        res.status(403).json({ error: 'POLICY_DENIED' });
        return;
      }
      limits.check(`http:${principal.ownerId}:${principal.clientId}`, 240, 60000);
      const server = createAgentServer(api, principal, limits);
      const transport = new NodeStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.once('close', () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    }),
  );
  agent.all('/mcp', (_req, res) => res.status(405).json({ error: 'INVALID_ARGUMENT' }));
  agent.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  const owner = (req: Request): string => {
    const token = bearer(req.headers.authorization);
    if (!token || !digestMatches(token, file.settings.adminTokenHash)) fail('CALLER_MISMATCH');
    limits.check('owner-admin', 120, 60000);
    return file.settings.ownerId;
  };
  const device = (req: Request) => {
    file.assertAuthorityReady();
    const token = bearer(req.headers.authorization);
    const record = token
      ? file.settings.deviceTransports.find(
          (d) => d.status !== 'REVOKED' && digestMatches(token, d.tokenHash),
        )
      : undefined;
    if (!record) fail('CALLER_MISMATCH');
    limits.check(`device:${record.id}`, 120, 60000);
    return record;
  };
  admin.get(
    '/',
    asyncRoute(async (_req, res) =>
      res
        .type('html')
        .send(await readFile(new URL('../../admin-web/index.html', import.meta.url), 'utf8')),
    ),
  );
  admin.get(
    '/app.js',
    asyncRoute(async (_req, res) =>
      res
        .type('application/javascript')
        .send(await readFile(new URL('../../admin-web/app.js', import.meta.url), 'utf8')),
    ),
  );
  admin.get(
    '/style.css',
    asyncRoute(async (_req, res) =>
      res
        .type('text/css')
        .send(await readFile(new URL('../../admin-web/style.css', import.meta.url), 'utf8')),
    ),
  );
  admin.get(
    '/admin/overview',
    asyncRoute(async (req, res) => res.json(await control.overview(owner(req)))),
  );
  admin.post(
    '/admin/policies/:id/mode',
    asyncRoute(async (req, res) => {
      const ownerId = owner(req),
        policyId = identifier.safeParse(req.params.id),
        input = z
          .object({
            mode: z.enum(['manual', 'safe', 'auto']),
            expected_version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
          })
          .strict()
          .safeParse(req.body);
      if (!policyId.success || !input.success) fail('INVALID_ARGUMENT');
      const policy = await control.setPolicyMode(ownerId, policyId.data, input.data);
      res.json({
        id: policy.id,
        mode: policy.mode,
        version: policy.version,
        enabled: policy.enabled,
        auto_delegation_available: policy.auto_delegation_available,
      });
    }),
  );
  admin.post(
    '/admin/pairings',
    asyncRoute(async (req, res) => {
      owner(req);
      z.object({}).strict().parse(req.body);
      limits.check('pairing', 5, 600000);
      const code = newToken(),
        expiresAt = new Date(Date.now() + 300000).toISOString();
      const pairingId = randomUUID();
      await file.update(`pairing:${pairingId}`, (draft) => {
        draft.pairings.push({ id: pairingId, codeHash: tokenDigest(code), expiresAt });
      });
      res
        .status(201)
        .json({ pairing_code: code, expires_at: expiresAt, broker_id: file.settings.brokerId });
    }),
  );
  admin.post(
    '/admin/devices/:id/confirm',
    asyncRoute(async (req, res) => {
      const ownerId = owner(req),
        id = identifier.parse(req.params.id);
      z.object({}).strict().parse(req.body);
      await control.confirmDevice(ownerId, id);
      res.json({ confirmed: true });
    }),
  );
  admin.post(
    '/admin/devices/:id/revoke',
    asyncRoute(async (req, res) => {
      const ownerId = owner(req),
        id = identifier.parse(req.params.id);
      z.object({}).strict().parse(req.body);
      await control.revokeDevice(ownerId, id);
      res.json({ revoked: true });
    }),
  );
  admin.post(
    '/admin/requests/:id/deny',
    asyncRoute(async (req, res) => {
      const ownerId = owner(req),
        id = identifier.parse(req.params.id);
      z.object({}).strict().parse(req.body);
      await control.denyRequest(ownerId, id);
      res.json({ denied: true });
    }),
  );
  // Pairing is a separate one-use owner-created path. It never activates a device by itself.
  admin.post(
    '/device/enroll',
    asyncRoute(async (req, res) => {
      limits.check('enrollment', 10, 600000);
      const input = z
        .object({
          pairing_code: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
          device_name: z.string().min(1).max(100),
          public_key: z.string().min(50).max(2048),
          key_algorithm: z.literal('P256_SHA256_DER'),
          assurance_profile: z.literal('OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE'),
        })
        .strict()
        .parse(req.body);
      let pem: string;
      try {
        const key = createPublicKey(input.public_key);
        if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
          fail('INVALID_ARGUMENT');
        pem = key.export({ format: 'pem', type: 'spki' }).toString();
      } catch {
        fail('INVALID_ARGUMENT');
      }
      const token = newToken(),
        id = `device_${randomUUID()}`;
      await file.update(`enroll:${tokenDigest(input.pairing_code)}`, (draft) => {
        const pairing = draft.pairings.find(
          (p) =>
            !p.consumedAt &&
            Date.parse(p.expiresAt) > Date.now() &&
            digestMatches(input.pairing_code, p.codeHash),
        );
        if (!pairing) fail('POLICY_DENIED');
        pairing.consumedAt = new Date().toISOString();
        draft.deviceTransports.push({
          id,
          ownerId: draft.ownerId,
          name: input.device_name,
          publicKeyPem: pem!,
          tokenHash: tokenDigest(token),
          status: 'PENDING_CONFIRMATION',
          createdAt: new Date().toISOString(),
        });
      });
      res.status(201).json({
        device_id: id,
        owner_id: file.settings.ownerId,
        broker_id: file.settings.brokerId,
        device_token: token,
        status: 'PENDING_CONFIRMATION',
      });
    }),
  );
  admin.get(
    '/device/challenges',
    asyncRoute(async (req, res) => {
      const record = device(req);
      const challenges =
        record.status === 'ACTIVE' ? await control.challenges(record.ownerId, record.id) : [];
      res.json({
        status: record.status,
        challenges: challenges.map((c) => ({
          challenge_id: c.challenge_id,
          payload_base64: c.payload_base64,
          payload_digest_sha256: c.payload_digest,
        })),
      });
    }),
  );
  admin.post(
    '/device/approve',
    asyncRoute(async (req, res) => {
      const record = device(req);
      const input = z
        .object({
          challenge_id: identifier,
          device_id: identifier,
          signature: z
            .string()
            .max(200)
            .regex(/^[A-Za-z0-9+/]+={0,2}$/),
        })
        .strict()
        .parse(req.body);
      if (record.status !== 'ACTIVE' || input.device_id !== record.id) fail('CALLER_MISMATCH');
      await control.approve({
        challenge_id: input.challenge_id,
        device_id: record.id,
        signature_base64: input.signature,
      });
      res.json({ accepted: true });
    }),
  );
  admin.post(
    '/device/deny',
    asyncRoute(async (req, res) => {
      const record = device(req),
        input = z
          .object({ challenge_id: identifier, device_id: identifier })
          .strict()
          .parse(req.body);
      if (record.status !== 'ACTIVE' || input.device_id !== record.id) fail('CALLER_MISMATCH');
      await control.deny(record.ownerId, input.challenge_id, record.id);
      res.json({ denied: true });
    }),
  );
  admin.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
  for (const app of [agent, admin])
    app.use((error: unknown, _req: Request, res: Response, _next: unknown) => {
      res.status(400).json(safeError(error));
    });
  return { agent: createServer(agent), admin: createServer(admin) };
}
export async function listen(server: Server, port = 0, host = '127.0.0.1'): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('LISTEN_FAILED');
  return address.port;
}
export const closeServer = (server: Server) =>
  new Promise<void>((resolve, reject) => {
    server.closeAllConnections();
    server.close((error) => (error ? reject(error) : resolve()));
  });
