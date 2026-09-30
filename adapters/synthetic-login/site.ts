import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { SYNTHETIC_CREDENTIAL } from '../../services/secret-service/synthetic-fixture.js';
import { generateTotp } from '../../services/secret-service/totp.js';

export type SyntheticAttack =
  | 'none'
  | 'wrong-origin'
  | 'cross-origin-frame'
  | 'wrong-account'
  | 'recovery'
  | 'unexpected-otp';
export interface SyntheticSite {
  origin: string;
  submissions(): { password: number; totp: number };
  close(): Promise<void>;
}

function same(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function body(request: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    length += buffer.length;
    if (length > 2048) throw new Error('INVALID_REQUEST');
    chunks.push(buffer);
  }
  const buffer = Buffer.concat(chunks);
  try {
    return new URLSearchParams(buffer.toString());
  } finally {
    buffer.fill(0);
    chunks.forEach((chunk) => chunk.fill(0));
  }
}

function html(response: ServerResponse, content: string): void {
  response.writeHead(200, {
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'content-security-policy':
      "default-src 'none'; script-src 'none'; connect-src 'none'; frame-src http://127.0.0.1:*; form-action 'self'; base-uri 'none'; object-src 'none'",
  });
  response.end(
    `<!doctype html><html><head><meta charset="utf-8"><title>Synthetic Login Test Fixture</title></head><body>${content}</body></html>`,
  );
}

function redirect(response: ServerResponse, target: string): void {
  response.writeHead(303, { location: target, 'cache-control': 'no-store' });
  response.end();
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('SITE_UNAVAILABLE'));
        return;
      }
      resolve(address.port);
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(new Error('SITE_UNAVAILABLE')) : resolve()));
    server.closeAllConnections();
  });
}

/** Fixed synthetic credentials and attack cases only. This is not an enrollment API. */
export async function startSyntheticSite(
  options: { attack?: SyntheticAttack; now?: () => number; port?: number } = {},
): Promise<SyntheticSite> {
  const attack = options.attack ?? 'none';
  const now = options.now ?? Date.now;
  let passwordSubmissions = 0;
  let totpSubmissions = 0;
  const passwordChallenges = new Set<string>();
  const sessions = new Set<string>();
  let alternate: Server | undefined;
  let alternateOrigin = '';
  if (attack === 'wrong-origin' || attack === 'cross-origin-frame') {
    alternate = createServer((_request, response) =>
      html(
        response,
        '<form data-auth-step="password" data-account="acct_synthetic"><input id="password" type="password"></form>',
      ),
    );
    alternateOrigin = `http://127.0.0.1:${await listen(alternate)}`;
  }
  const server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1');
      const cookies = request.headers.cookie ?? '';
      const challenge = /(?:^|;\s*)synthetic_challenge=([a-f0-9]+)/.exec(cookies)?.[1];
      const session = /(?:^|;\s*)synthetic_session=([a-f0-9]+)/.exec(cookies)?.[1];
      if (request.method === 'GET' && url.pathname === '/login') {
        if (attack === 'wrong-origin') {
          redirect(response, `${alternateOrigin}/login`);
          return;
        }
        if (attack === 'cross-origin-frame') {
          html(
            response,
            `<iframe name="credential-inputs" src="${alternateOrigin}/login"></iframe>`,
          );
          return;
        }
        html(
          response,
          '<form id="login-form" method="post" action="/password" data-auth-step="password" data-account="acct_synthetic"><label>Username<input id="username" name="username" autocomplete="off" value="synthetic-user" readonly></label><label>Password<input id="password" type="password" name="password" autocomplete="off"></label><button id="password-submit" type="submit">Sign in</button></form>',
        );
        return;
      }
      if (request.method === 'POST' && url.pathname === '/password') {
        passwordSubmissions += 1;
        const input = await body(request);
        if (
          !same(input.get('username') ?? '', SYNTHETIC_CREDENTIAL.username) ||
          !same(input.get('password') ?? '', SYNTHETIC_CREDENTIAL.password)
        ) {
          response.writeHead(401);
          response.end('Authentication failed');
          return;
        }
        if (attack === 'recovery') {
          redirect(response, '/recovery');
          return;
        }
        const token = randomBytes(24).toString('hex');
        passwordChallenges.add(token);
        response.setHeader(
          'set-cookie',
          `synthetic_challenge=${token}; HttpOnly; SameSite=Strict; Path=/`,
        );
        redirect(response, '/totp');
        return;
      }
      if (
        request.method === 'GET' &&
        url.pathname === '/totp' &&
        challenge &&
        passwordChallenges.has(challenge)
      ) {
        if (attack === 'unexpected-otp') {
          html(response, '<main data-interaction="push-approval">Approve on another device</main>');
          return;
        }
        html(
          response,
          '<form id="totp-form" method="post" action="/otp" data-auth-step="totp" data-account="acct_synthetic"><label>One-time code<input id="totp" name="totp" inputmode="numeric" autocomplete="off"></label><button id="totp-submit" type="submit">Verify</button></form>',
        );
        return;
      }
      if (
        request.method === 'POST' &&
        url.pathname === '/otp' &&
        challenge &&
        passwordChallenges.delete(challenge)
      ) {
        totpSubmissions += 1;
        const input = await body(request);
        const expected = generateTotp(
          SYNTHETIC_CREDENTIAL.totpSeed,
          now(),
          SYNTHETIC_CREDENTIAL.totp,
        );
        if (!same(input.get('totp') ?? '', expected)) {
          response.writeHead(401);
          response.end('Authentication failed');
          return;
        }
        const token = randomBytes(24).toString('hex');
        sessions.add(token);
        response.setHeader('set-cookie', [
          `synthetic_session=${token}; HttpOnly; SameSite=Strict; Path=/`,
          'synthetic_challenge=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/',
        ]);
        redirect(response, '/profile');
        return;
      }
      if (
        request.method === 'GET' &&
        url.pathname === '/profile' &&
        session &&
        sessions.has(session)
      ) {
        const account = attack === 'wrong-account' ? 'acct_other' : 'acct_synthetic';
        html(
          response,
          `<main id="profile" data-authenticated="true" data-account="${account}"><h1>Synthetic Owner</h1><p>Read-only synthetic profile.</p></main>`,
        );
        return;
      }
      if (request.method === 'GET' && url.pathname === '/recovery') {
        html(response, '<main data-interaction="recovery">Recovery required</main>');
        return;
      }
      response.writeHead(404, { 'cache-control': 'no-store' });
      response.end('Not found');
    })().catch(() => {
      if (!response.headersSent) response.writeHead(400);
      response.end('Request failed');
    });
  });
  const port =
    options.port === undefined
      ? await listen(server)
      : await new Promise<number>((resolve, reject) => {
          server.once('error', reject);
          server.listen(options.port, '127.0.0.1', () => {
            const address = server.address();
            if (!address || typeof address === 'string') {
              reject(new Error('SITE_UNAVAILABLE'));
              return;
            }
            resolve(address.port);
          });
        });
  const origin = `http://127.0.0.1:${port}`;
  return {
    origin,
    submissions: () => ({ password: passwordSubmissions, totp: totpSubmissions }),
    close: async () => {
      await close(server);
      if (alternate) await close(alternate);
    },
  };
}
