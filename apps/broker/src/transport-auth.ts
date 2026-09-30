import { createHash, timingSafeEqual } from 'node:crypto';
import type { AgentPrincipal } from './gateway.js';

export const tokenDigest = (token: string): string =>
  createHash('sha256').update(token).digest('hex');
export interface PairedClient extends AgentPrincipal {
  tokenHash: string;
  revokedAt?: string;
}
export function digestMatches(actual: string, expected: string): boolean {
  if (!/^[0-9a-f]{64}$/.test(expected)) return false;
  return timingSafeEqual(Buffer.from(tokenDigest(actual), 'hex'), Buffer.from(expected, 'hex'));
}
export function bearer(header: string | undefined): string | undefined {
  if (!header || header.length > 300 || !/^Bearer [A-Za-z0-9_-]{32,256}$/.test(header))
    return undefined;
  return header.slice(7);
}
export function authenticateClient(
  header: string | undefined,
  clients: PairedClient[],
): AgentPrincipal | undefined {
  const token = bearer(header);
  if (!token) return;
  const record = clients.find((c) => !c.revokedAt && digestMatches(token, c.tokenHash));
  if (!record) return;
  return { ownerId: record.ownerId, clientId: record.clientId, workloadId: record.workloadId };
}
