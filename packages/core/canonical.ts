import { createHash } from 'node:crypto';

/** Canonical JSON v1: UTF-8, recursively sorted object keys, arrays preserve order.
 * Rejects non-JSON values rather than silently changing the signed representation. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean')
    return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new TypeError('Noncanonical number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    const object = value as Record<string, unknown>;
    return `{${Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
      .join(',')}}`;
  }
  throw new TypeError('Non-JSON canonical value');
}
export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), 'utf8');
}
export function sha256(value: string | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}
export function canonicalDigest(value: unknown): string {
  return sha256(canonicalBytes(value));
}
