import { createHmac } from 'node:crypto';

export interface TotpParameters {
  algorithm: 'sha1' | 'sha256' | 'sha512';
  digits: 6 | 8;
  period: number;
}

function decodeBase32(value: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = value.replace(/=+$/, '').toUpperCase();
  if (!normalized || /[^A-Z2-7]/.test(normalized)) throw new Error('INVALID_TOTP_ENROLLMENT');
  let bits = 0;
  let buffer = 0;
  const result: number[] = [];
  for (const character of normalized) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      result.push((buffer >>> bits) & 0xff);
    }
  }
  return Buffer.from(result);
}

/** RFC 6238, available only in the trusted secret-service package. */
export function generateTotp(seed: string, atMs: number, parameters: TotpParameters): string {
  if (
    !Number.isFinite(atMs) ||
    atMs < 0 ||
    !Number.isInteger(parameters.period) ||
    parameters.period < 1
  ) {
    throw new Error('INVALID_TOTP_ENROLLMENT');
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / parameters.period)));
  const key = decodeBase32(seed);
  try {
    const digest = createHmac(parameters.algorithm, key).update(counter).digest();
    const offset = digest[digest.length - 1]! & 0xf;
    const binary = digest.readUInt32BE(offset) & 0x7fffffff;
    return (binary % 10 ** parameters.digits).toString().padStart(parameters.digits, '0');
  } finally {
    key.fill(0);
  }
}

export function totpLifetimeMs(atMs: number, period: number): number {
  const stepMs = period * 1000;
  return stepMs - (atMs % stepMs);
}
