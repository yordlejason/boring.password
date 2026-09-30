import { describe, expect, it } from 'vitest';
import { chmod, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import {
  parseOptions,
  prepareDraft,
  privateText,
  publicListenerConfig,
  selectPhone,
  canReusePairingDraft,
  phoneEnrollmentStage,
  localBrokerHost,
} from '../scripts/onboard.mjs';

const environment = [
  'POSTGRES_PASSWORD=synthetic-private-marker',
  'BROKER_TLS_HOST=broker.test',
  'BROKER_TLS_IP=192.168.1.20',
  'BROKER_TLS_BIND=0.0.0.0',
  'BROKER_TLS_PORT=8443',
  'BROKER_AGENT_PORT=3210',
  'BROKER_OWNER_PORT=3211',
].join('\n');
const config = publicListenerConfig(environment);
const pin = 'a'.repeat(64);
function phone(identifier = '12345678-1234-1234-1234-123456789012', connected = true) {
  return {
    identifier,
    hardwareProperties: { platform: 'iOS', deviceType: 'iPhone', udid: identifier },
    deviceProperties: { developerModeStatus: 'enabled', name: 'Synthetic test phone' },
    connectionProperties: {
      pairingState: 'paired',
      tunnelState: connected ? 'connected' : 'disconnected',
    },
  };
}

describe('owner-side onboarding boundaries', () => {
  it('uses the verified Mac local hostname for a named HTTPS origin', () => {
    expect(localBrokerHost('Example-Mac\n')).toBe('example-mac.local');
    for (const invalid of ['../host', '', '-host', 'host.', 'host\nother', 'a'.repeat(64)])
      expect(() => localBrokerHost(invalid)).toThrow('CHOOSE_BROKER_HOST');
  });
  it('defaults to preparation without phone enrollment or refresh', () => {
    expect(parseOptions([])).toEqual({ iphone: false, pair: false, refresh: false, status: false });
    expect(parseOptions(['--pair']).iphone).toBe(true);
  });
  it.each([
    ['--status', '--iphone'],
    ['--status', '--pair'],
    ['--status', '--refresh'],
    ['--status', '--device', '12345678'],
    ['--status', '--team', 'ABCDEFGHIJ'],
    ['--iphone=false'],
    ['--refresh', '--refresh'],
    ['--unknown'],
    ['--device'],
  ])('refuses contradictory or unrecognized options %j', (...args) => {
    expect(() => parseOptions(args)).toThrow();
  });
  it('refuses public or loopback phone-address autoconfiguration', () => {
    expect(() => parseOptions(['--iphone', '--ip', '8.8.8.8'])).toThrow('PRIVATE_LAN_REQUIRED');
    expect(() => parseOptions(['--iphone', '--ip', '127.0.0.1'])).toThrow('PRIVATE_LAN_REQUIRED');
    expect(parseOptions(['--iphone', '--ip=192.168.1.20']).ip).toBe('192.168.1.20');
  });
  it('selects only public listener values from private configuration', () => {
    expect(config).toEqual({
      host: 'broker.test',
      ip: '192.168.1.20',
      bind: '0.0.0.0',
      tlsPort: 8443,
      ownerPort: 3211,
      agentPort: 3210,
    });
    expect(JSON.stringify(config)).not.toContain('synthetic-private-marker');
    expect(() => publicListenerConfig(environment.replace('8443', '443'))).toThrow();
  });
  it('selects one paired iPhone, refuses ambiguity and excludes iPads', () => {
    const first = phone();
    const second = phone('22345678-1234-1234-1234-123456789012', false);
    expect(selectPhone({ result: { devices: [first, second] } }).identifier).toBe(first.identifier);
    expect(() => selectPhone({ result: { devices: [first, phone(second.identifier)] } })).toThrow(
      'CHOOSE_IPHONE',
    );
    expect(
      selectPhone({ result: { devices: [first, phone(second.identifier)] } }, second.identifier)
        .identifier,
    ).toBe(second.identifier);
    expect(() =>
      selectPhone({
        result: {
          devices: [
            { ...first, hardwareProperties: { ...first.hardwareProperties, deviceType: 'iPad' } },
          ],
        },
      }),
    ).toThrow('CONNECT_IPHONE');
  });
  it('does not bypass an unavailable development prerequisite', () => {
    const candidate = phone();
    candidate.deviceProperties.developerModeStatus = 'disabled';
    expect(() => selectPhone({ result: { devices: [candidate] } })).toThrow(
      'ENABLE_DEVELOPER_MODE',
    );
  });
  it('prepares only versioned unverified draft fields, never bearer authority', () => {
    const now = Date.now();
    const pairing = {
      pairing_code: 'a'.repeat(43),
      expires_at: new Date(now + 300_000).toISOString(),
      owner_token: 'synthetic-not-authority',
    };
    const draft = prepareDraft(config, pin, pairing, now);
    expect(draft).toEqual({
      version: 1,
      broker_url: 'https://broker.test:8443',
      certificate_sha256: pin,
      pairing_code: pairing.pairing_code,
      expires_at: pairing.expires_at,
    });
    expect(JSON.stringify(draft)).not.toContain('owner_token');
    expect(JSON.stringify(draft)).not.toContain('verified');
    expect(prepareDraft(config, pin, undefined, now)).not.toHaveProperty('pairing_code');
  });
  it('rejects expired, excessive-lifetime and malformed pairing responses', () => {
    const now = Date.now();
    for (const expires_at of [
      new Date(now).toISOString(),
      new Date(now + 600_001).toISOString(),
      'invalid',
    ])
      expect(() =>
        prepareDraft(config, pin, { pairing_code: 'a'.repeat(43), expires_at }, now),
      ).toThrow('PAIRING_RESPONSE_INVALID');
    expect(() =>
      prepareDraft(
        config,
        pin,
        { pairing_code: 'bad', expires_at: new Date(now + 1000).toISOString() },
        now,
      ),
    ).toThrow();
    expect(() => prepareDraft(config, 'BAD', undefined, now)).toThrow('INVALID_TLS_PIN');
  });
  it('reuses a draft only while its exact canonical pairing record is unconsumed', () => {
    const now = Date.now();
    const code = 'a'.repeat(43);
    const expiry = new Date(now + 300_000).toISOString();
    const saved = {
      deviceIdentifier: phone().identifier,
      draft: prepareDraft(config, pin, { pairing_code: code, expires_at: expiry }, now),
    };
    const record = { codeHash: createHash('sha256').update(code).digest('hex'), expiresAt: expiry };
    const selected = phone().identifier;
    expect(canReusePairingDraft(saved, config, pin, { pairings: [record] }, selected, now)).toBe(
      true,
    );
    // A consumed-then-revoked device can look unpaired locally; never reuse its code.
    expect(
      canReusePairingDraft(
        saved,
        config,
        pin,
        { pairings: [{ ...record, consumedAt: new Date(now).toISOString() }] },
        selected,
        now,
      ),
    ).toBe(false);
    expect(canReusePairingDraft(saved, config, pin, { pairings: [] }, selected, now)).toBe(false);
    expect(
      canReusePairingDraft(saved, config, pin, { pairings: [record] }, 'another-iphone', now),
    ).toBe(false);
    expect(
      canReusePairingDraft(saved, config, pin, { pairings: [record] }, selected, now + 300_000),
    ).toBe(false);
  });
  it('recognizes only the selected phone exact enrolled device and public key', () => {
    const now = Date.now();
    const receipt = {
      version: 1,
      status: 'PAIRED',
      written_at: new Date(now).toISOString(),
      broker_url: 'https://broker.test:8443',
      certificate_sha256: pin,
      device_id: 'dev_selected',
      approval_key_sha256: 'b'.repeat(64),
    };
    const selected = { id: 'dev_selected', key_fingerprint: 'b'.repeat(64), status: 'ACTIVE' };
    const unrelated = {
      id: 'dev_other',
      key_fingerprint: 'c'.repeat(64),
      status: 'PENDING_CONFIRMATION',
    };
    expect(phoneEnrollmentStage(receipt, config, pin, [unrelated, selected], now, now)).toBe(
      'ACTIVE',
    );
    expect(
      phoneEnrollmentStage(
        receipt,
        config,
        pin,
        [unrelated, { ...selected, status: 'PENDING_CONFIRMATION' }],
        now,
        now,
      ),
    ).toBe('PENDING_CONFIRMATION');
    for (const devices of [
      [unrelated],
      [{ ...selected, key_fingerprint: 'c'.repeat(64) }],
      [{ ...selected, status: 'REVOKED' }],
    ])
      expect(() => phoneEnrollmentStage(receipt, config, pin, devices, now, now)).toThrow(
        'EXISTING_ENROLLMENT_REQUIRES_REVIEW',
      );
    expect(() =>
      phoneEnrollmentStage(
        { ...receipt, certificate_sha256: 'c'.repeat(64) },
        config,
        pin,
        [selected],
        now,
        now,
      ),
    ).toThrow('EXISTING_ENROLLMENT_REQUIRES_REVIEW');
  });
  it('does not confuse unrelated active phones or unreadable enrollment with an unpaired phone', () => {
    const now = Date.now();
    const receipt = { version: 1, status: 'UNPAIRED', written_at: new Date(now).toISOString() };
    const devices = [{ id: 'other', key_fingerprint: 'b'.repeat(64), status: 'ACTIVE' }];
    expect(phoneEnrollmentStage(receipt, config, pin, devices, now, now)).toBe('UNPAIRED');
    expect(() =>
      phoneEnrollmentStage({ ...receipt, status: 'UNAVAILABLE' }, config, pin, devices, now, now),
    ).toThrow('CHECK_IPHONE_ENROLLMENT');
    for (const invalid of [
      { ...receipt, written_at: new Date(now - 3000).toISOString() },
      { ...receipt, written_at: new Date(now + 3000).toISOString() },
      { ...receipt, token: 'synthetic-private-marker' },
      { ...receipt, version: true },
      { ...receipt, written_at: 'invalid' },
    ])
      expect(() => phoneEnrollmentStage(invalid, config, pin, devices, now, now)).toThrow(
        'IPHONE_RECEIPT_INVALID',
      );
  });
  it('refuses publicly readable private files and symlinks without changing their targets', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'boring-onboarding-'));
    try {
      const file = join(directory, 'private');
      await writeFile(file, 'synthetic-private-marker', { mode: 0o600 });
      expect(await privateText(file)).toBe('synthetic-private-marker');
      await chmod(file, 0o644);
      await expect(privateText(file)).rejects.toThrow('PRIVATE_STATE_REQUIRED');
      await chmod(file, 0o600);
      const link = join(directory, 'link');
      await symlink(file, link);
      await expect(privateText(link)).rejects.toThrow('PRIVATE_STATE_REQUIRED');
      expect(await readFile(file, 'utf8')).toBe('synthetic-private-marker');
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
