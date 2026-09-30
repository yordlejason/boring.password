import { spawn, execFile } from 'node:child_process';
import { X509Certificate, createHash } from 'node:crypto';
import { lstat, mkdir, readFile, writeFile, chmod, rm } from 'node:fs/promises';
import { isIP } from 'node:net';
import { networkInterfaces } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

// Owner-side development setup. No owner capability is added to the agent MCP.
// Child output and transport credentials never enter this command's output.
export class OnboardingError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function localBrokerHost(label) {
  if (
    typeof label !== 'string' ||
    !/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label.trim())
  )
    throw new OnboardingError('CHOOSE_BROKER_HOST');
  return label.trim().toLowerCase() + '.local';
}

export function parseOptions(args) {
  const options = { iphone: false, pair: false, refresh: false, status: false };
  const flags = new Set(['iphone', 'pair', 'refresh', 'status']);
  const values = new Set(['device', 'host', 'ip', 'team']);
  for (let i = 0; i < args.length; i++) {
    const argument = args[i];
    if (!argument.startsWith('--')) throw new OnboardingError('INVALID_OPTIONS');
    const [key, inline, ...extra] = argument.slice(2).split('=');
    if (extra.length) throw new OnboardingError('INVALID_OPTIONS');
    if (flags.has(key)) {
      if (inline !== undefined || options[key]) throw new OnboardingError('INVALID_OPTIONS');
      options[key] = true;
    } else if (values.has(key)) {
      const value = inline ?? args[++i];
      if (!value || value.startsWith('--') || options[key] !== undefined)
        throw new OnboardingError('INVALID_OPTIONS');
      options[key] = value;
    } else throw new OnboardingError('INVALID_OPTIONS');
  }
  if (options.pair || options.device || options.team) options.iphone = true;
  if (options.status && (options.iphone || options.pair || options.refresh))
    throw new OnboardingError('INVALID_OPTIONS');
  if (options.host && !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$/.test(options.host))
    throw new OnboardingError('INVALID_HOST');
  if (options.ip && isIP(options.ip) !== 4) throw new OnboardingError('INVALID_IP');
  if (
    options.iphone &&
    options.ip &&
    !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(options.ip)
  )
    throw new OnboardingError('PRIVATE_LAN_REQUIRED');
  if (options.team && !/^[A-Z0-9]{10}$/.test(options.team))
    throw new OnboardingError('INVALID_TEAM');
  if (options.device && !/^[a-zA-Z0-9_. -]{1,200}$/.test(options.device))
    throw new OnboardingError('INVALID_DEVICE');
  return options;
}

export function publicListenerConfig(environment) {
  // Intentionally select six public fields, never return the environment object.
  const field = (key) => new RegExp('^' + key + '=([^\\r\\n]+)$', 'm').exec(environment)?.[1];
  const host = field('BROKER_TLS_HOST');
  const ip = field('BROKER_TLS_IP');
  const bind = field('BROKER_TLS_BIND');
  const tlsPort = Number(field('BROKER_TLS_PORT'));
  const ownerPort = Number(field('BROKER_OWNER_PORT'));
  const agentPort = Number(field('BROKER_AGENT_PORT'));
  if (
    !host ||
    !/^[a-zA-Z0-9.-]+$/.test(host) ||
    !ip ||
    isIP(ip) !== 4 ||
    !['127.0.0.1', '0.0.0.0'].includes(bind) ||
    [tlsPort, ownerPort, agentPort].some((p) => !Number.isInteger(p) || p < 1024 || p > 65535)
  )
    throw new OnboardingError('INVALID_LISTENERS');
  return { host, ip, bind, tlsPort, ownerPort, agentPort };
}

export function selectPhone(inventory, selector) {
  const devices = inventory?.result?.devices;
  if (!Array.isArray(devices)) throw new OnboardingError('DEVICE_INVENTORY_INVALID');
  let candidates = devices.filter(
    (d) =>
      d?.hardwareProperties?.platform === 'iOS' &&
      d?.hardwareProperties?.deviceType === 'iPhone' &&
      d?.connectionProperties?.pairingState === 'paired',
  );
  if (selector)
    candidates = candidates.filter((d) =>
      [d.identifier, d.hardwareProperties.udid, d.deviceProperties?.name].includes(selector),
    );
  else {
    const connected = candidates.filter((d) => d.connectionProperties.tunnelState === 'connected');
    if (connected.length) candidates = connected;
  }
  if (candidates.length !== 1)
    throw new OnboardingError(candidates.length ? 'CHOOSE_IPHONE' : 'CONNECT_IPHONE');
  const device = candidates[0];
  if (device.deviceProperties?.developerModeStatus !== 'enabled')
    throw new OnboardingError('ENABLE_DEVELOPER_MODE');
  if (
    !/^[a-fA-F0-9-]{8,80}$/.test(device.identifier) ||
    !/^[a-fA-F0-9-]{8,80}$/.test(device.hardwareProperties.udid)
  )
    throw new OnboardingError('DEVICE_INVENTORY_INVALID');
  return device; // Hardware selectors stay private inside this process.
}

export function prepareDraft(config, fingerprint, pairing, now = Date.now()) {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new OnboardingError('INVALID_TLS_PIN');
  const origin = new URL('https://' + config.host + ':' + config.tlsPort);
  if (origin.hostname !== config.host.toLowerCase()) throw new OnboardingError('INVALID_HOST');
  const expiry = pairing?.expires_at ?? new Date(now + 300_000).toISOString();
  const expiryMS = Date.parse(expiry);
  if (
    !Number.isFinite(expiryMS) ||
    expiryMS <= now ||
    expiryMS > now + 600_000 ||
    (pairing && !/^[A-Za-z0-9_-]{43}$/.test(pairing.pairing_code ?? ''))
  )
    throw new OnboardingError('PAIRING_RESPONSE_INVALID');
  return {
    version: 1,
    broker_url: origin.origin,
    certificate_sha256: fingerprint,
    ...(pairing ? { pairing_code: pairing.pairing_code } : {}),
    expires_at: expiry,
  };
}

export function canReusePairingDraft(
  saved,
  config,
  fingerprint,
  settings,
  deviceIdentifier,
  now = Date.now(),
) {
  const draft = saved?.draft;
  if (
    saved?.deviceIdentifier !== deviceIdentifier ||
    draft?.broker_url !== 'https://' + config.host + ':' + config.tlsPort ||
    draft?.certificate_sha256 !== fingerprint ||
    !/^[A-Za-z0-9_-]{43}$/.test(draft?.pairing_code ?? '') ||
    !Array.isArray(settings?.pairings)
  )
    return false;
  const digest = createHash('sha256').update(draft.pairing_code).digest('hex');
  return settings.pairings.some(
    (p) =>
      p.codeHash === digest &&
      p.consumedAt === undefined &&
      p.expiresAt === draft.expires_at &&
      Date.parse(p.expiresAt) > now &&
      Date.parse(p.expiresAt) <= now + 600_000,
  );
}

// A public local receipt helps navigate setup; it cannot confer authority.
// Only the matching owner-side device record determines ACTIVE/PENDING status.
export function phoneEnrollmentStage(
  receipt,
  config,
  fingerprint,
  devices,
  launchedAt,
  now = Date.now(),
) {
  const paired = receipt?.status === 'PAIRED';
  const keys = paired
    ? [
        'version',
        'status',
        'written_at',
        'broker_url',
        'certificate_sha256',
        'device_id',
        'approval_key_sha256',
      ]
    : ['version', 'status', 'written_at'];
  const writtenAt = Date.parse(receipt?.written_at);
  if (
    receipt?.version !== 1 ||
    !['UNPAIRED', 'UNAVAILABLE', 'PAIRED'].includes(receipt.status) ||
    Object.keys(receipt).length !== keys.length ||
    Object.keys(receipt).some((key) => !keys.includes(key)) ||
    typeof receipt.written_at !== 'string' ||
    !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$/.test(
      receipt.written_at,
    ) ||
    !Number.isFinite(writtenAt) ||
    writtenAt < launchedAt - 2000 ||
    writtenAt > now + 2000
  )
    throw new OnboardingError('IPHONE_RECEIPT_INVALID');
  if (receipt.status === 'UNAVAILABLE') throw new OnboardingError('CHECK_IPHONE_ENROLLMENT');
  if (!paired) return 'UNPAIRED';
  if (
    receipt.broker_url !== 'https://' + config.host + ':' + config.tlsPort ||
    receipt.certificate_sha256 !== fingerprint ||
    typeof receipt.device_id !== 'string' ||
    !/^[a-zA-Z0-9_-]{1,200}$/.test(receipt.device_id) ||
    !/^[a-f0-9]{64}$/.test(receipt.approval_key_sha256)
  )
    throw new OnboardingError('EXISTING_ENROLLMENT_REQUIRES_REVIEW');
  const device = devices.find((d) => d.id === receipt.device_id);
  if (
    !device ||
    device.key_fingerprint !== receipt.approval_key_sha256 ||
    device.status === 'REVOKED'
  )
    throw new OnboardingError('EXISTING_ENROLLMENT_REQUIRES_REVIEW');
  if (!['ACTIVE', 'PENDING_CONFIRMATION'].includes(device.status))
    throw new OnboardingError('OWNER_RESPONSE_INVALID');
  return device.status;
}

export async function privateText(file) {
  const info = await lstat(file);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    (info.mode & 0o077) !== 0 ||
    info.size > 131_072 ||
    (process.getuid && info.uid !== process.getuid())
  )
    throw new OnboardingError('PRIVATE_STATE_REQUIRED');
  return readFile(file, 'utf8');
}

async function exists(file) {
  try {
    await lstat(file);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw new OnboardingError('STATE_UNAVAILABLE');
  }
}
async function privateDirectory(directory) {
  if (!(await exists(directory))) await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || (info.mode & 0o077) !== 0)
    throw new OnboardingError('PRIVATE_STATE_REQUIRED');
}
async function savePrivate(file, value) {
  if (await exists(file)) {
    const info = await lstat(file);
    if (
      !info.isFile() ||
      info.isSymbolicLink() ||
      (info.mode & 0o077) !== 0 ||
      (process.getuid && info.uid !== process.getuid())
    )
      throw new OnboardingError('PRIVATE_STATE_REQUIRED');
  }
  await writeFile(file, value, { mode: 0o600 });
  await chmod(file, 0o600);
}
async function run(
  command,
  args,
  { env = process.env, log, timeout = 240_000, failure = 'SETUP_COMMAND_FAILED' } = {},
) {
  // Log only the Xcode build if requested. Never mirror a child's raw error.
  const chunks = [];
  const result = await new Promise((done) => {
    const child = spawn(command, args, { env, stdio: log ? ['ignore', 'pipe', 'pipe'] : 'ignore' });
    if (log) {
      child.stdout.on('data', (b) => {
        if (chunks.reduce((n, v) => n + v.length, 0) < 16_000_000) chunks.push(b);
      });
      child.stderr.on('data', (b) => {
        if (chunks.reduce((n, v) => n + v.length, 0) < 16_000_000) chunks.push(b);
      });
    }
    const timer = setTimeout(() => child.kill('SIGTERM'), timeout);
    child.once('error', () => {
      clearTimeout(timer);
      done(false);
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      done(code === 0);
    });
  });
  if (log) await savePrivate(log, Buffer.concat(chunks));
  if (!result) throw new OnboardingError(failure);
}

async function ensureEngine(mayStart) {
  try {
    await run('docker', ['info', '--format', '{{.ServerVersion}}'], { timeout: 15_000 });
  } catch {
    if (!mayStart) throw new OnboardingError('START_DOCKER');
    await run('docker', ['desktop', 'start'], { timeout: 120_000, failure: 'START_DOCKER' });
    await run('docker', ['info', '--format', '{{.ServerVersion}}'], {
      timeout: 30_000,
      failure: 'START_DOCKER',
    });
  }
}
function privateLANIP() {
  const addresses = Object.entries(networkInterfaces())
    .filter(([name]) => /^(en|eth|wlan)\d+$/.test(name))
    .flatMap(([, values]) => values ?? [])
    .filter(
      (a) =>
        !a.internal &&
        a.family === 'IPv4' &&
        /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address),
    )
    .map((a) => a.address);
  const unique = [...new Set(addresses)];
  if (unique.length !== 1) throw new OnboardingError('CHOOSE_LAN_IP');
  return unique[0];
}
async function ownerAPI(config, path, method = 'GET') {
  const token = (await privateText('.local/owner-token')).trim();
  if (!/^[A-Za-z0-9_-]{32,200}$/.test(token)) throw new OnboardingError('PRIVATE_STATE_REQUIRED');
  const response = await fetch('http://127.0.0.1:' + config.ownerPort + path, {
    method,
    redirect: 'error',
    signal: AbortSignal.timeout(10_000),
    headers: {
      Authorization: 'Bearer ' + token,
      ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
    },
    ...(method === 'POST' ? { body: '{}' } : {}),
  });
  if (!response.ok) throw new OnboardingError('OWNER_CONNECTION_FAILED');
  const data = await response.json();
  return data; // No raw body or provider exception reaches stdout/stderr.
}
function safeOverview(data) {
  if (
    data?.synthetic_only !== true ||
    data.production_credentials_enabled !== false ||
    !Array.isArray(data.devices) ||
    !Array.isArray(data.requests)
  )
    throw new OnboardingError('OWNER_RESPONSE_INVALID');
  const statuses = data.devices.map((d) => d.status);
  if (statuses.some((s) => !['ACTIVE', 'PENDING_CONFIRMATION', 'REVOKED'].includes(s)))
    throw new OnboardingError('OWNER_RESPONSE_INVALID');
  return {
    activeDevices: statuses.filter((s) => s === 'ACTIVE').length,
    pendingDevices: statuses.filter((s) => s === 'PENDING_CONFIRMATION').length,
    devices: data.devices.map((d) => ({
      id: d.id,
      status: d.status,
      key_fingerprint: d.key_fingerprint,
    })),
  };
}

async function prepareIPhone(options, config, fingerprint) {
  if (process.platform !== 'darwin') throw new OnboardingError('MAC_REQUIRED_FOR_IPHONE');
  if (await exists('.local/onboarding/devices.json'))
    await privateText('.local/onboarding/devices.json');
  await run(
    'xcrun',
    [
      'devicectl',
      'list',
      'devices',
      '--quiet',
      '--timeout',
      '15',
      '--json-output',
      '.local/onboarding/devices.json',
    ],
    { failure: 'CONNECT_IPHONE' },
  );
  await chmod('.local/onboarding/devices.json', 0o600);
  const phone = selectPhone(
    JSON.parse(await privateText('.local/onboarding/devices.json')),
    options.device,
  );
  const project = await readFile('apps/ios-approval/project.yml', 'utf8');
  const team = options.team ?? /DEVELOPMENT_TEAM:\s*"([A-Z0-9]{10})"/.exec(project)?.[1];
  if (!team) throw new OnboardingError('CHOOSE_SIGNING_TEAM');
  process.stdout.write('Preparing the signed iPhone app; existing pairing is preserved.\n');
  await run(
    'xcodebuild',
    [
      '-project',
      'apps/ios-approval/BrokerApproval.xcodeproj',
      '-scheme',
      'BrokerApproval',
      '-configuration',
      'Debug',
      '-sdk',
      'iphoneos',
      '-destination',
      'id=' + phone.hardwareProperties.udid,
      '-derivedDataPath',
      'apps/ios-approval/build/device',
      '-allowProvisioningUpdates',
      'DEVELOPMENT_TEAM=' + team,
      'build',
    ],
    { log: '.local/onboarding/iphone-build.log', timeout: 600_000, failure: 'IPHONE_BUILD_FAILED' },
  );
  await run(
    'xcrun',
    [
      'devicectl',
      'device',
      'install',
      'app',
      '--device',
      phone.identifier,
      'apps/ios-approval/build/device/Build/Products/Debug-iphoneos/BrokerApproval.app',
      '--quiet',
    ],
    { failure: 'IPHONE_INSTALL_FAILED' },
  );

  // Read a fresh receipt from this exact app container before deciding whether
  // to prefill. Unrelated ACTIVE or pending phones do not prove this phone's state.
  const launchedAt = Date.now();
  await launchPhone(phone);
  const receiptFile = '.local/onboarding/device-receipt.json';
  let receipt;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (await exists(receiptFile)) {
      await privateText(receiptFile);
      await rm(receiptFile);
    }
    try {
      await run(
        'xcrun',
        [
          'devicectl',
          'device',
          'copy',
          'from',
          '--device',
          phone.identifier,
          '--source',
          'Documents/boring-login-enrollment.json',
          '--destination',
          receiptFile,
          '--domain-type',
          'appDataContainer',
          '--domain-identifier',
          'login.boring.approval',
          '--quiet',
        ],
        { failure: 'CHECK_IPHONE_ENROLLMENT', timeout: 30_000 },
      );
      await chmod(receiptFile, 0o600);
      receipt = JSON.parse(await privateText(receiptFile));
      if (Date.parse(receipt.written_at) < launchedAt - 2000)
        throw new OnboardingError('IPHONE_RECEIPT_INVALID');
      break;
    } catch {
      if (attempt === 2) throw new OnboardingError('CHECK_IPHONE_ENROLLMENT');
      await new Promise((done) => setTimeout(done, 1000));
    }
  }
  const latest = safeOverview(await ownerAPI(config, '/admin/overview'));
  const stage = phoneEnrollmentStage(receipt, config, fingerprint, latest.devices, launchedAt);
  const cacheFile = '.local/onboarding/pairing-draft.json';
  const saved = (await exists(cacheFile)) ? JSON.parse(await privateText(cacheFile)) : undefined;
  if (stage !== 'UNPAIRED') {
    if (saved?.deviceIdentifier === phone.identifier) await rm(cacheFile);
    return {
      app: 'installed',
      pairing: stage === 'ACTIVE' ? 'existing_device_preserved' : 'awaiting_owner_confirmation',
    };
  }
  // Create a five-minute code only after the build/install, not before it.
  let draft;
  if (saved) {
    const settings = JSON.parse(await privateText('.local/state/broker.json'));
    const code = saved.draft?.pairing_code;
    const record =
      typeof code === 'string' && Array.isArray(settings.pairings)
        ? settings.pairings.find(
            (p) => p.codeHash === createHash('sha256').update(code).digest('hex'),
          )
        : undefined;
    if (saved.deviceIdentifier === phone.identifier && record?.consumedAt !== undefined)
      throw new OnboardingError('ENROLLMENT_RECONCILIATION_REQUIRED');
    if (
      saved.deviceIdentifier !== phone.identifier &&
      record &&
      record.consumedAt === undefined &&
      Date.parse(record.expiresAt) > Date.now()
    )
      throw new OnboardingError('PAIRING_FOR_ANOTHER_IPHONE_PENDING');
    if (canReusePairingDraft(saved, config, fingerprint, settings, phone.identifier))
      draft = prepareDraft(config, fingerprint, saved.draft);
  }
  if (!draft) {
    const pairing = await ownerAPI(config, '/admin/pairings', 'POST');
    draft = prepareDraft(config, fingerprint, pairing);
    await savePrivate(cacheFile, JSON.stringify({ deviceIdentifier: phone.identifier, draft }));
  }
  await savePrivate('.local/onboarding/device-setup.json', JSON.stringify(draft));
  await run(
    'xcrun',
    [
      'devicectl',
      'device',
      'copy',
      'to',
      '--device',
      phone.identifier,
      '--source',
      '.local/onboarding/device-setup.json',
      '--destination',
      'Documents/boring-login-onboarding.json',
      '--domain-type',
      'appDataContainer',
      '--domain-identifier',
      'login.boring.approval',
      '--quiet',
    ],
    { failure: 'IPHONE_PREFILL_FAILED' },
  );
  await rm('.local/onboarding/device-setup.json');
  await launchPhone(phone);
  return {
    app: 'installed',
    pairing: 'prepared_unverified_draft',
  };
}

async function launchPhone(phone) {
  await run(
    'xcrun',
    [
      'devicectl',
      'device',
      'process',
      'launch',
      '--device',
      phone.identifier,
      '--terminate-existing',
      'login.boring.approval',
      '--quiet',
    ],
    { failure: 'IPHONE_LAUNCH_FAILED' },
  );
}

export async function main(args = process.argv.slice(2)) {
  process.umask(0o077);
  const options = parseOptions(args);
  if (options.iphone && process.platform !== 'darwin')
    throw new OnboardingError('MAC_REQUIRED_FOR_IPHONE');
  await privateDirectory('.local');
  await privateDirectory('.local/onboarding');
  if (!(await exists('node_modules')) && !options.status) {
    process.stdout.write('Installing locked project dependencies.\n');
    await run('npm', ['ci', '--no-audit', '--no-fund'], {
      timeout: 300_000,
      failure: 'DEPENDENCIES_REQUIRED',
    });
  }
  await ensureEngine(!options.status);
  const hasState = await exists('.local/state/broker.json');
  if (
    hasState &&
    (!(await exists('.local/broker.json')) ||
      !(await exists('.local/docker.env')) ||
      !(await exists('.local/owner-token')) ||
      !(await exists('.local/client-token')))
  )
    throw new OnboardingError('EXISTING_STATE_REQUIRES_REVIEW');
  if (!(await exists('.local/docker.env'))) {
    if (options.status) throw new OnboardingError('SETUP_REQUIRED');
    const initialEnv = { ...process.env };
    if (options.iphone) {
      const ip = options.ip ?? privateLANIP();
      // An explicit --iphone run is local phone-access setup. MCP/admin stay loopback.
      if (options.host) initialEnv.BROKER_TLS_HOST = options.host;
      else {
        try {
          const { stdout } = await promisify(execFile)(
            '/usr/sbin/scutil',
            ['--get', 'LocalHostName'],
            { timeout: 5000, maxBuffer: 256 },
          );
          initialEnv.BROKER_TLS_HOST = localBrokerHost(stdout);
        } catch {
          throw new OnboardingError('CHOOSE_BROKER_HOST');
        }
      }
      initialEnv.BROKER_TLS_IP = ip;
      initialEnv.BROKER_TLS_BIND = '0.0.0.0';
    } else {
      if (options.host) initialEnv.BROKER_TLS_HOST = options.host;
      if (options.ip) initialEnv.BROKER_TLS_IP = options.ip;
    }
    await run('node', ['scripts/docker-bootstrap.mjs'], {
      env: initialEnv,
      failure: 'BOOTSTRAP_REVIEW_REQUIRED',
    });
  }
  const config = publicListenerConfig(await privateText('.local/docker.env'));
  if ((options.host && options.host !== config.host) || (options.ip && options.ip !== config.ip))
    throw new OnboardingError('EXISTING_LISTENERS_PRESERVED');
  if (
    options.iphone &&
    (config.bind !== '0.0.0.0' || config.ip === '127.0.0.1' || config.host === 'localhost')
  )
    throw new OnboardingError('PHONE_LISTENER_REQUIRES_REVIEW');
  await privateDirectory('.local/state');
  await privateText('.local/state/broker.json');
  await privateText('.local/client-token');
  let ready = false;
  try {
    await run('node', ['scripts/docker-start.mjs', '--verify-only'], { failure: 'VERIFY_FAILED' });
    ready = true;
  } catch {
    if (options.status) throw new OnboardingError('VERIFY_FAILED');
  }
  if (!ready || options.refresh) {
    process.stdout.write('Starting the Docker broker and verifying HTTPS.\n');
    if (ready && options.refresh) {
      await run(
        'docker',
        [
          'compose',
          '--env-file',
          '.local/docker.env',
          '-f',
          'compose.yaml',
          'up',
          '--build',
          '--force-recreate',
          '--no-deps',
          '-d',
          '--wait',
          '--wait-timeout',
          '180',
          'broker',
          'tls',
        ],
        { timeout: 600_000, failure: 'DOCKER_START_FAILED' },
      );
      await run('node', ['scripts/docker-start.mjs', '--verify-only'], {
        failure: 'VERIFY_FAILED',
      });
    } else
      await run('node', ['scripts/docker-start.mjs'], {
        timeout: 600_000,
        failure: 'DOCKER_START_FAILED',
      });
  }
  const leaf = new X509Certificate(await readFile('.local/tls/leaf.crt'));
  const root = new X509Certificate(await readFile('.local/tls/root.crt'));
  const fingerprint = createHash('sha256').update(leaf.raw).digest('hex');
  const overview = safeOverview(await ownerAPI(config, '/admin/overview'));
  const iphone = options.iphone ? await prepareIPhone(options, config, fingerprint) : undefined;
  const summary = {
    synthetic_only: true,
    production_credentials_enabled: false,
    owner_console: 'http://127.0.0.1:' + config.ownerPort + '/',
    mcp_endpoint: 'http://127.0.0.1:' + config.agentPort + '/mcp',
    broker_url: 'https://' + config.host + ':' + config.tlsPort,
    root_certificate_sha256: createHash('sha256').update(root.raw).digest('hex'),
    certificate_sha256: fingerprint,
    certificate_expires_at: new Date(leaf.validTo).toISOString(),
    public_ca_profile: 'http://' + config.ip + ':8080/broker-development-ca.mobileconfig',
    active_devices: overview.activeDevices,
    pending_devices: overview.pendingDevices,
    ...(iphone ? { iphone } : {}),
  };
  await savePrivate('.local/onboarding/summary.json', JSON.stringify(summary, null, 2) + '\n');
  process.stdout.write(JSON.stringify(summary, null, 2) + '\n');
  process.stdout.write(
    'Setup prepared. The agent completes the owner-console handoff; phone trust and physical key/biometric actions remain owner-controlled.\n',
  );
  return summary;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    const code = error instanceof OnboardingError ? error.code : 'ONBOARDING_FAILED';
    process.stderr.write(
      'Onboarding stopped: ' +
        code +
        '. Existing credentials, pairing and trust were preserved. See agent.md.\n',
    );
    process.exitCode = 1;
  });
}
