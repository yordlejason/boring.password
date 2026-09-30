import { spawn } from 'node:child_process';
import { X509Certificate, createHash, randomUUID } from 'node:crypto';
import { access, chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
process.umask(0o077);

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}
function openssl(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('openssl', args, { stdio: 'ignore' });
    child.once('error', () => reject(new Error('TLS_TOOL_UNAVAILABLE')));
    child.once('exit', (code) =>
      code === 0 ? resolve() : reject(new Error('TLS_GENERATION_FAILED')),
    );
  });
}

try {
  const environment = await readFile('.local/docker.env', 'utf8');
  const host = /^BROKER_TLS_HOST=([a-zA-Z0-9.-]+)$/m.exec(environment)?.[1];
  const ip = /^BROKER_TLS_IP=([0-9.]+)$/m.exec(environment)?.[1];
  if (!host || !ip || !isIP(ip)) throw new Error('TLS_BINDING_INVALID');
  await mkdir('.local/tls', { recursive: true, mode: 0o700 });
  await chmod('.local/tls', 0o700);
  const artifacts = [
    '.local/tls/ca.key',
    '.local/tls/root.crt',
    '.local/tls/server.key',
    '.local/tls/leaf.crt',
  ];
  const present = await Promise.all(artifacts.map(exists));
  if (present.some(Boolean) && !present.every(Boolean)) throw new Error('TLS_PARTIAL_STATE');
  if (!present.every(Boolean)) {
    // Standard OpenSSL development PKI. Keys are never output, used for login,
    // or mounted to the broker. This script never installs host trust.
    await openssl([
      'req',
      '-x509',
      '-newkey',
      'rsa:3072',
      '-nodes',
      '-sha256',
      '-days',
      '30',
      '-keyout',
      '.local/tls/ca.key',
      '-out',
      '.local/tls/root.crt',
      '-subj',
      '/CN=boring.login Development CA',
      '-addext',
      'basicConstraints=critical,CA:TRUE',
      '-addext',
      'keyUsage=critical,keyCertSign,cRLSign',
    ]);
    await chmod('.local/tls/ca.key', 0o600);
    await openssl([
      'req',
      '-new',
      '-newkey',
      'rsa:3072',
      '-nodes',
      '-sha256',
      '-keyout',
      '.local/tls/server.key',
      '-out',
      '.local/tls/server.csr',
      '-subj',
      `/CN=${host}`,
    ]);
    await chmod('.local/tls/server.key', 0o600);
    const names = [
      ...new Set([
        `${isIP(host) ? 'IP' : 'DNS'}:${host}`,
        `IP:${ip}`,
        'DNS:localhost',
        'IP:127.0.0.1',
      ]),
    ];
    await writeFile(
      '.local/tls/server-extensions.cnf',
      `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=${names.join(',')}\n`,
      { mode: 0o600 },
    );
    await openssl([
      'x509',
      '-req',
      '-in',
      '.local/tls/server.csr',
      '-CA',
      '.local/tls/root.crt',
      '-CAkey',
      '.local/tls/ca.key',
      '-CAcreateserial',
      '-out',
      '.local/tls/leaf.crt',
      '-days',
      '7',
      '-sha256',
      '-extfile',
      '.local/tls/server-extensions.cnf',
    ]);
  }
  const ca = new X509Certificate(await readFile('.local/tls/root.crt'));
  const leaf = new X509Certificate(await readFile('.local/tls/leaf.crt'));
  await chmod('.local/tls/root.crt', 0o644);
  await chmod('.local/tls/leaf.crt', 0o644);
  await chmod('.local/tls/ca.key', 0o600);
  await chmod('.local/tls/server.key', 0o600);
  if (
    !(isIP(host) ? leaf.checkIP(host) : leaf.checkHost(host)) ||
    !leaf.checkIP(ip) ||
    !leaf.verify(ca.publicKey) ||
    new Date(leaf.validTo).getTime() <= Date.now()
  )
    throw new Error('TLS_REVIEW_REQUIRED');
  const fingerprint = createHash('sha256').update(leaf.raw).digest('hex');
  const rootFingerprint = createHash('sha256').update(ca.raw).digest('hex');
  await writeFile('.local/tls/leaf-cert-sha256', `${fingerprint}\n`, { mode: 0o644 });
  await mkdir('.local/tls/public', { recursive: true, mode: 0o755 });
  await writeFile('.local/tls/public/broker-root-ca.crt', ca.toString(), { mode: 0o644 });
  await chmod('.local/tls/public', 0o755);
  await chmod('.local/tls/public/broker-root-ca.crt', 0o644);
  const certificateId = randomUUID(),
    profileId = randomUUID();
  const profile = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>
<key>PayloadType</key><string>Configuration</string><key>PayloadVersion</key><integer>1</integer>
<key>PayloadIdentifier</key><string>login.boring.synthetic-development-ca</string><key>PayloadUUID</key><string>${profileId}</string>
<key>PayloadDisplayName</key><string>boring.login Development CA</string><key>PayloadRemovalDisallowed</key><false/>
<key>PayloadDescription</key><string>Synthetic local broker only. Public CA SHA-256: ${rootFingerprint}. Expires ${ca.validTo}. Contains one public root certificate; no VPN, MDM or private key.</string>
<key>PayloadContent</key><array><dict><key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadVersion</key><integer>1</integer><key>PayloadIdentifier</key><string>login.boring.synthetic-development-ca.certificate</string>
<key>PayloadUUID</key><string>${certificateId}</string><key>PayloadDisplayName</key><string>boring.login Development CA</string>
<key>PayloadCertificateFileName</key><string>broker-root-ca.crt</string><key>PayloadContent</key><data>${ca.raw.toString('base64')}</data>
</dict></array></dict></plist>\n`;
  await writeFile('.local/tls/public/broker-development-ca.mobileconfig', profile, { mode: 0o644 });
  await writeFile('.local/tls/broker-development-ca.mobileconfig', profile, { mode: 0o644 });
  await chmod('.local/tls/public/broker-development-ca.mobileconfig', 0o644);
  process.stdout.write(
    `Prepared synthetic public CA/profile and multi-SAN leaf. No private keys were printed or trusted automatically.\nCA SHA-256: ${rootFingerprint}\nTLS certificate SHA-256: ${fingerprint}\n`,
  );
} catch {
  process.stderr.write(
    'Development TLS preparation failed. Check OpenSSL, private state and hostname bindings; existing trust/key files were preserved.\n',
  );
  process.exitCode = 1;
}
