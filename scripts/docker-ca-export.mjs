import { X509Certificate, createHash } from 'node:crypto';
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises';
import { connect } from 'node:tls';
import { isIP } from 'node:net';

try {
  // Parse only the pinned public listener fields; private database/password
  // entries remain in this process and never enter command args or outputs.
  const environment = await readFile('.local/docker.env', 'utf8');
  const host = /^BROKER_TLS_HOST=([a-zA-Z0-9.-]+)$/m.exec(environment)?.[1];
  const port = Number(/^BROKER_TLS_PORT=(\d+)$/m.exec(environment)?.[1]);
  if (!host || !port) throw new Error('TLS_BINDING_INVALID');
  const ca = await readFile('.local/tls/root.crt');
  const root = new X509Certificate(ca);
  const expectedLeaf = new X509Certificate(await readFile('.local/tls/leaf.crt'));
  await mkdir('.local/tls', { recursive: true, mode: 0o700 });
  await chmod('.local/tls', 0o700);
  await writeFile('.local/tls/root.crt', ca, { mode: 0o644 });
  const raw = await new Promise((resolve, reject) => {
    const socket = connect({
      host,
      port,
      ca,
      ...(isIP(host) ? {} : { servername: host }),
      rejectUnauthorized: true,
    });
    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error('TLS_UNAVAILABLE'));
    });
    socket.once('error', () => reject(new Error('TLS_UNAVAILABLE')));
    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate().raw;
      socket.end();
      certificate ? resolve(certificate) : reject(new Error('TLS_UNAVAILABLE'));
    });
  });
  const leaf = new X509Certificate(raw);
  if (!leaf.raw.equals(expectedLeaf.raw)) throw new Error('TLS_LEAF_MISMATCH');
  await writeFile('.local/tls/leaf.crt', leaf.toString(), { mode: 0o644 });
  const fingerprint = createHash('sha256').update(leaf.raw).digest('hex');
  await writeFile('.local/tls/leaf-cert-sha256', `${fingerprint}\n`, { mode: 0o644 });
  process.stdout.write(
    `Verified public CA and served leaf in .local/tls/.\nRoot CA SHA-256: ${root.fingerprint256}\nTLS certificate SHA-256: ${fingerprint}\n`,
  );
} catch {
  process.stderr.write(
    'Public certificate export failed. Check Caddy readiness, pinned hostname and TLS listener.\n',
  );
  process.exitCode = 1;
}
