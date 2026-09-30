import { randomBytes } from 'node:crypto';
import { access, chmod, copyFile, mkdir, stat, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { resolve } from 'node:path';

async function exists(path) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

function run(command, args) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { stdio: 'inherit' });
    child.once('error', reject);
    child.once('exit', (code) =>
      code === 0 ? resolvePromise() : reject(new Error('BOOTSTRAP_FAILED')),
    );
  });
}

try {
  const directory = resolve('.local');
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  if (!(await exists(resolve(directory, 'broker.json')))) await run('npm', ['run', 'bootstrap']);
  if (((await stat(resolve(directory, 'broker.json'))).mode & 0o077) !== 0)
    throw new Error('PRIVATE_CONFIG_REQUIRED');
  const stateDirectory = resolve(directory, 'state');
  await mkdir(stateDirectory, { recursive: true, mode: 0o700 });
  await chmod(stateDirectory, 0o700);
  const dockerSettings = resolve(stateDirectory, 'broker.json');
  if (!(await exists(dockerSettings))) {
    await copyFile(resolve(directory, 'broker.json'), dockerSettings);
    await chmod(dockerSettings, 0o600);
  }
  if (((await stat(dockerSettings)).mode & 0o077) !== 0) throw new Error('PRIVATE_CONFIG_REQUIRED');
  const file = resolve(directory, 'docker.env');
  if (await exists(file)) {
    if (((await stat(file)).mode & 0o077) !== 0) throw new Error('PRIVATE_ENV_REQUIRED');
    process.stdout.write(
      'Private Docker configuration already exists; credentials were preserved.\n',
    );
  } else {
    const host = process.env.BROKER_TLS_HOST ?? 'localhost';
    const ip = process.env.BROKER_TLS_IP ?? '127.0.0.1';
    const bind = process.env.BROKER_TLS_BIND ?? '127.0.0.1';
    const tlsPort = Number(process.env.BROKER_TLS_PORT ?? 8443);
    const agentPort = Number(process.env.BROKER_AGENT_PORT ?? 3210);
    const ownerPort = Number(process.env.BROKER_OWNER_PORT ?? 3211);
    if (
      !/^[a-zA-Z0-9.-]+$/.test(host) ||
      !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip) ||
      !['127.0.0.1', '0.0.0.0'].includes(bind) ||
      [tlsPort, agentPort, ownerPort].some(
        (port) => !Number.isInteger(port) || port < 1024 || port > 65535,
      )
    )
      throw new Error('BINDING_INVALID');
    const uid = process.getuid?.() ?? 1000;
    const gid = process.getgid?.() ?? 1000;
    if (uid === 0) throw new Error('NON_ROOT_REQUIRED');
    const lines = [
      '# Private synthetic development settings. Never print this file or compose config.',
      `POSTGRES_PASSWORD=${randomBytes(32).toString('hex')}`,
      `BROKER_UID=${uid}`,
      `BROKER_GID=${gid}`,
      `BROKER_TLS_HOST=${host}`,
      `BROKER_TLS_BIND=${bind}`,
      `BROKER_TLS_IP=${ip}`,
      `BROKER_TLS_PORT=${tlsPort}`,
      `BROKER_AGENT_PORT=${agentPort}`,
      `BROKER_OWNER_PORT=${ownerPort}`,
      `BROKER_ALLOWED_HOSTNAMES=${[...new Set(['127.0.0.1', 'localhost', host, ip])].join(',')}`,
    ];
    await writeFile(file, `${lines.join('\n')}\n`, { mode: 0o600, flag: 'wx' });
    process.stdout.write(
      'Created private .local/docker.env with generated PostgreSQL authentication. No credentials were printed.\n',
    );
  }
  await run('node', ['scripts/docker-tls-bootstrap.mjs']);
} catch {
  process.stderr.write(
    'Docker bootstrap failed. Check private file permissions and explicit listener configuration.\n',
  );
  process.exitCode = 1;
}
