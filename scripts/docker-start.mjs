import { spawn } from 'node:child_process';
import { readFile, stat } from 'node:fs/promises';

async function run(command, args, output = 'inherit') {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: output });
    child.once('error', () => reject(new Error('DOCKER_UNAVAILABLE')));
    child.once('exit', (code) => (code === 0 ? resolve() : reject(new Error('DOCKER_FAILED'))));
  });
}

try {
  if (process.argv.slice(2).some((arg) => arg !== '--verify-only'))
    throw new Error('INVALID_ARGUMENT');
  if (((await stat('.local/docker.env')).mode & 0o077) !== 0)
    throw new Error('PRIVATE_ENV_REQUIRED');
  await run('docker', ['info', '--format', '{{.ServerVersion}}'], 'ignore');
  const args = ['compose', '--env-file', '.local/docker.env', '-f', 'compose.yaml'];
  // Validation must remain quiet: rendered Compose output contains credentials.
  await run('docker', [...args, 'config', '--quiet']);
  if (!process.argv.includes('--verify-only'))
    await run('docker', [...args, 'up', '--build', '-d', '--wait', '--wait-timeout', '180']);
  const environment = await readFile('.local/docker.env', 'utf8');
  const agentPort = Number(/^BROKER_AGENT_PORT=(\d+)$/m.exec(environment)?.[1]);
  const ownerPort = Number(/^BROKER_OWNER_PORT=(\d+)$/m.exec(environment)?.[1]);
  if (!agentPort || !ownerPort) throw new Error('LISTENER_BINDING_INVALID');
  const health = await fetch(`http://127.0.0.1:${agentPort}/health`, {
    signal: AbortSignal.timeout(5000),
  });
  if (!health.ok) throw new Error('PUBLIC_HEALTH_UNAVAILABLE');
  const status = await health.json();
  if (
    status.status !== 'ok' ||
    status.synthetic_only !== true ||
    status.production_credentials_enabled !== false
  )
    throw new Error('PUBLIC_HEALTH_INVALID');
  const owner = await fetch(`http://127.0.0.1:${ownerPort}/`, {
    signal: AbortSignal.timeout(5000),
  });
  if (!owner.ok) throw new Error('OWNER_UNAVAILABLE');
  await run('node', ['scripts/docker-ca-export.mjs']);
  process.stdout.write(
    'Synthetic Docker services are running. Production credential isolation remains disabled.\n',
  );
} catch {
  process.stderr.write(
    'Docker startup failed. Check engine availability, private configuration, occupied ports and sandbox support.\n',
  );
  process.exitCode = 1;
}
