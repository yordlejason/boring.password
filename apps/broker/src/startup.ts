import type { TransactionStore } from '../../../packages/core/index.js';
import { startSyntheticSite, type SyntheticSite } from '../../../adapters/synthetic-login/site.js';
import { type SettingsFile } from './config.js';
import { createRuntime } from './runtime.js';
import { createHttpServices, listen, closeServer } from './http.js';

/** Partial startup owns and closes every acquired resource, even before any
 * public listener is ready. A failed startup must never leave an agent API alive. */
export async function startBroker(
  file: SettingsFile,
  store: TransactionStore,
  options: {
    agentPort: number;
    adminPort: number;
    allowedHostnames: string[];
  },
) {
  let site: SyntheticSite | undefined;
  let runtime: Awaited<ReturnType<typeof createRuntime>> | undefined;
  let servers: ReturnType<typeof createHttpServices> | undefined;
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    if (servers) await Promise.allSettled([closeServer(servers.agent), closeServer(servers.admin)]);
    await Promise.allSettled([runtime ? runtime.close() : Promise.resolve(store.close?.())]);
    await site?.close();
  };
  try {
    const context = file.settings.trusted.contexts[0];
    if (!context) throw new Error('CONTEXT_REQUIRED');
    const origin = new URL(context.destination);
    if (origin.protocol !== 'http:' || origin.hostname !== '127.0.0.1' || !origin.port)
      throw new Error('SYNTHETIC_ORIGIN_REQUIRED');
    if (
      options.allowedHostnames.some(
        (host) => !host || host.includes('*') || host.includes('/') || host.includes(':'),
      )
    )
      throw new Error('HOST_ALLOWLIST_REQUIRED');
    if (
      [options.agentPort, options.adminPort].some(
        (port) => !Number.isInteger(port) || port < 0 || port > 65535,
      )
    )
      throw new Error('LISTENER_PORT_INVALID');
    site = await startSyntheticSite({ port: Number(origin.port) });
    runtime = await createRuntime(file, store, site.origin);
    servers = createHttpServices(runtime.api, runtime.control, file, options.allowedHostnames);
    const agentPort = await listen(servers.agent, options.agentPort);
    const adminPort = await listen(servers.admin, options.adminPort);
    return { agentPort, adminPort, stop };
  } catch (error) {
    await stop();
    throw error;
  }
}
