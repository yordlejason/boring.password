import { TrustedOperationError } from '../../services/browser-worker/contracts.js';

export const SYNTHETIC_ADAPTER_ID = 'synthetic-login';
export const SYNTHETIC_ADAPTER_VERSION = '1.0.0';
export const SYNTHETIC_ACTION_PROFILE = 'synthetic_read_profile';

export interface SyntheticManifest {
  readonly id: typeof SYNTHETIC_ADAPTER_ID;
  readonly version: typeof SYNTHETIC_ADAPTER_VERSION;
  readonly origin: string;
  readonly accountId: 'acct_synthetic';
  readonly username: 'synthetic-user';
  readonly actionProfile: typeof SYNTHETIC_ACTION_PROFILE;
  readonly paths: Readonly<{
    password: '/login';
    passwordSubmit: '/password';
    totp: '/totp';
    totpSubmit: '/otp';
    authenticated: '/profile';
  }>;
}

/** Administrator wiring only; caller-supplied URLs/selectors are never accepted. */
export function createSyntheticManifest(origin: string): SyntheticManifest {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    throw new TrustedOperationError('DESTINATION_MISMATCH');
  }
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    url.origin !== origin ||
    url.username ||
    url.password ||
    !url.port
  )
    throw new TrustedOperationError('DESTINATION_MISMATCH');
  return Object.freeze({
    id: SYNTHETIC_ADAPTER_ID,
    version: SYNTHETIC_ADAPTER_VERSION,
    origin,
    accountId: 'acct_synthetic',
    username: 'synthetic-user',
    actionProfile: SYNTHETIC_ACTION_PROFILE,
    paths: Object.freeze({
      password: '/login',
      passwordSubmit: '/password',
      totp: '/totp',
      totpSubmit: '/otp',
      authenticated: '/profile',
    }),
  });
}
