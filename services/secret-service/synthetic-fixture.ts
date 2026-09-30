/** Deliberately public, test-only data. Never enroll a real account in this prototype. */
export const SYNTHETIC_CREDENTIAL = Object.freeze({
  accountId: 'acct_synthetic',
  version: 1,
  username: 'synthetic-user',
  password: 'SYNTHETIC-only-password-7d!NeverReal',
  // RFC 6238 test key, Base32 representation of ASCII 12345678901234567890.
  totpSeed: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  totp: Object.freeze({ algorithm: 'sha1' as const, digits: 6 as const, period: 30 }),
});
