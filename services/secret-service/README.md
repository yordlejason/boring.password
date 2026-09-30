# Trusted secret service

The development bootstrap uses only fixed synthetic credentials. `SyntheticSecretService` consumes a one-use broker permit, checks all immutable binding metadata and the exact enrolled credential version, and delivers a password or newly generated TOTP through a private trusted-worker callback. Its permit operations return `void`. The TOTP seed is never sent to the worker. No generic password, OTP, seed, credential-list or vault-dump API exists.

TOTP follows RFC 6238 with enrollment-specific algorithm, digits and period. Clock-health failure blocks release. A code is generated immediately before delivery; short remaining lifetime causes a bounded wait for the next step. Receiver/network/provider exceptions are replaced with fixed typed errors. An exception after private delivery starts is conservatively `OUTCOME_UNKNOWN`.

`vault-kv-v2.ts` supplies an established Vault KV v2 adapter source. It reads an administrator-pinned path and exact enrolled Vault version over HTTPS with redirects disabled, validates version/deletion metadata, limits body size and time, and delivers only through the scoped secret-provider input helper. The controller receives neither Vault records nor `SecretHandle` objects. See the [official exact-version API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version).

Production Vault use is deliberately disabled. The opaque release-capability registry has no production issuer or bootstrap path. The synthetic test capability works only with `https://synthetic-vault.invalid`, explicitly synthetic enrollment and an injected fake fetch. A boolean, copied object or MCP argument cannot activate it. Fake-fetch tests are not a live Vault integration or deployment-isolation acceptance.

JavaScript strings cannot be reliably erased. This local synthetic development topology does not provide production credential isolation. A real provider must run on a separately trusted service host after real-device, deployment, recovery, containment, logging and adapter-review release gates pass. No real credentials were retrieved or enrolled by these modules/tests.
