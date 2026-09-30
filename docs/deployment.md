# Deployment boundaries

The executable currently accepts synthetic accounts/adapters only. There is no environment-variable switch that enables production credentials. The Vault provider has no production release-capability issuer; its test capability works only with a fake transport and synthetic origin. Production rollout requires implementation and reviewed release evidence, not changing a boolean.

## Development

The broker, synthetic secret service, and browser worker run in one trusted development process. This is useful for functional tests and explicitly does not supply production-grade credential isolation. This chat's agent has filesystem and process access to the workspace. Never place a production password, vault token, TOTP seed, browser profile, or owner recovery credential here.

Agent HTTP binds to 127.0.0.1:3210. Owner/device HTTP binds to 127.0.0.1:3211. The browser fixture binds to 127.0.0.1:3212. Only the first listener exposes MCP. Separate client, owner, and device bearer credentials are hashed in the owner configuration. These transport credentials are not destination-service tokens and must never be forwarded downstream.

Use an owner-protected filesystem location for `BROKER_CONFIG`, outside an agent-controlled execution environment. Configuration must be mode 0600. Bootstrap's `.local/` is an ignored development convenience. Do not mount it into the agent host. Serialized settings updates stage a draft, sync a private temporary file, atomically rename it, then publish it to the controller. Authority is suspended during updates and after any persistence failure; only a successful retry of that exact failed mutation clears its fault. An unrelated pairing/write cannot reactivate authority after a failed revocation. Failed updates are never acknowledged as successful. Repair failed revocation persistence before restarting: an uncommitted revocation cannot survive a process loss. Durable revocation/recovery operational testing remains a production gate. Transactional request/permit authority is stored in PostgreSQL.

The [Docker development guide](../docker/README.md) runs private PostgreSQL, the broker/browser, and a separate TLS proxy. Docker owner configuration is `.local/state/broker.json`; only that state directory enters the broker. The proxy receives the server certificate/key and a separate public-only certificate/profile directory, while the CA private key stays on the host. Cleartext MCP/owner proxy ports bind to host loopback. A phone test may explicitly bind HTTPS and the public-certificate download listener to the local network; no public internet tunnel is configured. Database ports and Docker sockets are not exposed.

The broker and proxy use non-root UIDs, read-only root filesystems, and no container capabilities. Chromium must start with its sandbox enabled. The namespace seccomp policy permits Chromium's user-namespace operations and `chroot`; it does not grant outer container capabilities. Caddy's vendor executable file capability is removed at build time because every proxy port exceeds 1024. These development controls do not remove this agent's host administrative access. Startup checks the actual proxy endpoints and TLS chain/leaf against the generated CA. A broker/proxy recreation is coordinated because they share a network namespace; see the Docker guide for restart and crash recovery.

## Native-device testing

Serve the owner/device listener through a private HTTPS reverse proxy. Configure a hostname whose certificate is trusted by the iPhone, add that exact hostname to `BROKER_ALLOWED_HOSTNAMES`, and preserve its Host header when proxying. Configure normal TLS trust plus the leaf certificate SHA-256 pin in the app. Do not disable certificate validation or use a URL pointing directly to the plaintext development listener.

The phone never opens the authentication destination. A signed `http://127.0.0.1:<port>` target refers to the broker's local synthetic website, and the app identifies it as a local synthetic target. Device-to-broker traffic still uses pinned HTTPS. Enrollment runs through an owner-created, five-minute one-use pairing code. Owner confirmation compares the app's SPKI DER SHA-256 key fingerprint with the pending-device fingerprint in the console.

The proxy is trusted infrastructure. Keep it outside agent administration, restrict ingress, and apply network/body/rate limits. Do not publish the owner listener to the public internet as an unaudited production administration service. The current console's bearer-based owner authentication is a development control; it does not establish the strong owner-authentication release profile for security-policy expansion or recovery.

## Production prerequisites

Use a trusted dedicated machine or VM with:

- private metadata database and tested backups/restores;
- isolated secret service connected to the approved vault, with exact-version credential bindings;
- isolated browser worker with authenticated private service channels and runtime fencing;
- TLS, monitored clock synchronization, owner authentication, rate controls, and hardened ingress;
- no agent access to the Docker socket, hypervisor, trusted runtime administration, vault, browser profiles, process memory, CDP, traces, or service credentials;
- reviewed adapters and restricted post-login action/observation profiles;
- completed physical-device, containment, logging, crash/recovery, and deployment tests.

Linux browser tests use Chromium's sandbox. Browser/CDP endpoints are never exposed by the application. This alone is not proof that a deployed host's filesystem/process/network boundaries are correct; test them from the actual untrusted agent host before enrolling any real account.

## PostgreSQL

`db/001_authorization.sql` contains only metadata and signed approval bytes. Passwords, seeds, OTPs, cookies, and destination tokens are forbidden. `PostgresStore` uses a singleton metadata row `FOR UPDATE` to serialize authority changes, then commits request/nonce/lease/permit/session updates in the same transaction. Use one live controller boot epoch; a newly started controller invalidates prior authority. Horizontal controller startup/leadership is not implemented.

PGlite tests exercise PostgreSQL SQL/constraints and restart semantics. Two opt-in tests also passed against the Docker PostgreSQL 17 server using independent connection pools and an isolated random schema: competing nonce approvals, execution leases and permit consumption, conflicting idempotency rollback, and restart fencing. These do not establish database TLS, replication, backup/restore, horizontal leadership, or production deployment behavior. The store currently reads metadata into a transaction snapshot and writes it back; review performance/retention before production scale.

Approval/device registration and transport configuration currently live in the owner-only settings file. Audited recovery, owner proof, APNs provisioning, and backup/restore ceremonies remain explicit release work. The agent MCP API has no recovery path.
