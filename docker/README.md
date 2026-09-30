# Synthetic local Docker hosting

This stack hosts the existing synthetic broker, a private PostgreSQL 17 service and a Caddy TLS sidecar. It is development hosting. The owner/agent still has Docker administration on this laptop; containers do not satisfy the production credential-isolation release gate.

The pinned `mcr.microsoft.com/playwright:v1.63.0-noble` image includes Node 24, matching browsers and their Linux dependencies. Both broker and Caddy run as the host's non-root UID/GID. Chromium retains `chromiumSandbox: true`; startup refuses to become healthy if its sandbox cannot launch. The version-pinned [official Playwright seccomp profile](https://github.com/microsoft/playwright/blob/v1.63.0/utils/docker/seccomp_profile.json) permits user namespace creation, with one narrow addition allowing `chroot` so Chromium can enter its child sandbox despite all outer container capabilities being dropped. Kernel capability checks still apply to that syscall; no `SYS_ADMIN` or outer `SYS_CHROOT` capability is granted. The broker uses a private 1 GiB shared-memory allocation and receives no Docker socket, host browser profile, real credential store or certificate private keys.

Prepare and start from the repository root:

```sh
BROKER_TLS_HOST=yujamac.local BROKER_TLS_IP=192.168.68.57 BROKER_TLS_BIND=0.0.0.0 node scripts/docker-bootstrap.mjs
node scripts/docker-start.mjs
node scripts/docker-ca-export.mjs
node scripts/docker-start.mjs --verify-only
docker compose --env-file .local/docker.env --profile test run --build --rm postgres-tests
```

`.local/docker.env` contains a generated database password and must remain mode 0600. Never print it, run unredacted `docker compose config`, or publish Docker inspection/environment output. The initial bootstrap privately copies `.local/broker.json` to `.local/state/broker.json`. **While running Docker, `.local/state/broker.json` is the canonical mutable owner/client/device/policy configuration.** Subsequent bootstrap preserves it. Only `.local/state/` mounts into the broker; standalone owner/client token files, Docker credentials and TLS private keys remain outside that mount. PostgreSQL has no published host port and uses the private internal metadata network.

MCP remains at `http://127.0.0.1:3210/mcp`; the local owner console is `http://127.0.0.1:3211/`. Caddy shares the broker's network namespace, forwarding to the application's unchanged loopback listeners. The device/owner listener is `https://yujamac.local:8443/`, using one development leaf certificate with both hostname and LAN IP SANs. LAN port 8080 serves only `/broker-root-ca.crt` and `/broker-development-ca.mobileconfig` from a public-only directory. The profile contains one public development root certificate and no VPN, MDM, web clip or private key.

Installing and fully trusting the root certificate on a physical iPhone requires the owner’s explicit device ceremony; bootstrap does not trust it on this Mac or any phone. Compare the public CA SHA-256 before installing. The native TLS pin is the SHA-256 of the full leaf certificate DER, stored in `.local/tls/leaf-cert-sha256`; it is not the approval-device public-key fingerprint. Leaf certificates expire after seven days and the local CA after thirty days. Renew through an owner-controlled TLS review, then update/reverify the exact native certificate pin. Bootstrap preserves existing trust/key files and refuses a changed hostname, partial state or expired leaf.

Caddy depends on broker health with Compose `restart: true`. Treat broker restart and recreation as a paired broker/TLS lifecycle operation because Caddy holds the broker's network namespace. Do not rely on an automatic Engine restart to update a dependent sidecar; its health check surfaces a stale proxy. Use `node scripts/docker-start.mjs` for coordinated changes; if recovering manually, run `docker compose --env-file .local/docker.env up -d --force-recreate broker tls`. Both services have health checks, including HTTPS and the public CA route. Do not restore access by disabling the Chromium sandbox or removing private configuration checks.

The opt-in external PostgreSQL test uses two independent pools and a random temporary schema. It exercises atomic approval-nonce replay, execution leasing, one-use permit consumption, rollback and restart fencing without touching the running broker’s schema. Its test service never mounts owner or device configuration.
