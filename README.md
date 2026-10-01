# boring.password

boring.password is a self-hosted authentication broker for AI agents. It runs authorized sign-ins and gives MCP agents opaque references and typed results, not credentials.

**Development only: the current implementation uses synthetic accounts. Production credential release is disabled.** The local Docker setup does not isolate secrets from an agent with host access.

## How it works

1. A paired agent requests access to an owner-configured account.
2. When device approval is required, the iPhone app shows the destination, account and requested access. You approve the exact request with Face ID or Touch ID.
3. A trusted browser worker signs in and verifies the account. The agent can use only the session's named operations, then end the session.

The broker includes a TypeScript authorization core, PostgreSQL storage, an MCP endpoint, a web owner console and a Swift approval app. The included browser adapter tests password and TOTP sign-in against a local test site.

## Quickstart

### 1. Clone the repository

Install Git, Node.js 24, Docker with Compose and OpenSSL, then run:

```sh
git clone https://github.com/yordlejason/boring.password.git
cd boring.password
```

### 2. Start the broker

Choose one command for the initial setup. For iPhone approval, use the iPhone command from the start. Desktop-only setup persists loopback-only phone listeners; a later `--iphone` run refuses that configuration rather than migrating it.

For the desktop server only, without installing the iPhone app:

```sh
npm run onboard
```

For phone access and native app installation, you need a Mac with Xcode, an Apple development signing team and a physical iPhone paired with the Mac. Enable Developer Mode on the phone and make sure it can reach the Mac on your private local network:

```sh
npm run onboard -- --iphone --team <TEAM_ID>
```

No initial `npm ci` or host Chromium installation is needed: the helper installs missing npm dependencies, and the Docker image supplies Chromium.

The helper starts Docker Desktop if it is installed but stopped, prepares or reuses Docker services and TLS, checks endpoints and prints the console address. With `--iphone`, it also configures phone access, builds the app and installs it. Private configuration stays in `.local/` and is excluded from Git.

### 3. Connect the console and MCP client

The helper does not connect the console. Open the printed address, normally `http://127.0.0.1:3211`, and enter the token from `.local/owner-token` in its password field.

Configure your MCP client privately using the URL and `Authorization` header in `.local/mcp-client.json`. The default endpoint is `http://127.0.0.1:3210/mcp`; configuration and import syntax vary by client. Keep both files private. Do not print their contents or include them in chat, logs or screenshots.

### 4. Pair the iPhone

For iPhone setup, follow [agent.md](agent.md) to complete the physical owner ceremony. This requires HTTPS system trust, verification of the exact full TLS fingerprint, physical pairing and owner confirmation of the full approval-key fingerprint.

The helper transfers an unverified connection draft only if the selected phone is confirmed to be unpaired. It does not complete trust, pairing, owner confirmation or biometric approval. The owner must complete the required iOS trust and passcode prompts and Face ID or Touch ID directly on the phone.

Starting the server alone does not complete a sign-in. The default Manual mode requires approval from a paired device.

## Check or update the setup

```sh
npm run onboard -- --status
npm run onboard -- --refresh
```

`--status` checks the existing setup. `--refresh` updates the broker and HTTPS proxy while preserving database data, certificates and pairing. Add `--iphone` when refreshing an existing iPhone setup to update the app too.

## Approval modes

Choose a mode in the owner console, review the change, then click **Apply change**.

| Mode   | Behavior                                                                                                                          |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| Manual | Every sign-in requires a registered device's signature over the exact request.                                                    |
| Safe   | Checks eligibility, then requires the same device signature. Eligibility alone does not authorize sign-in.                        |
| Auto   | An exact match to an existing owner-created delegation can authorize sign-in without device approval. Other requests are blocked. |

Changing modes retires old requests, approvals and sessions. Affected requests with possible credential delivery are marked terminal, and their runtimes are quarantined.

For Auto, the required delegation must already be bound to the new active policy version. Selecting Auto does not create or renew it. Agents cannot change modes or grant themselves access.

## Development

```sh
npm ci
npx playwright install chromium
npm run check
npm run demo
```

The checks run type checking, tests and a build. The demo exercises all three modes with synthetic signing keys; it does not test biometrics.

Read the [design](docs/design.md), [implementation status](docs/implementation-status.md) and [deployment notes](docs/deployment.md) before using this beyond the local test setup. Outstanding production requirements include isolated deployment, the remaining physical-device tests, owner recovery, vault review and a reviewed real-service adapter.
