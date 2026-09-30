# boring.password

A self-hosted authentication broker for AI agents. The broker runs authorized sign-ins and gives MCP agents opaque references and typed results, not credentials.

**Development only: the current implementation uses synthetic accounts. Production credential release is disabled.** The local Docker setup does not isolate secrets from an agent with host access.

## How it works

1. A paired agent requests access to an owner-configured account.
2. When device approval is required, the iPhone app shows the destination, account and requested access. You approve the exact request with Face ID or Touch ID.
3. A trusted browser worker signs in and verifies the account. The agent can use only the session's named operations, then end the session.

The broker includes a TypeScript authorization core, PostgreSQL storage, an MCP endpoint, a web owner console and a Swift approval app. The included browser adapter tests password and TOTP sign-in against a local test site.

## Start locally

Install Node.js 24 and Docker, then run:

```sh
npm run onboard
```

The helper installs missing npm dependencies and starts Docker Desktop if it is installed but stopped. It prepares or reuses Docker services and TLS, checks endpoints and prints the console address. It does not open or connect the owner console.

The local defaults are `http://127.0.0.1:3211` for the owner console and `http://127.0.0.1:3210/mcp` for MCP. Private configuration stays in `.local/` and is excluded from Git.

For iPhone setup, use a Mac with Xcode, an Apple development signing team and a Mac-paired physical iPhone with Developer Mode enabled:

```sh
npm run onboard -- --iphone --team <TEAM_ID>
```

The helper builds and installs the app. It transfers an unverified connection draft only if the selected phone is confirmed to be unpaired. It does not complete trust, verification, physical pairing, owner confirmation or biometric approval. Follow [agent.md](agent.md) for the handoff, including required iOS trust and passcode prompts.

```sh
npm run onboard -- --status
npm run onboard -- --refresh
```

`--status` checks the existing setup. `--refresh` updates the broker and HTTPS proxy while preserving database data, certificates and pairing. Add `--iphone` to update the app too.

## Approval modes

Choose a mode in the owner console, review the change, then click **Apply change**.

| Mode   | Behavior                                                                                                      |
| ------ | ------------------------------------------------------------------------------------------------------------- |
| Manual | Every sign-in requires a registered device's signature over the exact request.                                |
| Safe   | Checks eligibility, then requires the same device signature. Eligibility alone does not authorize sign-in.    |
| Auto   | An exact existing owner delegation can authorize sign-in without device approval. Other requests are blocked. |

Changing modes retires old requests, approvals and sessions. Any affected request with possible credential delivery is terminal, and its runtime is quarantined.

The required Auto delegation must already be bound to the new policy version; selecting Auto does not create or renew it. Agents cannot change modes or grant themselves access.

## Development

```sh
npm ci
npx playwright install chromium
npm run check
npm run demo
```

The checks run type checking, tests and a build. The demo exercises all three modes with synthetic signing keys; it is not a biometric test.

Read the [design](docs/design.md), [implementation status](docs/implementation-status.md) and [deployment notes](docs/deployment.md) before using this beyond the local test setup. Production use still requires isolated deployment, the remaining physical-device tests, owner recovery, vault review and a reviewed real-service adapter.
