# Agent-assisted setup

This guide is for an owner-authorized setup agent, not an MCP client. Read [AGENTS.md](AGENTS.md) and the [implementation status](docs/implementation-status.md) first.

## Prepare the software

Use Node.js 24 and Docker. iPhone setup also requires macOS, Xcode, an Apple development signing team and a Mac-paired physical iPhone with Developer Mode enabled.

```sh
npm run onboard -- --iphone --team <TEAM_ID>
```

Reuse the configured signing team. Ask for one only if it is missing or unavailable.

The helper installs missing npm dependencies and starts Docker Desktop if it is installed but stopped. It prepares or reuses Docker services and TLS, verifies endpoints and installs the app. It transfers an unverified setup draft only if the selected phone is confirmed to be unpaired.

The helper does not open or connect the owner console or complete trust, verification, physical pairing, owner confirmation or biometric approval. The setup agent can prepare the owner handoff described below.

| Command                                 | Use                                                                |
| --------------------------------------- | ------------------------------------------------------------------ |
| `npm run onboard -- --status`           | Check the existing setup without enrolling or confirming a device. |
| `npm run onboard -- --iphone`           | Prepare or resume setup using the configured signing team.         |
| `npm run onboard -- --refresh`          | Update the broker and HTTPS proxy, preserving data and identities. |
| `npm run onboard -- --iphone --refresh` | Update the services and installed app in place.                    |

Use `--device`, `--host`, `--ip` or `--team` only to resolve a missing or ambiguous choice, using verified inventory or the owner's selection. Finish active flows before refreshing: restarting the broker invalidates outstanding approvals, permits and sessions.

## Preserve the existing setup

Reuse `.local/docker.env`, the canonical `.local/state/broker.json`, certificates, transport identities, Docker volumes and the app's Keychain. Keep the current approval mode. Rerunning setup is not a reason to reset data, replace a key or create another pairing code.

For an existing phone, match its fresh public receipt to the exact owner record: broker URL, leaf-certificate SHA-256, device ID and full approval-key SPKI SHA-256. An ACTIVE device count or matching name is not enough. Inspect stale, missing, revoked or mismatched receipts before continuing.

## Keep private material private

- Use the helper's public summary. Do not print private configuration, transport tokens, pairing drafts, device inventory or build logs.
- Read the owner token inside trusted local code and enter it directly in the console's password field. Clear the field after connection. Keep it out of chat, URLs, browser storage and screenshots.
- Configure the paired MCP client from its private local file without exposing its Authorization header.
- Keep single-use pairing codes masked. Reuse only a valid, unconsumed code bound to the selected phone.
- Never add real passwords, OTP seeds, cookies, vault tokens, approval private keys or reusable browser state to fixtures or Git.

## Complete the owner handoff

1. Verify the served HTTPS certificate against the prepared CA and full leaf fingerprint. Preserve system trust and certificate pinning.
2. Open and connect the owner console. For an exactly matched ACTIVE phone, reuse its enrollment.
3. Only for a phone confirmed to be unpaired, prepare the app's draft and any public certificate-only profile. A draft does not verify trust, create a key, enroll a device or authorize a request.
4. Stop iPhone Mirroring before physical pairing or biometric approval. Give the owner one concise instruction for the remaining actions.
5. After pairing, compare all 64 hexadecimal characters of the phone's approval-key SPKI fingerprint with the console record. Confirm the device only during an explicitly authorized owner ceremony, then verify that this exact device is ACTIVE.

The owner handles required OS consent, certificate trust, system passcode entry, physical pairing and Face ID or Touch ID. Do not inspect or capture the phone during passcode or biometric entry.

The setup agent may compare public fingerprints when the owner has authorized that ceremony. Never check a verification control or confirm a device just because an import or poll succeeded.

## Verify and report

When the owner requests a functional test, queue one fresh synthetic request:

```sh
npx tsx scripts/device-smoke.ts request
```

Show the request's exact review, stop iPhone Mirroring and hand off one physical approval. After the owner reports completion, run:

```sh
npx tsx scripts/device-smoke.ts wait
```

Verify signature acceptance, successful sign-in, one restricted profile read and session end. A tap or successful login alone does not verify the full flow.

Investigate failures using public health output and typed errors. Do not blindly retry uncertain delivery or enrollment.

Report software readiness, exact device enrollment and functional test results separately. State any remaining device or production gates. The setup agent can access the local host; Docker does not provide production isolation. Do not describe local setup as production-ready or fully unattended.
