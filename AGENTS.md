# Repository guidance

Read `docs/design.md` and `docs/implementation-status.md` before changing authentication authority or release claims.

For owner-authorized onboarding, follow [agent.md](agent.md). It separates automated preparation from the required physical owner ceremony. The security boundaries below still apply.

Use synthetic accounts only. Do not put production passwords, vault tokens, seeds, OTPs, cookies, destination tokens, approval private keys or reusable browser state in agent-visible output or workspace fixtures. Production account and adapter enrollment and Vault release-capability issuance must remain disabled until evidence satisfies the design's security release gate.

Maintain these boundaries:

- Derive owner, client and workload identity from trusted transport enrollment. Agents cannot select destinations, adapters, factors, runtimes, modes, policies or permissions.
- Manual and Safe require a registered device's signature over the exact request. Safe eligibility is not authorization. Auto requires an exact existing owner-created delegation bound to the active policy version and cannot fall back to Manual.
- On mode changes, retire old requests, approvals and sessions. If credentials may have been delivered, mark the affected request terminal and quarantine its runtime. Selecting Auto does not create or renew a delegation; an exact one must already be bound to the new policy version.
- Keep approval bytes immutable and nonce consumption atomic. Bind permits to the request revision, worker/runtime/execution generations, credential version, factor, adapter step and destination.
- Treat consumed permits as possible delivery before returning metadata. Uncertain delivery or submission is terminal: quarantine the runtime and do not retry blindly.
- Keep credentials in callback-scoped trusted service/worker channels. Never add agent-side secret getters, global authref replacement, arbitrary scripting, CDP, screenshots, traces, HAR, storage exports, cookie exports or auth-header exports.
- Keep owner, device and recovery authority outside the agent MCP listener. Stage owner settings, persist before activation and suspend authority on persistence faults.
- Keep session references caller/workload-bound and restricted to named action/observation profiles. Login approval does not authorize arbitrary post-login operations.
- Serialize errors, audit records and results with explicit typed allowlists. Do not log raw request objects, secrets, browser state, exception bodies or vault responses.

Run `npm run check` and the meaningful adversarial tests for changed boundaries. Browser tests use actual sandboxed Chromium and synthetic credentials. PGlite and simulator results are local functional evidence; they do not replace a deployed PostgreSQL server, physical Face ID/Touch ID tests, trusted-host isolation or reviewed real-service adapter evidence.

The native app's broker connection must retain HTTPS system trust and owner-confirmed certificate pinning. Use a fresh LAContext for every biometric signature. Do not weaken biometric key access to make simulator tests pass.
