# Self-Hosted LLM Authentication Broker

**Technical Design Document**

**Version:** 1.0

**Status:** Implementation specification
**Primary use case:** Allow AI agents such as ChatGPT, Claude, Codex, browser agents, and computer-use agents to authenticate to user-authorized services without exposing credentials to the LLM.

---

# 1. Overview

Build a self-hosted authentication broker that allows an AI agent to complete authentication workflows while ensuring that passwords, TOTP secrets, OTP codes, session cookies, refresh tokens, passkeys, and other reusable authentication material never enter the model's visible context.

The system acts as a trusted intermediary between:

1. an AI agent requesting authentication;
2. the user's credential store;
3. a controlled browser or execution environment;
4. an optional human approval device such as an iPhone using Face ID or a Mac using Touch ID.

The LLM interacts only with opaque references and sanitized authentication state.

The broker owns secret resolution and credential injection.

The system supports three operating modes:

- **Auto** — authentication executes automatically when covered by an explicit owner-created delegation.
- **Safe** — an internal risk classifier must classify the request as safe, after which human biometric approval is still required.
- **Manual** — every otherwise-valid authentication request requires human approval.

The broker must fail closed.

---

# 2. Product security contract

The primary security guarantee is:

> For supported authentication flows, the AI agent can cause authentication to occur without receiving credentials or reusable authentication material.

The following must never be exposed to the LLM:

- plaintext passwords;
- password manager contents;
- TOTP seeds;
- generated OTP/TOTP values;
- recovery codes;
- session cookies;
- browser storage containing reusable credentials;
- OAuth authorization codes;
- OAuth access tokens;
- OAuth refresh tokens;
- passkey private keys;
- Secure Enclave private keys;
- biometric data;
- raw authentication headers;
- secret-bearing clipboard contents;
- secret-bearing browser traces.

The agent may receive:

- opaque account references;
- opaque request references;
- opaque session references;
- sanitized status values;
- broker-approved metadata;
- restricted post-authentication results.

The broker must not rely solely on hiding secret-returning APIs. The protected runtime must prevent the agent from obtaining equivalent credential access through debugging interfaces, browser storage, filesystem access, process inspection, screenshots, logs, traces, or unrestricted scripting.

---

# 3. Non-goals

Version 1 does not attempt to:

- bypass CAPTCHA;
- bypass device trust;
- bypass biometric requirements;
- bypass hardware security keys;
- simulate Touch ID or Face ID for another service;
- defeat anti-bot protections;
- bypass operating-system privilege prompts;
- provide arbitrary passwords to shell commands;
- provide unrestricted authenticated browser debugging;
- automatically support every embedded browser inside third-party AI applications;
- perform arbitrary credential extraction;
- replace full password managers;
- guarantee safety of every action performed after login.

Authentication authorization and post-login action authorization are separate concepts.

---

# 4. Trust model

## 4.1 Trusted components

The following components form the trusted computing base:

- Authentication Broker Controller
- Policy Engine
- Secret Service
- Protected Execution Worker
- Observation Gateway
- Native Approval Application
- Credential Vault Adapter
- Authentication Adapter definitions
- Metadata/Audit database
- owner-controlled administrative interface

## 4.2 Untrusted components

Treat the following as untrusted:

- the LLM;
- agent-generated descriptions;
- page text;
- web content;
- prompt instructions contained in websites;
- arbitrary MCP clients;
- model-supplied URLs;
- model-supplied selectors;
- model-supplied client names;
- third-party browser extensions;
- unrelated MCP servers;
- arbitrary JavaScript supplied by the agent.

## 4.3 Deployment assumption

The agent must not have administrator-level control over the trusted execution environment.

The agent must not be able to:

- access the broker's secret-service filesystem;
- inspect protected worker memory;
- control the VM/container manager hosting the trusted worker;
- mount the protected browser profile;
- access protected browser debugging ports;
- read vault credentials;
- modify broker policy;
- modify authentication adapters;
- approve its own requests.

Development environments may run components together, but such a configuration must not be labeled as providing production-grade credential isolation.

---

# 5. High-level architecture

```text
┌───────────────────────────────┐
│ AI Agent / LLM Host           │
│                               │
│ ChatGPT / Claude / Codex      │
│ Browser Agent / Computer Use  │
└───────────────┬───────────────┘
                │
                │ MCP
                ▼
┌───────────────────────────────┐
│ Authentication Broker         │
│                               │
│ - MCP Gateway                 │
│ - Request Controller          │
│ - Policy Engine               │
│ - Risk Classifier             │
│ - Audit Controller            │
└───────────────┬───────────────┘
                │
       ┌────────┴────────┐
       │                 │
       ▼                 ▼
┌──────────────┐   ┌──────────────────┐
│ Secret       │   │ Approval Service │
│ Service      │   │                  │
│              │   │ iPhone / macOS   │
│ Password     │   │ Face ID/Touch ID │
│ TOTP         │   │ protected key    │
│ OAuth tokens │   └────────┬─────────┘
└──────┬───────┘            │
       │                    │ signed approval
       └──────────┬─────────┘
                  ▼
      ┌───────────────────────────┐
      │ Protected Execution       │
      │ Environment               │
      │                           │
      │ Controlled browser        │
      │ Authentication adapters   │
      │ Observation filtering     │
      └─────────────┬─────────────┘
                    │
                    ▼
              Destination Service
```

---

# 6. Components

## 6.1 MCP Gateway

Responsibilities:

- authenticate MCP clients;
- derive caller identity from transport credentials;
- validate tool arguments;
- enforce rate limits;
- expose only agent-safe tools;
- return sanitized results;
- prevent administrative APIs from appearing in the agent tool list.

Suggested implementation:

- TypeScript
- Node.js 22+
- official or maintained MCP SDK
- schema validation using Zod or equivalent

The gateway must never expose secret values.

---

## 6.2 Request Controller

The Request Controller owns authentication transaction state.

Responsibilities:

- create authentication requests;
- provide idempotency;
- capture immutable request context;
- apply policy;
- coordinate human approval;
- issue worker-bound execution permits;
- manage expiration;
- manage cancellation;
- coordinate crash recovery;
- produce sanitized status responses.

The controller is the authoritative state machine.

Workers must not independently decide whether authentication is authorized.

---

## 6.3 Policy Engine

The Policy Engine determines whether authentication may proceed.

Inputs include:

- authenticated caller;
- account;
- destination;
- authentication adapter;
- requested operation;
- required factors;
- execution environment;
- workload;
- configured mode;
- policy version;
- current delegation state.

Mandatory security checks execute before mode-specific behavior.

---

## 6.4 Risk Classifier

Used only in **Safe** mode.

Allowed outputs:

```json
{
  "classification": "safe",
  "reason_codes": [],
  "uncertainties": []
}
```

or:

```text
unsafe
uncertain
```

Rules:

- classifier is broker-controlled;
- requesting LLM cannot select the classifier;
- secrets must not be provided to the classifier;
- classifier receives minimized context only;
- website instructions are untrusted data;
- malformed output becomes `uncertain`;
- inference timeout becomes `uncertain`;
- classifier unavailable becomes `uncertain`;
- `unsafe` and `uncertain` always block;
- `safe` still requires human approval.

The classifier is an eligibility filter, not authorization.

---

## 6.5 Secret Service

The Secret Service is the only component allowed to retrieve authentication secrets.

Responsibilities:

- access enrolled credentials;
- retrieve exact credential versions;
- generate TOTP;
- access OAuth credentials when supported;
- authorize use only after receiving a valid execution permit;
- return secrets only over a private trusted-worker channel.

The service must not provide general APIs such as:

```text
get_password
get_totp
resolve_secret
list_all_credentials
dump_vault
```

Instead, use narrowly scoped operations such as:

```text
consume_password_permit()
consume_totp_permit()
```

A permit must be bound to a specific request and authentication step.

---

# 7. Operating modes

## 7.1 Manual

Every valid authentication transaction requires human approval.

Flow:

```text
request
  ↓
mandatory checks
  ↓
approval request
  ↓
Face ID / Touch ID
  ↓
execute
```

A previous approval does not authorize future independent authentication requests.

---

## 7.2 Safe

Flow:

```text
request
  ↓
mandatory checks
  ↓
risk classifier
  ↓
safe?
  ├─ no → BLOCK
  └─ yes
       ↓
     human approval
       ↓
     execute
```

Safe mode never performs unattended authentication.

---

## 7.3 Auto

Auto requires an explicit owner-created delegation.

Example delegation:

```text
Client:
  Codex Home Server

Account:
  GitHub Personal

Destination:
  github.com

Factors:
  password + TOTP

Allowed operation:
  sign_in

Session permissions:
  issue read access

Expiration:
  30 days
```

Requests within the delegation execute automatically.

Requests outside the delegation block.

Auto must not automatically fall back to Manual.

---

# 8. Authentication request model

Each authentication request must include or derive:

```text
request_id
revision
owner_id
client_id
workload_id
runtime_id
runtime_generation
account_id
credential_binding_version
destination
identity_provider
relying_party
operation
authentication_adapter
adapter_version
factor_plan
session_action_profile
observation_profile
policy_id
policy_version
mode
created_at
expires_at
idempotency_key
```

The following must be derived from trusted broker state, not accepted blindly from the LLM:

- caller identity;
- effective destination;
- account binding;
- authentication adapter;
- policy;
- authentication factors;
- execution runtime identity.

---

# 9. MCP API

Expose the following tools.

## `auth.capabilities`

Returns capabilities for the current caller.

Example:

```json
{
  "protected_browser": true,
  "password": true,
  "totp": true,
  "remote_biometric_approval": true,
  "native_macos_auth": false,
  "oauth": false
}
```

---

## `auth.inspect`

Inspect an authentication context.

Input:

```json
{
  "target_ref": "browser_target_123"
}
```

Output:

```json
{
  "context_ref": "ctx_84b2",
  "authentication_required": true,
  "destination": "github.com",
  "supported_accounts": [
    {
      "account_ref": "acct_github_personal",
      "display_name": "GitHub Personal"
    }
  ]
}
```

No secrets are returned.

---

## `auth.request`

Input:

```json
{
  "context_ref": "ctx_84b2",
  "account_ref": "acct_github_personal",
  "operation": "sign_in",
  "workload_ref": "task_122",
  "purpose": "Access the repository requested by the owner.",
  "idempotency_key": "task_122_auth_1"
}
```

Output examples:

```json
{
  "request_id": "req_123",
  "state": "AWAITING_APPROVAL"
}
```

or:

```json
{
  "request_id": "req_123",
  "state": "AUTHORIZED"
}
```

---

## `auth.status`

```json
{
  "request_id": "req_123"
}
```

Response:

```json
{
  "request_id": "req_123",
  "state": "EXECUTING",
  "next_action": "WAIT"
}
```

---

## `auth.cancel`

Cancels a pending request.

Cancellation after credential delivery cannot retroactively retract the credential.

The returned result must state whether secret delivery had already occurred.

---

## `session.perform`

Optional protected-session operation.

Example:

```json
{
  "session_ref": "session_52c1",
  "operation": "github.list_repositories",
  "arguments": {}
}
```

The initial implementation should prefer named operations rather than unrestricted browser control.

---

## `session.end`

Ends access to the broker-managed session.

---

# 10. Placeholder design

Opaque placeholders are supported only as internal adapter references.

Example:

```text
authref://req_123/password
```

The placeholder itself contains no credential material.

The server maps it to:

```text
request_id
revision
caller_id
runtime_id
account_id
credential_version
factor
adapter_step
destination
expiration
```

Possession of the placeholder is insufficient authorization.

Only the trusted executor may resolve it.

Never implement global text replacement.

This must be invalid:

```text
curl https://example.com?password=authref://req_123/password
```

Placeholders may be consumed only by typed secret-input operations inside certified adapters.

---

# 11. Approval architecture

Human approval uses a separate native application.

Initial target:

- iOS
- Swift
- SwiftUI
- LocalAuthentication
- Security framework
- Secure Enclave when available

macOS support can reuse the same protocol.

---

# 12. Approval-device enrollment

Enrollment must occur outside the LLM-controlled environment.

Flow:

```text
Owner opens broker admin UI
       ↓
Broker generates enrollment challenge
       ↓
Native app scans/pastes pairing code
       ↓
App verifies broker identity
       ↓
App generates protected signing key
       ↓
Public key registered with broker
       ↓
Owner confirms device
```

Store:

```text
device_id
owner_id
public_key
key_algorithm
device_name
created_at
revoked_at
assurance_profile
```

The private key never leaves the device.

---

# 13. Face ID / Touch ID approval

For each approval request:

1. broker generates a unique nonce;
2. broker constructs immutable approval payload;
3. payload is persisted;
4. native app receives request;
5. app displays security-relevant fields;
6. user chooses Approve;
7. app performs biometric authorization;
8. app signs exact approval payload;
9. broker verifies signature;
10. broker consumes approval nonce atomically;
11. broker creates execution authorization.

The native app must use a fresh authentication context for each approval.

Do not intentionally reuse authentication state between approval requests.

---

# 14. Signed approval payload

Use a canonical, versioned serialization.

Suggested:

```text
CBOR + COSE_Sign1
```

Payload:

```json
{
  "version": 1,
  "action": "authorize_authentication",

  "broker_id": "broker_home",
  "boot_epoch": "boot_93841",

  "owner_id": "owner_1",
  "device_id": "iphone_1",

  "request_id": "req_123",
  "revision": 3,
  "nonce": "random_256_bit_nonce",

  "issued_at": "...",
  "expires_at": "...",

  "client_id": "codex_home",
  "workload_id": "task_122",

  "runtime_id": "browser_worker_4",
  "runtime_generation": 92,

  "account_id": "acct_github_personal",
  "credential_binding_version": 7,

  "destination": "https://github.com",
  "operation": "sign_in",

  "adapter_id": "github_login",
  "adapter_version": "3.2.1",

  "factors": [
    "password",
    "totp"
  ],

  "policy_id": "policy_44",
  "policy_version": 12,

  "session_action_profile": "github_read_repository",

  "review_digest": "..."
}
```

The user must see the material security-relevant contents represented by this signed object.

The server must not display one request and sign another.

---

# 15. Biometric assurance semantics

The broker must not claim:

```text
"Server independently verified Face ID."
```

The server verifies:

```text
A registered device-controlled key signed the exact request.
```

The native application is responsible for enforcing its intended biometric policy before use of that key.

Use a device-bound biometric-protected key where supported.

A biometric enrollment change should invalidate or require re-enrollment of the approval key under the strict security profile.

Possible server assurance label:

```text
OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE
```

This is more accurate than:

```text
FACE_ID_VERIFIED
```

---

# 16. Approval UI

Example:

```text
Authentication Request

Destination
github.com

Account
GitHub Personal

Requested by
Codex — Home Server

Authentication
Password + TOTP

Access after login
Repository read operations

Agent-stated purpose
"Inspect the requested repository"

Expires
4 minutes

[Approve with Face ID]

[Deny]
```

Rules:

- destination is broker-verified;
- account is broker-verified;
- client identity is broker-derived;
- agent purpose is explicitly labeled;
- page-provided text must not be shown as trusted broker data;
- URL must not be visually truncated in a misleading way;
- repeated approval spam must be rate-limited.

Opening a push notification must never count as approval.

---

# 17. Authentication adapters

Do not build authentication as generic LLM-driven DOM interaction initially.

Each supported service uses a reviewed adapter.

Example:

```text
github_login@3.2.1
```

Adapter manifest:

```yaml
id: github_login
version: 3.2.1

allowed_origins:
  - https://github.com

allowed_identity_origins:
  - https://github.com

steps:
  - detect_login
  - enter_username
  - enter_password
  - detect_totp
  - enter_totp
  - verify_authenticated_account
```

Adapters may use selectors and navigation rules internally.

Adapters are installed and updated by an administrator.

The LLM cannot modify an adapter while authentication is active.

---

# 18. Protected browser runtime

Recommended initial browser engine:

```text
Chromium + Playwright
```

The browser worker must not expose to the agent:

- CDP endpoint;
- browser profile;
- cookies;
- local storage;
- indexed DB;
- authorization headers;
- browser trace;
- HAR export;
- unrestricted page source during authentication;
- arbitrary `evaluate()` calls;
- unrestricted screenshots during secret-bearing steps.

During authentication, the LLM receives status only.

Example:

```json
{
  "state": "EXECUTING",
  "phase": "SUBMITTING_SECOND_FACTOR"
}
```

---

# 19. Execution locking

Before secret release:

1. acquire exclusive runtime lease;
2. verify runtime generation;
3. verify browser session identity;
4. verify tab;
5. verify navigation context;
6. verify top-level origin;
7. verify target frame origin;
8. verify account context;
9. verify authentication step;
10. verify policy is still current.

The agent must not be able to race execution by changing page state during secret entry.

---

# 20. Credential release permits

Human approval authorizes the authentication plan.

Individual secret releases use separate one-use permits.

Example:

```text
permit_id
request_id
request_revision
runtime_id
runtime_generation
account_id
credential_version
factor
adapter_step
destination
expires_at
consumed_at
```

The secret service atomically consumes the permit before releasing the credential to the protected worker.

A consumed permit cannot be reused.

---

# 21. Password flow

Example:

```text
AUTHORIZED
   ↓
create password permit
   ↓
worker locks browser context
   ↓
worker verifies password field
   ↓
secret service consumes permit
   ↓
password delivered privately
   ↓
password inserted
   ↓
record SECRET_DELIVERED
   ↓
submit
   ↓
verify expected next state
```

Password insertion itself counts as secret delivery.

Do not wait until form submission to record exposure.

---

# 22. TOTP flow

TOTP seed remains inside the secret service.

Flow:

```text
verify TOTP challenge
       ↓
create TOTP permit
       ↓
check trusted clock health
       ↓
generate code
       ↓
consume permit
       ↓
deliver code privately
       ↓
insert
       ↓
submit
```

Do not generate TOTP while waiting for human approval.

Generate it immediately before use.

If too little lifetime remains in the current time step, wait for the next step before generating.

Store:

```text
algorithm
digits
period
```

per enrollment.

Do not assume every TOTP credential uses identical parameters.

Never log:

```text
TOTP code
TOTP seed
hash(TOTP code)
```

---

# 23. OAuth

OAuth support is post-v1 unless required for the first integration.

When implemented:

- broker stores tokens;
- tokens are never returned to LLM;
- verify provider;
- verify OAuth client;
- verify redirect URI;
- verify scope;
- distinguish login from permission expansion;
- treat new consent scopes as new authorization.

Do not forward MCP client tokens to unrelated downstream services.

---

# 24. Passkeys

Passkeys must be treated separately from broker approval.

Face ID approving a broker request does not equal Face ID authenticating a destination website.

When a destination supports passkeys:

- use standards-compliant WebAuthn flows;
- private passkey material remains in the authenticator;
- do not export passkey private keys;
- do not simulate user verification.

Cross-device passkey workflows may require physical device proximity and are not equivalent to internet-based remote broker approval.

---

# 25. Session model

After successful authentication, create a broker-owned session:

```text
session_id
owner_id
client_id
workload_id
account_id
runtime_id
runtime_generation
action_profile
observation_profile
created_at
expires_at
revoked_at
```

The LLM gets only:

```text
session_ref
```

Session references must be opaque and bound to the caller.

They must not be transferable bearer credentials.

---

# 26. Post-authentication authorization

Authentication does not imply unrestricted account access.

Use action profiles.

Example:

```text
github_repository_read
```

Allowed:

```text
list repositories
read repository metadata
read file contents
```

Not automatically allowed:

```text
create personal access token
change password
disable MFA
create SSH key
change recovery email
purchase product
transfer money
delete account
```

Sensitive post-login operations require separate policy and potentially new approval.

---

# 27. Observation profiles

An observation profile defines what information can reach the agent.

Example:

```text
github_repository_read
```

May expose:

- repository names;
- file contents;
- issue data.

Must not expose:

- cookies;
- session storage;
- authentication headers;
- browser internals;
- credentials;
- protected security settings unless explicitly allowed.

---

# 28. State machine

Primary states:

```text
CREATED
INSPECTING
POLICY_EVALUATING
CLASSIFYING
AWAITING_APPROVAL
AUTHORIZED
EXECUTING
VERIFYING
SUCCEEDED
```

Terminal and exceptional states:

```text
DENIED
FAILED
EXPIRED
CANCELLED
INTERACTION_REQUIRED
OUTCOME_UNKNOWN
```

Example:

```text
CREATED
  ↓
INSPECTING
  ↓
POLICY_EVALUATING
  ├─ Auto valid → AUTHORIZED
  ├─ Safe → CLASSIFYING
  │          ├─ safe → AWAITING_APPROVAL
  │          └─ other → DENIED
  └─ Manual → AWAITING_APPROVAL
                  ↓
             AUTHORIZED
                  ↓
              EXECUTING
                  ↓
              VERIFYING
                  ↓
              SUCCEEDED
```

---

# 29. Request immutability

Once authorization begins, security-relevant request properties become immutable.

If any of these change:

```text
client
workload
account
credential version
destination
identity provider
relying party
operation
factor plan
adapter
policy
runtime
session permissions
```

increment the request revision and require re-evaluation.

Old approvals cannot authorize a new revision.

---

# 30. Idempotency

Every request must carry an idempotency key.

Unique constraint:

```text
(owner_id, client_id, idempotency_key)
```

Reusing the key with identical canonical request data returns the existing request.

Reusing it with different data fails.

Example:

```text
IDEMPOTENCY_CONFLICT
```

---

# 31. Concurrency

Only one execution attempt may own a request revision at a time.

Use:

- database transaction;
- execution lease;
- monotonically increasing runtime generation;
- one-use secret permits.

Database leasing alone is insufficient if a stale worker remains alive.

Secret release must verify:

```text
worker_id
runtime_generation
execution_generation
```

---

# 32. Crash handling

## Before secret release

Retry may be safe.

## After permit consumption but before confirmed secret delivery

Treat conservatively.

Do not reuse the same permit.

## After possible secret delivery

Do not automatically retry authentication.

Quarantine runtime and attempt reconciliation.

If the system cannot establish the result:

```text
OUTCOME_UNKNOWN
```

Never convert uncertainty to success based solely on model interpretation.

---

# 33. Authentication success verification

A successful form submission is not sufficient.

Adapters must define verification criteria.

Example GitHub criteria:

```text
authenticated navigation reached;
expected account identity found;
login form absent;
no unexpected consent/recovery screen;
destination session established.
```

If the wrong account is authenticated:

```text
ACCOUNT_MISMATCH
```

Do not expose the session.

---

# 34. Cancellation

Before secret permit consumption:

```text
cancel immediately
```

After secret delivery:

```text
cancel remaining actions
mark credential exposure state
do not claim credential was retracted
```

Example response:

```json
{
  "state": "CANCELLED",
  "credential_delivery": "PASSWORD_ALREADY_DELIVERED"
}
```

---

# 35. Auto delegation

Auto policies are explicit owner-created delegation documents.

Example:

```json
{
  "delegation_id": "del_123",
  "client": "codex_home",
  "account": "github_personal",
  "adapter": "github_login@3.2.1",
  "operation": "sign_in",
  "factors": ["password", "totp"],
  "action_profile": "github_repository_read",
  "max_session_minutes": 60,
  "expires_at": "..."
}
```

Creating or expanding Auto delegation should require strong owner authorization.

Recommended:

```text
Face ID / Touch ID
```

Auto executions should be recorded as:

```text
DELEGATED_AUTO
```

not as biometric per-request approvals.

---

# 36. Recovery

Recovery must not share the same authority path as normal MCP requests.

Supported recovery mechanisms may include:

1. secondary enrolled approval device;
2. offline recovery credential;
3. owner-controlled local administrative process.

The LLM must never be able to:

- enroll a new approval device;
- rotate approval keys;
- reset owner authentication;
- downgrade biometric requirements;
- enable Auto;
- replace recovery material.

Restoring a database backup should invalidate or suspend outstanding approvals and execution permits.

---

# 37. Administrative operations

Require strong owner authentication for:

- adding account;
- removing account;
- connecting vault;
- pairing client;
- revoking client;
- adding approval device;
- removing approval device;
- enabling Auto;
- expanding Auto delegation;
- changing allowed destinations;
- changing session permissions;
- modifying authentication adapters;
- invoking recovery;
- disabling security controls.

Administrative APIs must not be exposed through the agent MCP interface.

---

# 38. Data model

Suggested tables:

```text
owners
clients
approval_devices
accounts
credential_bindings
destinations
authentication_adapters
policies
auto_delegations
workloads
auth_requests
approval_challenges
approvals
execution_attempts
secret_permits
protected_sessions
session_operations
audit_events
outbox_events
```

---

# 39. `auth_requests`

Important fields:

```text
id
owner_id
client_id
workload_id
account_id
revision
state
mode
runtime_id
runtime_generation
adapter_id
adapter_version
policy_id
policy_version
destination
operation
factor_plan_json
session_action_profile
observation_profile
idempotency_key
created_at
expires_at
updated_at
```

---

# 40. `approval_challenges`

```text
id
request_id
request_revision
device_id
nonce
payload_bytes
payload_digest
created_at
expires_at
consumed_at
```

Nonce must be cryptographically random.

Consumption must be atomic.

---

# 41. `secret_permits`

```text
id
request_id
request_revision
attempt_id
runtime_id
runtime_generation
factor
adapter_step
credential_version
destination
created_at
expires_at
consumed_at
```

A unique database constraint must prevent duplicate permit consumption.

---

# 42. Audit log

Audit only typed metadata.

Example:

```json
{
  "event": "AUTH_REQUEST_APPROVED",
  "request_id": "req_123",
  "client_id": "codex_home",
  "account_alias": "GitHub Personal",
  "destination": "github.com",
  "mode": "manual",
  "approval_device": "Jason iPhone",
  "timestamp": "..."
}
```

Never log:

- password;
- password hash;
- TOTP;
- TOTP hash;
- seed;
- cookie;
- bearer token;
- authorization header;
- full browser state;
- browser profile;
- recovery secret;
- passkey private material.

Audit serialization should use an allowlist rather than redacting arbitrary debug objects.

---

# 43. Notifications

Push notification:

```text
Authentication approval requested
Open Auth Broker to review.
```

Avoid putting sensitive account or site details in lock-screen notifications by default.

Notification payload contains only an opaque request reference.

Opening the notification is not authorization.

---

# 44. Rate limiting

Apply limits by:

```text
owner
client
account
destination
request type
approval device
```

Example defaults:

```text
authentication failures:
3 / 15 minutes / account+destination

approval notifications:
5 / 10 minutes / client

TOTP:
1 normal attempt
1 bounded rollover attempt if explicitly safe

password:
1 submission per execution attempt
```

Repeated failures should not result in automated credential guessing.

---

# 45. Security-sensitive error handling

Errors returned to LLM should be typed:

```text
AUTH_REQUIRED
APPROVAL_REQUIRED
CLASSIFIER_BLOCKED
POLICY_DENIED
DESTINATION_MISMATCH
ACCOUNT_MISMATCH
ADAPTER_UNSUPPORTED
INTERACTION_REQUIRED
AUTH_FAILED
OUTCOME_UNKNOWN
SESSION_EXPIRED
```

Do not return raw stack traces.

Internal error objects must not contain secret values.

---

# 46. Deployment

Recommended production topology:

```text
Agent machine
    │
    │ authenticated MCP
    ▼
Broker service
    │
    ├── metadata DB
    │
    ├── secret service
    │
    └── protected browser worker
```

For stronger isolation:

```text
Agent Host
    │
 network
    ▼
Trusted Broker VM / machine
```

The agent must not have:

```text
Docker socket
hypervisor control
root access
broker SSH credentials
vault storage
protected browser profile access
```

A local Unix socket is appropriate only when the local process boundary is trusted.

---

# 47. Initial technical stack

Recommended:

## Broker

```text
TypeScript
Node.js 22+
MCP SDK
Zod
PostgreSQL
```

## Browser worker

```text
Playwright
Chromium
isolated worker runtime
```

## Apple approval app

```text
Swift
SwiftUI
LocalAuthentication
Security
CryptoKit where appropriate
APNs
```

## Infrastructure

```text
Docker/containers for development
isolated VM or dedicated host for stronger production assurance
reverse proxy
TLS
structured logging
```

Do not implement custom password encryption.

Use an established vault backend or platform keystore abstraction.

---

# 48. Test strategy

All authentication tests use synthetic credentials until the security release gate is passed.

Tests are divided into:

- unit tests;
- integration tests;
- protocol tests;
- property tests;
- concurrency tests;
- browser adversarial tests;
- real-device biometric tests;
- recovery tests;
- deployment-isolation tests.

---

# 49. Required adversarial tests

## Policy

**T01** Manual never executes without approval.

**T02** Safe + classifier `safe` still requires approval.

**T03** Safe + classifier `unsafe` blocks.

**T04** Safe + classifier `uncertain` blocks.

**T05** Safe + malformed classifier result blocks.

**T06** Safe + classifier timeout blocks.

**T07** Auto without matching delegation blocks.

**T08** Auto cannot create its own delegation.

---

## Request binding

**T09** Changing account invalidates approval.

**T10** Changing destination invalidates approval.

**T11** Changing authentication factors invalidates approval.

**T12** Changing adapter version invalidates approval.

**T13** Changing policy version invalidates approval.

**T14** Changing workload invalidates approval.

**T15** Changing runtime generation invalidates approval.

**T16** Expired request cannot execute.

---

## Replay

**T17** Approval nonce can be consumed once only.

**T18** Concurrent replay produces at most one authorization.

**T19** Approval from another broker is rejected.

**T20** Approval from another device is rejected where device binding applies.

**T21** Approval for revision N cannot execute revision N+1.

---

## Biometrics

**T22** Cancelling Face ID does not approve.

**T23** Failed biometric does not approve.

**T24** Application backgrounding during approval aborts safely.

**T25** Device key revocation immediately prevents approval.

**T26** Changed biometric enrollment follows configured key-invalidation behavior.

**T27** Previously authenticated application context cannot silently approve a new strict request.

**T28** Opening push notification does not authorize.

---

## Browser containment

**T29** Agent cannot access Chrome DevTools Protocol endpoint.

**T30** Agent cannot access browser profile.

**T31** Agent cannot export cookies.

**T32** Agent cannot retrieve localStorage.

**T33** Agent cannot retrieve authentication headers.

**T34** Agent cannot call arbitrary JavaScript during protected authentication.

**T35** Agent cannot receive password-containing screenshots.

**T36** Agent cannot request HAR/trace containing authentication data.

---

## Destination integrity

**T37** Navigation after approval invalidates execution when security context changes.

**T38** Credential field in unexpected cross-origin frame is rejected.

**T39** Lookalike hostname is rejected.

**T40** Unexpected OAuth scope expansion is rejected.

**T41** Unexpected account recovery flow is rejected.

**T42** Authentication into wrong account does not expose session.

---

## Credential lifecycle

**T43** Password permit can be consumed once.

**T44** TOTP permit can be consumed once.

**T45** Worker crash after password delivery does not blindly retry password.

**T46** Worker crash with ambiguous submission results in `OUTCOME_UNKNOWN`.

**T47** TOTP is generated only immediately before use.

**T48** TOTP seed never appears in application logs.

**T49** OTP never appears in application logs.

---

## Session containment

**T50** `session_ref` cannot be used by another client.

**T51** `session_ref` cannot be used by another workload unless policy allows it.

**T52** Session operation outside action profile is denied.

**T53** Token-generation security page is denied by a read-only profile.

**T54** Browser-storage export is denied.

**T55** Session expiration prevents subsequent operation.

---

## Recovery

**T56** Agent cannot enroll approval device.

**T57** Agent cannot initiate security downgrade.

**T58** Revoked device approval fails.

**T59** Restored database does not reactivate consumed approvals.

**T60** Recovery does not reuse normal agent credentials as owner proof.

---

## Logging

**T61** Synthetic password absent from all logs.

**T62** Synthetic TOTP seed absent from all logs.

**T63** Synthetic OTP absent from all logs.

**T64** Session cookie absent from all logs.

**T65** Raw authorization header absent from all logs.

**T66** Crash reporter does not contain secret-bearing browser state.

---

# 50. Property-based tests

Generate random mutations to authorization-bound fields and assert:

```text
approval(A) cannot authorize B
```

for any:

```text
A != B
```

across security-relevant fields.

Property:

```text
If canonical authorization payload changes,
previous approval must not remain executable.
```

---

# 51. Concurrency tests

Test:

```text
two workers acquire same request;
two approval responses arrive simultaneously;
two TOTP workers race;
cancel races with secret release;
policy revocation races with execution;
device revocation races with approval verification.
```

The expected result must always be fail-closed.

---

# 52. Real-device tests

Face ID / Touch ID tests must run on physical Apple hardware.

Do not treat mocked LocalAuthentication success as evidence for the biometric security profile.

Test:

- successful biometric;
- cancelled biometric;
- failed biometric;
- device lock;
- app backgrounding;
- key invalidation;
- device revocation;
- multiple simultaneous approval requests;
- request expiration;
- network loss after biometric approval.

---

# 53. Security release gate

Production credentials must not be introduced until all of the following are true:

1. synthetic credential isolation tests pass;
2. browser containment tests pass;
3. approval replay tests pass;
4. crash/retry tests pass;
5. recovery tests pass;
6. real-device approval tests pass;
7. logging leakage tests pass;
8. deployment configuration has been reviewed;
9. the agent does not have administrative access to the trusted runtime;
10. at least one authentication adapter has been manually reviewed.

---

# 54. Implementation phases

## Phase 1 — Core authorization model

Implement:

- PostgreSQL schema;
- request state machine;
- policy engine;
- idempotency;
- revisions;
- execution leases;
- one-use permits;
- fake secret service;
- synthetic adapter.

No browser or real credentials yet.

Exit:

```text
policy, replay, concurrency, and crash-state tests pass
```

---

## Phase 2 — Apple approval app

Implement:

- iOS application;
- enrollment;
- device key;
- Face ID approval;
- signed approval envelope;
- revocation;
- push notifications;
- server verification.

Exit:

```text
real-device signed approval tests pass
```

---

## Phase 3 — Protected browser

Implement:

- Chromium worker;
- restricted Playwright wrapper;
- runtime generation;
- origin validation;
- frame validation;
- observation gateway;
- synthetic login website;
- password injection;
- synthetic TOTP.

Exit:

```text
all synthetic secret containment tests pass
```

---

## Phase 4 — Modes

Implement:

- Manual;
- Safe;
- Auto delegation;
- local Safe classifier;
- policy administration UI.

Exit:

```text
mode truth-table tests pass
```

---

## Phase 5 — Vault

Add one supported secret backend.

Interface:

```typescript
interface SecretProvider {
  usePassword(
    credentialRef: CredentialRef,
    permit: SecretPermit
  ): Promise<SecretHandle>;

  generateTotp(
    credentialRef: CredentialRef,
    permit: SecretPermit
  ): Promise<SecretHandle>;
}
```

`SecretHandle` must not expose plaintext to the controller or MCP layer.

Exit:

```text
vault integration leakage tests pass
```

---

## Phase 6 — First real service adapter

Select one low-risk service.

Implement reviewed adapter.

Use a test account first.

Exit:

```text
end-to-end Manual, Safe, and Auto flows pass
```

---

## Phase 7 — Restricted authenticated operations

Implement action profiles and `session.perform`.

Do not expose generic unrestricted browser control yet.

Exit:

```text
session containment tests pass
```

---

# 55. Repository structure

Recommended:

```text
/auth-broker
  /apps
    /broker
    /admin-web
    /ios-approval

  /packages
    /protocol
    /policy
    /state-machine
    /audit
    /crypto
    /adapter-sdk
    /secret-provider-sdk

  /services
    /secret-service
    /browser-worker
    /classifier

  /adapters
    /synthetic-login
    /github

  /tests
    /unit
    /integration
    /adversarial
    /concurrency
    /browser
    /protocol
```

---

# 56. Engineering invariants

Treat these as non-negotiable invariants.

### Invariant 1

No agent-facing tool returns a secret.

### Invariant 2

No credential can be released without a currently valid authorization path.

### Invariant 3

An approval authorizes exactly one immutable request revision.

### Invariant 4

A secret permit can be consumed at most once.

### Invariant 5

Authentication success must be independently verified by the adapter.

### Invariant 6

`OUTCOME_UNKNOWN` never automatically becomes retry.

### Invariant 7

The agent cannot modify its own security policy.

### Invariant 8

The agent cannot approve its own request.

### Invariant 9

The agent cannot access reusable authenticated browser state.

### Invariant 10

Authentication approval does not imply unrestricted post-login authorization.

### Invariant 11

Safe mode never executes without human approval.

### Invariant 12

Auto executes only under an existing explicit delegation.

### Invariant 13

No unsupported environment silently falls back to plaintext credential entry.

---

# 57. Definition of done for v1

Version 1 is complete when a real workflow can perform:

```text
Codex
  ↓
auth.request
  ↓
broker validates GitHub authentication request
  ↓
iPhone receives approval request
  ↓
user reviews exact context
  ↓
Face ID
  ↓
device signs immutable approval
  ↓
broker validates signature
  ↓
protected worker receives one-use password permit
  ↓
password injected
  ↓
protected worker receives one-use TOTP permit
  ↓
TOTP generated and injected
  ↓
adapter verifies expected GitHub account
  ↓
broker creates restricted authenticated session
  ↓
Codex receives opaque session_ref
  ↓
Codex performs only permitted operations
```

At no point may Codex receive:

```text
password
TOTP
TOTP seed
cookies
authorization headers
browser storage
approval private key
Face ID information
```

The same workflow must work under:

```text
Manual
Safe
Auto
```

with the mode semantics defined above.

The security release gate must pass using synthetic credentials before any production account is enrolled.
