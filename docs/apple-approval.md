# Native Apple approval app

`apps/ios-approval` contains a Swift 6 / SwiftUI iOS 17+ application and an XcodeGen project. The checked-in Xcode project opens directly in Xcode. Cheng Chun Liu's development team is selected per the owner's instruction. The physical iPhone pairing, separate owner confirmation, and synthetic signed-approval/login/profile-read/session-end happy path passed; the remaining physical and production gates are recorded in [implementation status](implementation-status.md). Regenerate the project with `xcodegen generate` from that directory after changing `project.yml`.

The app implements foreground polling, exact-payload review, one-use device pairing, biometric key signing, explicit denial, and local pairing erasure. Production biometric assurance remains gated on the complete physical-device checklist below. Simulator builds and protocol unit tests provide no evidence for Face ID or Secure Enclave enforcement.

## Prepared onboarding and simpler screens

Run `npm run onboard -- --iphone` from the repository. Follow [agent.md](../agent.md) for owner-authorized automation. The helper reuses the Docker/CA/signing setup, updates the same app in place, reads a fresh public enrollment receipt from the selected phone, and matches its exact device ID and complete approval-key fingerprint against the owner overview. An existing matching ACTIVE phone needs no new pairing; a matching pending phone needs separate owner confirmation.

For an unpaired phone, the helper transfers a private short-lived draft into the app's data container. The app accepts only a bounded, versioned, flat JSON file with HTTPS origin, whole-leaf SHA-256 pin, expiry and optional one-use pairing code. Duplicate/unknown fields, symlinks, invalid values and expired imports are rejected; the file is consumed once. Imported values remain unverified, the code remains masked, and importing never creates a key, enrolls or signs. The explicit verification control starts unchecked. The public receipt is navigation metadata, not attestation; it contains no bearer, key tag, private key or biometric assertion.

Pairing now shows two short steps, with manual connection fields under Details. After pairing, the home screen shows Ready and current requests; device IDs and full public fingerprints live in Device details. Request review shows a short summary and a fixed Approve with biometrics button, while every exact signed field remains available in the full context disclosure. The separate web console shows current requests first, with history and settings collapsed by default. Physical trust/passcode/biometric actions remain owner-controlled.

## Owner-controlled enrollment

1. Configure an HTTPS reverse proxy for the broker. The certificate must pass normal iOS system trust and hostname validation. For a private CA, provision its trust independently using owner-controlled device administration. The app does not bypass trust for a pinned self-signed certificate.
2. In the owner administration interface, create a one-use pairing challenge. Obtain the broker origin, its TLS leaf certificate SHA-256 fingerprint, and the pairing code through an owner-controlled channel outside the agent environment.
3. On the iPhone, enter those values, confirm that you verified the fingerprint, and enroll. Only an HTTPS origin is accepted; all redirects are rejected. Pin mismatch, expired/untrusted certificates, unavailable biometrics, a missing passcode, or unavailable Secure Enclave fail closed.
4. The app creates a permanent P-256 Secure Enclave key. Its access control is `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` with `.privateKeyUsage` and `.biometryCurrentSet`. There is no software-key or passcode-only fallback.
5. The public key is sent as RFC 5480 SubjectPublicKeyInfo PEM. The broker registers a pending device and issues a device-scoped bearer token. The token and enrollment configuration remain in the nonsynchronizing device-bound Keychain. The app never receives or stores an owner administration token.
6. Compare the SHA-256 fingerprint of the SPKI DER public key displayed in the app with the pending device in the owner administration interface, then confirm it separately. Pending devices cannot fetch usable challenges or authorize requests. Device signing is not a substitute for this owner confirmation.

Certificate rotation requires explicitly re-pairing with an independently verified new fingerprint. Erasing local pairing deletes the key and token; it does not revoke the corresponding server record. Revoke that record using owner administration. An enrollment response lost in transit may leave a pending server record; revoke it before creating another pairing challenge.

## Local HTTPS device-test ceremony

The local test setup uses the Mac at `192.168.68.57` and its mDNS hostname `yujamac.local`; verify the active LAN address and local hostname when starting each run. Prefer `https://yujamac.local:<TLS-port>` as the native broker origin. Caddy's leaf certificate must contain that exact DNS name; an IP-address origin additionally requires an IP SAN and may be blocked by iOS 17+ ATS IP-resource policy. The app retains ATS protections and uses no arbitrary-load or insecure HTTP exception. [Apple ATS local-network policy](https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking).

Host preparation:

1. The Docker preparation helper creates an OpenSSL development CA and multi-SAN leaf, then configures Caddy to serve that fixed certificate. Reverse-proxy only the required private owner/device listener, preserve the exact Host header, and include the current hostname in `BROKER_ALLOWED_HOSTNAMES`. MCP and owner-console plaintext listeners remain loopback-only; PostgreSQL has no host port. Keep Caddy administration, synthetic browser state and the Docker control socket private. The current development host is not proof of production agent isolation.
2. Use only `.local/tls/root.crt` as the **public root certificate**. Never export `.local/tls/ca.key`, `.local/tls/server.key`, credential configuration or device tokens. The helper validates the served chain/hostname and computes SHA-256 of the actual leaf DER for the native pin. Read the current public values from `npm run onboard -- --status`; historical hashes are not setup inputs.
3. Package the public root for owner review:

```sh
python3 apps/ios-approval/tools/create-root-profile.py \
  /owner-controlled/path/root.crt .local/tls/boring-login-local-root.mobileconfig
```

The helper rejects private-key PEM, non-CA certificates, intermediates, and expired roots, and emits only a public-certificate profile, `.cer`, and root SHA-256. The `.mobileconfig` contains one `com.apple.security.root` payload; it does not enroll MDM, configure a VPN, contain a private key, or install itself. [Apple root-certificate payload](https://developer.apple.com/documentation/devicemanagement/certificateroot).

4. Present the exact root profile and root SHA-256 to the owner through the existing trusted channel. Enabling this development CA changes the phone's system-wide certificate trust; the owner must review and install this exact profile. Transfer the public profile using an owner-controlled local channel and open it on the phone. Install through Settings > General > VPN & Device Management (or Profile Downloaded), then enable SSL trust at Settings > General > About > Certificate Trust Settings > Enable Full Trust for Root Certificates. A manually installed profile alone does not confer SSL trust. The owner enters the device passcode directly; never request or retrieve it. [Apple manual trust instructions](https://support.apple.com/en-us/102390).
5. Open Broker Approval on the same reachable Wi-Fi network. The prepared draft fills the named HTTPS origin and leaf SHA-256; manual entry remains available under Details. Tap **Check HTTPS connection** to exercise system trust, the entered leaf pin, DNS, and local-network permission without generating a key, enrolling, submitting approval, or attesting owner verification. This read-only preflight requires valid inputs and does not require the owner-verification checkbox. Allow the Local Network prompt; a denial can be corrected under Settings > Privacy & Security > Local Network > Broker Approval. `waitsForConnectivity` supports that initial permission decision without implementing an approval retry. Before pairing, independently verify the exact origin and pin, then explicitly check the verification control. It starts unchecked, is disabled until the origin and pin are valid, and resets whenever either value changes. [Apple local-network privacy](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy).
6. Obtain a fresh owner-created five-minute pairing code. **Stop iPhone Mirroring and use the physical iPhone** to create its strict biometric key and finish enrollment. Reopen mirroring afterward for review if useful. Compare the app's public-key fingerprint to the pending device record and obtain separate owner confirmation. Trigger only synthetic broker requests, verify complete signed context, and perform every biometric Approve action on the physical phone.

Strict `deviceOwnerAuthenticationWithBiometrics` fails during iPhone Mirroring because the phone's biometric sensors are unavailable. Apple offers a companion policy for Mac/Watch authentication, but this app deliberately retains the specified iPhone-only biometric key policy. Mirroring may help with certificate settings, fields, transport preflight, and review; it is not physical Face ID evidence. [Apple Mirroring authentication guidance](https://developer.apple.com/documentation/technotes/tn3210-optimizing-your-app-for-iphone-mirroring).

Safe diagnostics distinguish untrusted/expired/hostname-invalid TLS, a mismatched pin, DNS failure, and network reachability without exposing exception bodies, response bodies, tokens, or authentication headers. TLS diagnostics are isolated per request; every request starts a new pinned session. A connection preflight cannot approve, enroll, or prove that authentication succeeded.

Keep the same fixed leaf throughout the test ceremony. The current OpenSSL helper creates a 30-day root and seven-day leaf and preserves existing keys/certificates on rerun; Caddy does not use its automatic internal issuer here. Expired or partial TLS state stops setup for review. Certificate renewal changes the whole-leaf pin and requires an independently verified new fingerprint and explicit re-pairing. Do not weaken pinning or silently regenerate trust. Remove the development device/root only when the owner actually requests that cleanup.

## HTTP device protocol

The broker/reverse proxy must present the same verified TLS leaf certificate for these routes. Enforce device token scope, device state, expiry, revocation, rate limits, and atomic one-use approval consumption on the server.

`POST /device/enroll` (one-use pairing code, no bearer):

```json
{
  "pairing_code": "owner-generated-one-use-code",
  "device_name": "My iPhone",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "key_algorithm": "P256_SHA256_DER",
  "assurance_profile": "OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE"
}
```

Response:

```json
{
  "device_id": "device_1",
  "owner_id": "owner_1",
  "broker_id": "broker_home",
  "device_token": "device-scoped-token",
  "status": "PENDING_CONFIRMATION"
}
```

`GET /device/challenges` with `Authorization: Bearer <device_token>`:

```json
{
  "status": "ACTIVE",
  "challenges": [
    {
      "challenge_id": "challenge_1",
      "payload_base64": "canonical-UTF8-JSON-bytes-as-base64",
      "payload_digest_sha256": "lowercase-hex-sha256-of-those-exact-bytes"
    }
  ]
}
```

Pending devices return `{"status":"PENDING_CONFIRMATION","challenges":[]}`. Revoked/unknown devices must receive an authorization failure. Polling occurs every five seconds only while the app is active. A transport, identity, decoding, or revocation failure clears displayed challenges.

`POST /device/approve` with the device bearer:

```json
{
  "challenge_id": "challenge_1",
  "device_id": "device_1",
  "signature": "base64-ASN.1-DER-ECDSA-signature"
}
```

`POST /device/deny` with the device bearer sends `{"challenge_id":"challenge_1","device_id":"device_1"}`. Denial needs no biometric authorization. A device bearer authenticates transport only; it can never replace the signature required for approval. Successful submission returns HTTP 2xx; the broker remains authoritative for authentication execution status.

## Signed bytes and display

Protocol v1 is canonical JSON in UTF-8: lexically sorted ASCII object keys, no whitespace, JSON.stringify-compatible escaping, and safe nonnegative integral version values (request/policy/binding revisions and runtime generation are positive). Dates are ISO 8601 strings. The app decodes strictly, checks the payload SHA-256, rejects missing, duplicate, and unknown keys, and verifies that the exact received bytes match the v1 canonical typed object. It retains and signs the original received bytes, never a separately assembled display object.

Required payload keys are the design's `version`, `action`, `broker_id`, `boot_epoch`, `owner_id`, `device_id`, `request_id`, `revision`, `nonce`, `issued_at`, `expires_at`, `client_id`, `workload_id`, `runtime_id`, `runtime_generation`, `account_id`, `credential_binding_version`, `destination`, `operation`, `adapter_id`, `adapter_version`, `factors`, `policy_id`, `policy_version`, `session_action_profile`, and `review_digest`, plus signed `purpose`, `client_display_name`, and `account_display_name`. The aliases appear beside their signed IDs. Purpose is explicitly labeled agent-stated untrusted text. Its `review_digest` is lowercase hex SHA-256 of canonical `{"purpose": <purpose>}` bytes.

The app checks action/version, broker/owner/device against local enrollment, destination validity, and issue/expiry dates. Normal destinations require HTTPS with no user information or fragment. For the broker's synthetic integration fixture only, signed destination metadata may be exactly `http://127.0.0.1:<explicit decimal port>` with optional trailing slash; ports must be 1–65535 and paths, query strings, fragments, user information, alternate loopback forms, and lookalike hosts are rejected. The review labels this a **Local synthetic target**. The phone never opens or connects to any destination URL; its broker transport remains strictly HTTPS, system-trusted, and pinned. The broker's accounts/adapters must continue to enforce the synthetic-only release gate.

Maximum payload lifetime is ten minutes; future issue time tolerance is thirty seconds. The broker must enforce its own authoritative time and all authorization bindings regardless of these client checks. All material fields, including the complete destination URL, are visible without ellipsis in the review screen.

Every Approve tap creates a **new** `LAContext`, sets biometric authentication reuse duration to zero, disables passcode fallback, and evaluates `deviceOwnerAuthenticationWithBiometrics`. Key lookup/signing use only that request's context, then invalidate it. The key signs the exact message using `ecdsaSignatureMessageX962SHA256`; wire signatures are ECDSA P-256 / SHA-256 in ASN.1 DER form. No reusable private key or biometric data leaves the device. The server verifies an enrolled key's signature, not Face ID independently. This local assurance is not remote device attestation.

An inactive scene covers both pairing and review screens to protect snapshots; the biometric prompt's transient inactivity does not itself cancel the prompt. Backgrounding invalidates the current authentication context, cancels the approval task and polling, and clears visible requests. A completion callback checks cancellation, active scene state, and time validity before transmitting the signature. Network loss after submission does not trigger an automatic retry. A request already transmitted cannot be retracted by backgrounding or transport cancellation; reconcile its status in the broker. The broker must atomically consume its nonce and reject stale/expired/revoked approvals.

## Push notification status

APNs is not provisioned or implemented in this development slice. No notification permission, push entitlement, APNs credential, or background push claim is included. The functional transport is foreground polling. To add APNs, provision a developer team, entitlement, device-token registration, and server delivery. Notifications must carry only an opaque request reference and generic lock-screen copy; opening one may navigate to review but must never invoke Approve or key signing. APNs delivery and real-device notification tests remain an explicit Phase 2 gate.

## Validation and release gate

Build (does not validate Secure Enclave):

```sh
cd apps/ios-approval
xcodegen generate
xcodebuild -project BrokerApproval.xcodeproj -scheme BrokerApproval \
  -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/boring-login-ios-derived CODE_SIGNING_ALLOWED=NO build
```

Protocol unit tests exercise exact-byte preservation, digest mismatch, wrong broker/owner/device, canonical encoding, duplicate/extra/missing keys, purpose-digest substitution, unsupported versions/actions/factors, invalid issue/expiry windows, Unicode escaping, and invalid broker origins/pins. A fixture generated by the broker's TypeScript canonical serializer checks Swift/TypeScript interoperability including Unicode and line-separator escaping. They never mock biometric success and never satisfy the physical-device gate.

On physical hardware with synthetic accounts and the HTTPS broker, record every result before introducing production credentials:

- Pair with correct trust and fingerprint; reject wrong pin, wrong hostname, untrusted/expired certificate, redirects, expired/reused pairing code, and an unconfirmed/revoked device.
- Confirm that Secure Enclave key generation succeeds, the public key is SPKI P-256, and the broker verifies the DER signature over the exact canonical UTF-8 bytes.
- Approve successfully; cancel biometrics; fail biometrics; attempt passcode fallback; remove passcode; lock the device during approval.
- Background during biometric evaluation, after success before signing, after signing before transmit, and during a network request. Verify that pre-transmission interruption authorizes nothing; reconcile submissions that may already have reached the broker.
- Change biometric enrollment and verify old key invalidation. Never silently regenerate a key for existing enrollment.
- Revoke the device while reviewing and while signing; replay serially and concurrently; mutate each security-relevant field; expire the challenge during the prompt. Broker rejection must be immediate and atomic.
- Approve two separate requests in succession and observe a fresh biometric prompt each time; reject concurrent signing actions and do not reuse a successful context.
- Drop the network after biometric approval and after submission; verify no implicit resend and correct authoritative broker state.
- Review complete destination strings, long IDs, Unicode purpose text, dynamic type, light/dark mode, and narrow devices. Check background snapshots for the privacy cover.
- Once APNs is added, verify generic notification contents and that opening a notification performs no approval.

Simulator approval must fail closed when Secure Enclave is unavailable. Compiling/installing the app is not a production release, a physical biometric pass, or confirmation of deployment isolation.
