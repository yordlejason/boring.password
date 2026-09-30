import CryptoKit
import Foundation

enum ApprovalError: LocalizedError, Sendable {
    case invalidBroker, invalidPayload, wrongIdentity, expired, unavailableBiometrics
    case unavailableKey, interrupted, serverRejected(Int), transport, pairingPending
    case certificateTrust, certificatePin, networkUnavailable, hostUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidBroker: "Enter an HTTPS broker origin and its verified 64-character certificate fingerprint."
        case .invalidPayload: "The broker challenge has an unsupported or invalid signed payload."
        case .wrongIdentity: "The challenge is for a different broker, owner, or device."
        case .expired: "This challenge expired or has an invalid time window. Refresh the request."
        case .unavailableBiometrics: "Strict biometric approval is unavailable. Use a physical device with biometrics enrolled and a passcode enabled."
        case .unavailableKey: "The protected signing key is unavailable or invalidated. Ask the owner to revoke this device, then enroll it again."
        case .interrupted: "Approval was interrupted. No further approval will be sent from this action."
        case .serverRejected(let status): "The broker rejected this operation (HTTP \(status)). Refresh or contact the owner."
        case .transport: "The broker connection failed or its identity could not be verified. Submitted approvals are never retried automatically; refresh broker state."
        case .certificateTrust: "The broker certificate is not trusted for this HTTPS host. Verify its hostname and dates, and install and explicitly trust the owner's local root certificate if required. Certificate checks remain enabled."
        case .certificatePin: "The broker certificate does not match the fingerprint you verified. Ask the owner to verify certificate rotation through an independent channel before pairing again."
        case .networkUnavailable: "The broker could not be reached. Check the broker service, this phone's network, and Settings > Privacy & Security > Local Network > Broker Approval. Submitted approvals are never retried automatically."
        case .hostUnavailable: "The broker hostname could not be resolved. Check the exact owner-provided hostname, local network permission, and that the broker is reachable on this network."
        case .pairingPending: "The owner must confirm this device separately in the broker administration interface."
        }
    }
}

struct Enrollment: Codable, Sendable {
    let brokerURL: URL
    let certificateFingerprint: String
    let keyTag: String
    let brokerID: String
    let ownerID: String
    let deviceID: String
    let deviceToken: String
    let publicKeyFingerprint: String
}

struct ApprovalPayload: Decodable, Sendable {
    let version: Int
    let action: String
    let brokerID: String
    let bootEpoch: String
    let ownerID: String
    let deviceID: String
    let requestID: String
    let revision: Int
    let nonce: String
    let issuedAt: String
    let expiresAt: String
    let clientID: String
    let clientDisplayName: String
    let workloadID: String
    let runtimeID: String
    let runtimeGeneration: Int
    let accountID: String
    let accountDisplayName: String
    let credentialBindingVersion: Int
    let destination: String
    let operation: String
    let adapterID: String
    let adapterVersion: String
    let factors: [String]
    let policyID: String
    let policyVersion: Int
    let sessionActionProfile: String
    let purpose: String
    let reviewDigest: String

    enum CodingKeys: String, CodingKey, CaseIterable {
        case version, action, nonce, revision, destination, operation, factors, purpose
        case brokerID = "broker_id", bootEpoch = "boot_epoch", ownerID = "owner_id"
        case deviceID = "device_id", requestID = "request_id", issuedAt = "issued_at"
        case expiresAt = "expires_at", clientID = "client_id", clientDisplayName = "client_display_name"
        case workloadID = "workload_id", runtimeID = "runtime_id", runtimeGeneration = "runtime_generation"
        case accountID = "account_id", accountDisplayName = "account_display_name"
        case credentialBindingVersion = "credential_binding_version", adapterID = "adapter_id"
        case adapterVersion = "adapter_version", policyID = "policy_id", policyVersion = "policy_version"
        case sessionActionProfile = "session_action_profile", reviewDigest = "review_digest"
    }

    var canonicalBytes: Data {
        let q = CanonicalJSON.quote
        let fields: [String: String] = [
            "version": String(version), "action": q(action), "broker_id": q(brokerID),
            "boot_epoch": q(bootEpoch), "owner_id": q(ownerID), "device_id": q(deviceID),
            "request_id": q(requestID), "revision": String(revision), "nonce": q(nonce),
            "issued_at": q(issuedAt), "expires_at": q(expiresAt), "client_id": q(clientID),
            "client_display_name": q(clientDisplayName), "workload_id": q(workloadID),
            "runtime_id": q(runtimeID), "runtime_generation": String(runtimeGeneration),
            "account_id": q(accountID), "account_display_name": q(accountDisplayName),
            "credential_binding_version": String(credentialBindingVersion), "destination": q(destination),
            "operation": q(operation), "adapter_id": q(adapterID), "adapter_version": q(adapterVersion),
            "factors": "[" + factors.map(q).joined(separator: ",") + "]", "policy_id": q(policyID),
            "policy_version": String(policyVersion), "session_action_profile": q(sessionActionProfile),
            "purpose": q(purpose), "review_digest": q(reviewDigest)
        ]
        return Data(CanonicalJSON.object(fields).utf8)
    }

    var isLocalSyntheticDestination: Bool { Self.isLocalSyntheticDestination(destination) }

    static func isLocalSyntheticDestination(_ destination: String) -> Bool {
        // Signed metadata only; this app never opens or connects to the target URL.
        guard destination.range(of: #"^http://127\.0\.0\.1:[1-9][0-9]{0,4}/?$"#, options: .regularExpression) != nil,
              let url = URLComponents(string: destination), url.scheme == "http", url.host == "127.0.0.1",
              let port = url.port, (1...65_535).contains(port), ["", "/"].contains(url.path),
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else { return false }
        return true
    }

    func validate(enrollment: Enrollment, now: Date = Date()) throws {
        guard version == 1, action == "authorize_authentication" else { throw ApprovalError.invalidPayload }
        guard brokerID == enrollment.brokerID, ownerID == enrollment.ownerID,
              deviceID == enrollment.deviceID else { throw ApprovalError.wrongIdentity }
        let numbers = [revision, runtimeGeneration, credentialBindingVersion, policyVersion]
        guard numbers.allSatisfy({ $0 > 0 && $0 <= 9_007_199_254_740_991 }) else { throw ApprovalError.invalidPayload }
        let identifiers = [brokerID, bootEpoch, ownerID, deviceID, requestID, nonce, clientID,
                           workloadID, runtimeID, accountID, operation, adapterID, adapterVersion,
                           policyID, sessionActionProfile, accountDisplayName, clientDisplayName]
        guard identifiers.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 512 && !$0.unicodeScalars.contains(where: { [.control, .format].contains($0.properties.generalCategory) }) }),
              purpose.utf8.count <= 8_192, !factors.isEmpty, factors.count <= 8,
              Set(factors).count == factors.count,
              factors.allSatisfy({ ["password", "totp", "oauth", "passkey", "security_key"].contains($0) }),
              let url = URLComponents(string: destination),
              url.scheme == "https" || isLocalSyntheticDestination,
              let host = url.host, !host.isEmpty, url.user == nil, url.password == nil,
              url.fragment == nil, destination.utf8.count <= 2_048,
              !destination.unicodeScalars.contains(where: { [.control, .format].contains($0.properties.generalCategory) })
        else { throw ApprovalError.invalidPayload }
        guard let issued = Self.date(issuedAt), let expires = Self.date(expiresAt),
              expires > now, expires > issued, expires.timeIntervalSince(issued) <= 600,
              issued.timeIntervalSince(now) <= 30, now.timeIntervalSince(issued) <= 600
        else { throw ApprovalError.expired }
        let purposeBytes = Data(CanonicalJSON.object(["purpose": CanonicalJSON.quote(purpose)]).utf8)
        guard reviewDigest == Self.sha256(purposeBytes) else { throw ApprovalError.invalidPayload }
    }

    static func date(_ value: String) -> Date? {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fractional.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    }

    static func sha256(_ value: Data) -> String {
        SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined()
    }
}

enum CanonicalJSON {
    // Protocol v1 uses lexically sorted ASCII keys and JSON.stringify-compatible strings.
    // Requiring these exact bytes also rejects duplicate keys and alternate encodings.
    static func object(_ fields: [String: String]) -> String {
        "{" + fields.keys.sorted().map { quote($0) + ":" + fields[$0]! }.joined(separator: ",") + "}"
    }

    static func quote(_ text: String) -> String {
        var result = "\""
        for scalar in text.unicodeScalars {
            switch scalar.value {
            case 0x22: result += "\\\""
            case 0x5c: result += "\\\\"
            case 0x08: result += "\\b"
            case 0x09: result += "\\t"
            case 0x0a: result += "\\n"
            case 0x0c: result += "\\f"
            case 0x0d: result += "\\r"
            case 0..<0x20: result += String(format: "\\u%04x", scalar.value)
            default: result.unicodeScalars.append(scalar)
            }
        }
        return result + "\""
    }
}

struct WireChallenge: Decodable, Sendable {
    let challengeID: String
    let payloadBase64: String
    let payloadDigestSHA256: String
    enum CodingKeys: String, CodingKey {
        case challengeID = "challenge_id", payloadBase64 = "payload_base64"
        case payloadDigestSHA256 = "payload_digest_sha256"
    }
}

struct ReviewedChallenge: Identifiable, Sendable {
    let id: String
    let bytes: Data
    let payload: ApprovalPayload
    let digest: String

    init(wire: WireChallenge, enrollment: Enrollment, now: Date = Date()) throws {
        guard !wire.challengeID.isEmpty, wire.challengeID.utf8.count <= 512,
              wire.payloadBase64.utf8.count <= 32_768,
              let data = Data(base64Encoded: wire.payloadBase64), data.count <= 24_576,
              String(data: data, encoding: .utf8) != nil,
              wire.payloadDigestSHA256 == ApprovalPayload.sha256(data)
        else { throw ApprovalError.invalidPayload }
        let payload: ApprovalPayload
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys) == Set(ApprovalPayload.CodingKeys.allCases.map(\.rawValue))
            else { throw ApprovalError.invalidPayload }
            payload = try JSONDecoder().decode(ApprovalPayload.self, from: data)
        } catch { throw ApprovalError.invalidPayload }
        guard payload.canonicalBytes == data else { throw ApprovalError.invalidPayload }
        try payload.validate(enrollment: enrollment, now: now)
        id = wire.challengeID
        bytes = data
        self.payload = payload
        digest = wire.payloadDigestSHA256
    }
}
