import Foundation
import XCTest
@testable import BrokerApproval

final class ApprovalPayloadTests: XCTestCase {
    private let now = ApprovalPayload.date("2026-09-30T00:00:10.000Z")!
    private let enrollment = Enrollment(brokerURL: URL(string: "https://broker.example")!,
                                        certificateFingerprint: String(repeating: "a", count: 64),
                                        keyTag: "test-only-unused-key", brokerID: "broker_home", ownerID: "owner_1",
                                        deviceID: "device_1", deviceToken: "synthetic-not-a-real-token",
                                        publicKeyFingerprint: "synthetic-unused-fingerprint")

    private func fields(purpose: String = "Read the requested repository.") -> [String: Any] {
        let review = Data(CanonicalJSON.object(["purpose": CanonicalJSON.quote(purpose)]).utf8)
        return [
            "version": 1, "action": "authorize_authentication", "broker_id": "broker_home",
            "boot_epoch": "boot_1", "owner_id": "owner_1", "device_id": "device_1",
            "request_id": "req_1", "revision": 1, "nonce": String(repeating: "b", count: 64),
            "issued_at": "2026-09-30T00:00:00.000Z", "expires_at": "2026-09-30T00:01:00.000Z",
            "client_id": "client_1", "client_display_name": "Codex synthetic",
            "workload_id": "workload_1", "runtime_id": "runtime_1", "runtime_generation": 1,
            "account_id": "account_1", "account_display_name": "Synthetic account",
            "credential_binding_version": 1, "destination": "https://synthetic.example",
            "operation": "sign_in", "adapter_id": "synthetic_login", "adapter_version": "1.0.0",
            "factors": ["password", "totp"], "policy_id": "policy_1", "policy_version": 1,
            "session_action_profile": "synthetic.read", "purpose": purpose,
            "review_digest": ApprovalPayload.sha256(review)
        ]
    }

    private func wire(_ fields: [String: Any]) throws -> WireChallenge {
        let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes])
        return WireChallenge(challengeID: "challenge_1", payloadBase64: data.base64EncodedString(),
                             payloadDigestSHA256: ApprovalPayload.sha256(data))
    }

    func testExactCanonicalMessageIsRetained() throws {
        let transport = try wire(fields())
        let challenge = try ReviewedChallenge(wire: transport, enrollment: enrollment, now: now)
        XCTAssertEqual(challenge.bytes, Data(base64Encoded: transport.payloadBase64))
        XCTAssertEqual(challenge.payload.destination, "https://synthetic.example")
        XCTAssertEqual(challenge.payload.canonicalBytes, challenge.bytes)
    }

    func testTypeScriptCanonicalProtocolFixture() throws {
        let url = try XCTUnwrap(Bundle(for: Self.self).url(forResource: "canonical-v1", withExtension: "json"))
        let transport = try JSONDecoder().decode(WireChallenge.self, from: Data(contentsOf: url))
        let challenge = try ReviewedChallenge(wire: transport, enrollment: enrollment, now: now)
        XCTAssertEqual(challenge.bytes, Data(base64Encoded: transport.payloadBase64))
        XCTAssertTrue(challenge.payload.purpose.contains("한글"))
        XCTAssertTrue(challenge.payload.purpose.contains("\u{2028}"))
    }

    func testBrokerOwnerAndDeviceCannotBeSubstituted() throws {
        for key in ["broker_id", "owner_id", "device_id"] {
            var payload = fields()
            payload[key] = "somebody_else"
            XCTAssertThrowsError(try ReviewedChallenge(wire: wire(payload), enrollment: enrollment, now: now))
        }
    }

    func testVersionActionAndUnsupportedFactorsAreRejected() throws {
        for (key, value) in [("version", 2 as Any), ("action", "enable_auto" as Any),
                             ("factors", ["unknown_factor"] as Any)] {
            var payload = fields()
            payload[key] = value
            XCTAssertThrowsError(try ReviewedChallenge(wire: wire(payload), enrollment: enrollment, now: now))
        }
    }

    func testMissingAndUnsignedExtraFieldsAreRejected() throws {
        var missing = fields()
        missing.removeValue(forKey: "purpose")
        XCTAssertThrowsError(try ReviewedChallenge(wire: wire(missing), enrollment: enrollment, now: now))
        var extra = fields()
        extra["display_destination"] = "https://different.example"
        XCTAssertThrowsError(try ReviewedChallenge(wire: wire(extra), enrollment: enrollment, now: now))
    }

    func testDuplicateKeysAndNoncanonicalWhitespaceAreRejected() throws {
        let original = try wire(fields())
        let canonical = String(data: Data(base64Encoded: original.payloadBase64)!, encoding: .utf8)!
        for text in ["{\"version\":1," + canonical.dropFirst(), " " + canonical] {
            let bytes = Data(text.utf8)
            let changed = WireChallenge(challengeID: "challenge_1", payloadBase64: bytes.base64EncodedString(),
                                        payloadDigestSHA256: ApprovalPayload.sha256(bytes))
            XCTAssertThrowsError(try ReviewedChallenge(wire: changed, enrollment: enrollment, now: now))
        }
    }

    func testExpiredFutureAndExcessiveLifetimeAreRejected() throws {
        for (key, value) in [("expires_at", "2026-09-30T00:00:05.000Z"),
                             ("issued_at", "2026-09-30T00:00:45.000Z"),
                             ("expires_at", "2026-09-30T00:20:00.000Z")] {
            var payload = fields()
            payload[key] = value
            XCTAssertThrowsError(try ReviewedChallenge(wire: wire(payload), enrollment: enrollment, now: now))
        }
    }

    func testChangedPurposeMustMatchItsSignedReviewDigest() throws {
        var payload = fields()
        payload["purpose"] = "An unrelated request."
        XCTAssertThrowsError(try ReviewedChallenge(wire: wire(payload), enrollment: enrollment, now: now))
    }

    func testDigestMismatchIsRejected() throws {
        let transport = try wire(fields())
        let changed = WireChallenge(challengeID: transport.challengeID, payloadBase64: transport.payloadBase64,
                                    payloadDigestSHA256: String(repeating: "0", count: 64))
        XCTAssertThrowsError(try ReviewedChallenge(wire: changed, enrollment: enrollment, now: now))
    }

    func testExactLoopbackOriginIsAcceptedOnlyAsSignedSyntheticMetadata() throws {
        for destination in ["http://127.0.0.1:12345", "http://127.0.0.1:12345/"] {
            var payload = fields()
            payload["destination"] = destination
            let challenge = try ReviewedChallenge(wire: wire(payload), enrollment: enrollment, now: now)
            XCTAssertTrue(challenge.payload.isLocalSyntheticDestination)
            XCTAssertEqual(challenge.payload.destination, destination)
        }
    }

    func testPlainHTTPRemoteLookalikeAndExpandedLoopbackTargetsAreRejected() throws {
        let invalid = ["http://remote.example:1234", "http://127.0.0.1.evil:1234", "http://localhost:1234",
                       "http://2130706433:1234", "http://127.0.0.1", "http://127.0.0.1:0",
                       "http://127.0.0.1:65536", "http://127.0.0.1:01234", "http://127.0.0.1:1234/login",
                       "http://127.0.0.1:1234/?foo=bar", "http://127.0.0.1:1234/#foo",
                       "http://user:pass@127.0.0.1:1234"]
        for destination in invalid {
            var payload = fields()
            payload["destination"] = destination
            XCTAssertThrowsError(try ReviewedChallenge(wire: wire(payload), enrollment: enrollment, now: now), destination)
        }
    }

    func testUnicodeAndJSONStringEscapesRoundTripWithoutReserialization() throws {
        let purpose = "한글 / emoji 👋\n\"quoted\"\\value\t\u{08}\u{0c}"
        let challenge = try ReviewedChallenge(wire: wire(fields(purpose: purpose)), enrollment: enrollment, now: now)
        XCTAssertEqual(challenge.payload.purpose, purpose)
        XCTAssertEqual(challenge.bytes, challenge.payload.canonicalBytes)
    }

    func testInsecureBrokerAndUnverifiedPinShapesAreRejected() {
        for origin in ["http://broker.example", "https://user:pass@broker.example", "https://broker.example/path",
                       "https://broker.example?token=value", "https://broker.example/#fragment"] {
            XCTAssertThrowsError(try BrokerClient(origin: URL(string: origin)!, fingerprint: String(repeating: "a", count: 64)))
        }
        XCTAssertThrowsError(try BrokerClient(origin: URL(string: "https://broker.example")!, fingerprint: "invalid"))
    }

    func testTransportDiagnosticsNeverReturnUnderlyingErrorContents() {
        let cases: [(URLError.Code, String)] = [
            (.serverCertificateUntrusted, ApprovalError.certificateTrust.localizedDescription),
            (.serverCertificateHasUnknownRoot, ApprovalError.certificateTrust.localizedDescription),
            (.cannotFindHost, ApprovalError.hostUnavailable.localizedDescription),
            (.notConnectedToInternet, ApprovalError.networkUnavailable.localizedDescription),
            (.timedOut, ApprovalError.networkUnavailable.localizedDescription)
        ]
        for (code, expected) in cases {
            let error = URLError(code, userInfo: [NSLocalizedDescriptionKey: "sensitive-underlying-debug-body"])
            let safe = BrokerClient.safeTransportError(error).localizedDescription
            XCTAssertEqual(safe, expected)
            XCTAssertFalse(safe.contains("sensitive-underlying-debug-body"))
        }
    }

    #if targetEnvironment(simulator)
    @MainActor
    func testSimulatorCannotCreateADeviceApprovalKey() {
        let tag = "login.boring.synthetic-test." + UUID().uuidString
        XCTAssertThrowsError(try DeviceSigner().makeKey(tag: tag))
        try? DeviceSigner.eraseKey(tag: tag)
    }
    #endif
}
