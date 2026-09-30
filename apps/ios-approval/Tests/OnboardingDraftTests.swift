import Foundation
import XCTest
@testable import BrokerApproval

final class OnboardingDraftTests: XCTestCase {
    private let now = ApprovalPayload.date("2026-09-30T00:00:00.000Z")!
    private let pin = String(repeating: "a", count: 64)
    private let syntheticCode = String(repeating: "A", count: 43)

    private func fields() -> [String: Any] {
        ["version": 1, "broker_url": "https://broker.example:8443",
         "certificate_sha256": pin, "pairing_code": syntheticCode,
         "expires_at": "2026-09-30T00:05:00.000Z"]
    }

    private func bytes(_ fields: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
    }

    func testValidPacketProducesOnlyUnverifiedFields() throws {
        let draft = try PairingSetupDraft.parse(data: bytes(fields()), now: now)
        XCTAssertEqual(draft.brokerURL, "https://broker.example:8443")
        XCTAssertEqual(draft.certificateFingerprint, pin)
        XCTAssertEqual(draft.pairingCode, syntheticCode)
        XCTAssertEqual(draft.expiresAt, now.addingTimeInterval(300))
    }

    func testMissingCodeProducesEmptyDraftCode() throws {
        var input = fields()
        input.removeValue(forKey: "pairing_code")
        XCTAssertEqual(try PairingSetupDraft.parse(data: bytes(input), now: now).pairingCode, "")
    }

    func testMissingUnknownAndSensitiveFieldsAreRejected() throws {
        for key in ["version", "broker_url", "certificate_sha256", "expires_at"] {
            var input = fields()
            input.removeValue(forKey: key)
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
        for key in ["unknown", "owner_token", "device_token", "verified", "confirm_device"] {
            var input = fields()
            input[key] = "synthetic-unused-value"
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
    }

    func testVersionMustBeLiteralIntegerOne() throws {
        for value in [true as Any, false as Any, 0 as Any, 2 as Any, 1.5 as Any, "1" as Any, NSNull()] {
            var input = fields()
            input["version"] = value
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
        let valid = String(data: try bytes(fields()), encoding: .utf8)!
        for alternate in ["1.0", "1e0", "+1", "01"] {
            let changed = valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":\(alternate)")
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: Data(changed.utf8), now: now))
        }
    }

    func testOriginRequiresExistingStrictHTTPSClientRules() throws {
        for origin in ["http://broker.example", "https://user:pass@broker.example", "https://broker.example/path",
                       "https://broker.example?code=value", "https://broker.example/#fragment",
                       "https://", " https://broker.example", "https://broker.example\n"] {
            var input = fields()
            input["broker_url"] = origin
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
    }

    func testPinAndOptionalCodeMustHaveExactTypesAndShapes() throws {
        for value in [String(repeating: "A", count: 64) as Any, String(repeating: "a", count: 63) as Any,
                      String(repeating: "g", count: 64) as Any, 1 as Any, NSNull()] {
            var input = fields()
            input["certificate_sha256"] = value
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
        for value in ["" as Any, String(repeating: "A", count: 42) as Any,
                      String(repeating: "A", count: 44) as Any, String(repeating: "+", count: 43) as Any,
                      String(repeating: "가", count: 43) as Any, true as Any, NSNull()] {
            var input = fields()
            input["pairing_code"] = value
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
        var input = fields()
        input["pairing_code"] = String(repeating: "_", count: 42) + "-"
        XCTAssertNoThrow(try PairingSetupDraft.parse(data: bytes(input), now: now))
    }

    func testExpiryIsFutureAndAtMostTenMinutes() throws {
        for value in ["2026-09-29T23:59:59Z" as Any, "2026-09-30T00:00:00.000Z" as Any,
                      "2026-09-30T00:10:00.001Z" as Any, "2026-09-30" as Any,
                      "2026-09-30T00:05:00Zjunk" as Any, "2026-09-30T00:05:00Z\n" as Any,
                      1 as Any, NSNull()] {
            var input = fields()
            input["expires_at"] = value
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
        for value in ["2026-09-30T00:10:00.000Z", "2026-09-30T09:05:00+09:00"] {
            var input = fields()
            input["expires_at"] = value
            XCTAssertNoThrow(try PairingSetupDraft.parse(data: bytes(input), now: now))
        }
    }

    func testMalformedDuplicateNestedAndOversizedPacketsAreRejected() throws {
        let valid = String(data: try bytes(fields()), encoding: .utf8)!
        for text in ["", "[]", "null", "{", valid + "{}", valid + "trailing",
                     "{\"version\":1," + valid.dropFirst(),
                     "{\"vers\\u0069on\":1," + valid.dropFirst(),
                     valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":{\"value\":1}"),
                     valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":[1]"),
                     String(repeating: " ", count: 4_097)] {
            XCTAssertThrowsError(try PairingSetupDraft.parse(data: Data(text.utf8), now: now))
        }
        XCTAssertThrowsError(try PairingSetupDraft.parse(data: Data([0xff, 0xfe]), now: now))
    }

    func testValidAndInvalidFilesAreConsumedOnce() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-onboarding.json")
        XCTAssertNil(try PairingSetupDraft.consume(at: file, now: now))
        try bytes(fields()).write(to: file)
        XCTAssertNotNil(try PairingSetupDraft.consume(at: file, now: now))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertNil(try PairingSetupDraft.consume(at: file, now: now))
        for data in [Data("invalid".utf8), Data(repeating: 65, count: 4_097)] {
            try data.write(to: file)
            XCTAssertThrowsError(try PairingSetupDraft.consume(at: file, now: now))
            XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
            XCTAssertNil(try PairingSetupDraft.consume(at: file, now: now))
        }
    }

    func testExactMaximumSizeAcceptedAndOneExtraByteRejected() throws {
        var data = try bytes(fields())
        data.append(Data(repeating: 32, count: 4_096 - data.count))
        XCTAssertNoThrow(try PairingSetupDraft.parse(data: data, now: now))
        data.append(32)
        XCTAssertThrowsError(try PairingSetupDraft.parse(data: data, now: now))
    }

    func testConcurrentConsumersReturnTheDraftOnlyOnce() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-onboarding.json")
        try bytes(fields()).write(to: file)
        let instant = now
        let count = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    do { return try PairingSetupDraft.consume(at: file, now: instant) != nil }
                    catch { return false }
                }
            }
            var succeeded = 0
            for await accepted in group { if accepted { succeeded += 1 } }
            return succeeded
        }
        XCTAssertEqual(count, 1)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
    }

    func testSymlinkIsRemovedWithoutReadingOrRemovingItsTarget() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("preserved-target.json")
        let file = directory.appendingPathComponent("boring-login-onboarding.json")
        let contents = try bytes(fields())
        try contents.write(to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        XCTAssertThrowsError(try PairingSetupDraft.consume(at: file, now: now))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertEqual(try Data(contentsOf: target), contents)
    }

    func testDirectoryIsRejectedWithoutRecursiveDeletion() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-onboarding.json")
        try FileManager.default.createDirectory(at: file, withIntermediateDirectories: false)
        let preserved = file.appendingPathComponent("preserved")
        try Data("synthetic-test".utf8).write(to: preserved)
        XCTAssertThrowsError(try PairingSetupDraft.consume(at: file, now: now))
        XCTAssertTrue(FileManager.default.fileExists(atPath: preserved.path))
    }

    func testErrorsExposeOnlyTypedSafeDescriptions() {
        for error in [OnboardingDraftError.invalidPacket, .invalidFile, .expired, .storageUnavailable,
                      .invalidReceipt, .receiptStorageUnavailable] {
            XCTAssertFalse(error.localizedDescription.contains(syntheticCode))
            XCTAssertFalse(error.localizedDescription.contains("broker.example"))
            XCTAssertFalse(error.localizedDescription.contains(pin))
        }
    }

    func testReceiptHasExactPublicPairedAllowlistAndFreshTime() throws {
        for unavailable in [false, true] {
            let data = try PairingSetupDraft.serializeEnrollmentReceipt(enrollment: receiptEnrollment(),
                                                                        unavailable: unavailable, now: now)
            let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(Set(fields.keys), Set(["version", "status", "written_at", "broker_url",
                                                  "certificate_sha256", "device_id", "approval_key_sha256"]))
            XCTAssertEqual(fields["version"] as? Int, 1)
            XCTAssertEqual(fields["status"] as? String, "PAIRED")
            XCTAssertEqual(fields["written_at"] as? String, "2026-09-30T00:00:00.000Z")
            XCTAssertEqual(fields["broker_url"] as? String, "https://broker.example:8443")
            XCTAssertEqual(fields["certificate_sha256"] as? String, pin)
            XCTAssertEqual(fields["device_id"] as? String, "device_synthetic")
            XCTAssertEqual(fields["approval_key_sha256"] as? String, String(repeating: "b", count: 64))
            let text = String(decoding: data, as: UTF8.self)
            for excluded in ["synthetic-do-not-export-token", "synthetic-do-not-export-keytag",
                             "owner_synthetic", "broker_synthetic", "deviceToken", "keyTag"] {
                XCTAssertFalse(text.contains(excluded))
            }
            XCTAssertLessThanOrEqual(data.count, 4_096)
        }
    }

    func testReceiptNilEnrollmentStatesOmitAllPairingFields() throws {
        for (unavailable, expected) in [(false, "UNPAIRED"), (true, "UNAVAILABLE")] {
            let data = try PairingSetupDraft.serializeEnrollmentReceipt(enrollment: nil, unavailable: unavailable, now: now)
            let fields = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
            XCTAssertEqual(Set(fields.keys), Set(["version", "status", "written_at"]))
            XCTAssertEqual(fields["status"] as? String, expected)
        }
    }

    func testReceiptInvalidPublicMetadataIsRejected() {
        for enrollment in [receiptEnrollment(origin: "http://broker.example"),
                           receiptEnrollment(origin: "https://broker.example/path"),
                           receiptEnrollment(certificate: String(repeating: "A", count: 64)),
                           receiptEnrollment(deviceID: "device/other"), receiptEnrollment(deviceID: ""),
                           receiptEnrollment(approvalFingerprint: String(repeating: "g", count: 64)),
                           receiptEnrollment(approvalFingerprint: String(repeating: "b", count: 63))] {
            XCTAssertThrowsError(try PairingSetupDraft.serializeEnrollmentReceipt(enrollment: enrollment,
                                                                                  unavailable: false, now: now))
        }
    }

    func testReceiptAtomicReplacementUsesFixedPathAndPrivatePermissions() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-enrollment.json")
        try PairingSetupDraft.writeEnrollmentReceipt(enrollment: receiptEnrollment(), unavailable: false,
                                                     in: directory, now: now)
        try PairingSetupDraft.writeEnrollmentReceipt(enrollment: nil, unavailable: true,
                                                     in: directory, now: now.addingTimeInterval(1))
        let expected = try PairingSetupDraft.serializeEnrollmentReceipt(enrollment: nil, unavailable: true,
                                                                        now: now.addingTimeInterval(1))
        XCTAssertEqual(try Data(contentsOf: file), expected)
        let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)
        XCTAssertEqual(mode.intValue & 0o777, 0o600)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["boring-login-enrollment.json"])
    }

    func testReceiptFailedSerializationRemovesStalePairedReceipt() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-enrollment.json")
        try PairingSetupDraft.writeEnrollmentReceipt(enrollment: receiptEnrollment(), unavailable: false,
                                                     in: directory, now: now)
        XCTAssertThrowsError(try PairingSetupDraft.writeEnrollmentReceipt(enrollment: receiptEnrollment(deviceID: ""),
                                                                         unavailable: false, in: directory, now: now))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
    }

    func testReceiptSymlinkRefusalRemovesLinkAndPreservesTarget() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-enrollment.json")
        let target = directory.appendingPathComponent("preserved-target")
        let original = Data("synthetic-preserved-content".utf8)
        try original.write(to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        XCTAssertThrowsError(try PairingSetupDraft.writeEnrollmentReceipt(enrollment: nil, unavailable: false,
                                                                         in: directory, now: now))
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        XCTAssertEqual(try Data(contentsOf: target), original)
    }

    func testReceiptUnsafeDirectoryAndDirectoryTargetAreNotFollowedOrRecursivelyRemoved() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let child = directory.appendingPathComponent("actual")
        try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
        let alias = directory.appendingPathComponent("alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: child)
        XCTAssertThrowsError(try PairingSetupDraft.writeEnrollmentReceipt(enrollment: nil, unavailable: false,
                                                                         in: alias, now: now))
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: child.path).isEmpty)
        let blocked = child.appendingPathComponent("boring-login-enrollment.json")
        try FileManager.default.createDirectory(at: blocked, withIntermediateDirectories: false)
        let preserved = blocked.appendingPathComponent("preserved")
        try Data("synthetic-preserved-content".utf8).write(to: preserved)
        XCTAssertThrowsError(try PairingSetupDraft.writeEnrollmentReceipt(enrollment: nil, unavailable: false,
                                                                         in: child, now: now))
        XCTAssertTrue(FileManager.default.fileExists(atPath: preserved.path))
    }

    func testReceiptConcurrentRefreshesPublishOnlyCompleteAllowlistedJSON() async throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("boring-login-enrollment.json")
        let instant = now
        let enrollment = receiptEnrollment()
        let unpaired = try PairingSetupDraft.serializeEnrollmentReceipt(enrollment: nil, unavailable: false, now: instant)
        let paired = try PairingSetupDraft.serializeEnrollmentReceipt(enrollment: enrollment, unavailable: false, now: instant)
        try PairingSetupDraft.writeEnrollmentReceipt(enrollment: nil, unavailable: false, in: directory, now: instant)
        let valid = await withTaskGroup(of: Bool.self, returning: Bool.self) { group in
            for index in 0..<8 {
                group.addTask {
                    do {
                        for _ in 0..<10 {
                            try PairingSetupDraft.writeEnrollmentReceipt(enrollment: index.isMultiple(of: 2) ? nil : enrollment,
                                                                         unavailable: false, in: directory, now: instant)
                            let read = try Data(contentsOf: file)
                            if read != unpaired && read != paired { return false }
                        }
                        return true
                    } catch { return false }
                }
            }
            var accepted = true
            for await complete in group { accepted = accepted && complete }
            return accepted
        }
        XCTAssertTrue(valid)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path), ["boring-login-enrollment.json"])
    }

    private func receiptEnrollment(origin: String = "https://broker.example:8443", certificate: String? = nil,
                                   deviceID: String = "device_synthetic", approvalFingerprint: String? = nil) -> Enrollment {
        Enrollment(brokerURL: URL(string: origin)!, certificateFingerprint: certificate ?? pin,
                   keyTag: "synthetic-do-not-export-keytag", brokerID: "broker_synthetic", ownerID: "owner_synthetic",
                   deviceID: deviceID, deviceToken: "synthetic-do-not-export-token",
                   publicKeyFingerprint: approvalFingerprint ?? String(repeating: "b", count: 64))
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("onboarding-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }
}
