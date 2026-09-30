import Darwin
import Foundation

enum OnboardingDraftError: LocalizedError, Sendable {
    case invalidPacket, invalidFile, expired, storageUnavailable
    case invalidReceipt, receiptStorageUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidPacket: "The setup packet is invalid. Prepare a new packet from the owner-controlled host."
        case .invalidFile: "The setup import must be a small regular file. Prepare a new setup packet."
        case .expired: "The setup packet expired or has an invalid lifetime. Prepare a fresh packet."
        case .storageUnavailable: "The one-use setup packet could not be consumed safely. Check local app storage."
        case .invalidReceipt: "Public enrollment metadata is unavailable. Check the app's existing pairing."
        case .receiptStorageUnavailable: "Public enrollment status could not be refreshed safely. Check local app storage."
        }
    }
}

/// Unverified field values only. Importing never creates a key, changes pairing,
/// makes a network request, confirms a fingerprint, or authorizes an operation.
struct PairingSetupDraft: Equatable, Sendable {
    let brokerURL: String
    let certificateFingerprint: String
    let pairingCode: String
    let expiresAt: Date

    private static let maximumBytes = 4_096
    private static let filename = "boring-login-onboarding.json"
    private static let receiptFilename = "boring-login-enrollment.json"

    static func parse(data: Data, now: Date = Date()) throws -> PairingSetupDraft {
        guard !data.isEmpty, data.count <= maximumBytes,
              String(data: data, encoding: .utf8) != nil else { throw OnboardingDraftError.invalidPacket }
        var decoder = DraftJSONObject(bytes: Array(data))
        let fields = try decoder.decode()
        let required: Set<String> = ["version", "broker_url", "certificate_sha256", "expires_at"]
        guard required.isSubset(of: Set(fields.keys)),
              Set(fields.keys).isSubset(of: required.union(["pairing_code"])),
              fields["version"] == .token("1"),
              case .string(let origin)? = fields["broker_url"],
              case .string(let fingerprint)? = fields["certificate_sha256"],
              case .string(let expiryText)? = fields["expires_at"]
        else { throw OnboardingDraftError.invalidPacket }

        guard origin.utf8.count <= 2_048,
              origin == origin.trimmingCharacters(in: .whitespacesAndNewlines),
              !origin.unicodeScalars.contains(where: { [.control, .format].contains($0.properties.generalCategory) }),
              let originURL = URL(string: origin),
              (try? BrokerClient(origin: originURL, fingerprint: fingerprint)) != nil
        else { throw OnboardingDraftError.invalidPacket }

        let code: String
        if let value = fields["pairing_code"] {
            guard case .string(let supplied) = value,
                  supplied.utf8.count == 43,
                  supplied.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) ||
                      (48...57).contains($0) || $0 == 45 || $0 == 95 })
            else { throw OnboardingDraftError.invalidPacket }
            code = supplied
        } else { code = "" }

        guard expiryText.range(of: #"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?(?:Z|[+-][0-9]{2}:[0-9]{2})$"#,
                               options: .regularExpression) == expiryText.startIndex..<expiryText.endIndex,
              let expires = ApprovalPayload.date(expiryText),
              expires > now, expires.timeIntervalSince(now) <= 600
        else { throw OnboardingDraftError.expired }
        return PairingSetupDraft(brokerURL: origin, certificateFingerprint: fingerprint,
                                 pairingCode: code, expiresAt: expires)
    }

    static func consumeFromDocuments() throws -> PairingSetupDraft? {
        try consume(at: importURL(), now: Date())
    }

    /// Already-paired apps discard the transient file without decoding its fields.
    static func discardPendingImport() throws {
        try removeExactFile(at: importURL())
    }

    /// Public navigation metadata only; this receipt is never device attestation
    /// or authority to pair, confirm a device, or authorize a request.
    static func writeEnrollmentReceipt(enrollment: Enrollment?, unavailable: Bool) throws {
        try writeEnrollmentReceipt(enrollment: enrollment, unavailable: unavailable,
                                   in: documentsDirectory(), now: Date())
    }

    static func serializeEnrollmentReceipt(enrollment: Enrollment?, unavailable: Bool,
                                           now: Date = Date()) throws -> Data {
        guard now.timeIntervalSince1970.isFinite else { throw OnboardingDraftError.invalidReceipt }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let q = CanonicalJSON.quote
        var fields = ["version": "1", "written_at": q(formatter.string(from: now)),
                      "status": q(enrollment == nil ? (unavailable ? "UNAVAILABLE" : "UNPAIRED") : "PAIRED")]
        if let enrollment {
            let origin = enrollment.brokerURL.absoluteString
            guard origin.utf8.count <= 2_048,
                  !origin.unicodeScalars.contains(where: { [.control, .format].contains($0.properties.generalCategory) }),
                  (try? BrokerClient(origin: enrollment.brokerURL,
                                     fingerprint: enrollment.certificateFingerprint)) != nil,
                  enrollment.deviceID.utf8.count <= 200, !enrollment.deviceID.isEmpty,
                  enrollment.deviceID.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) ||
                      (48...57).contains($0) || $0 == 45 || $0 == 95 }),
                  enrollment.publicKeyFingerprint.utf8.count == 64,
                  enrollment.publicKeyFingerprint.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
            else { throw OnboardingDraftError.invalidReceipt }
            fields["broker_url"] = q(origin)
            fields["certificate_sha256"] = q(enrollment.certificateFingerprint)
            fields["device_id"] = q(enrollment.deviceID)
            fields["approval_key_sha256"] = q(enrollment.publicKeyFingerprint)
        }
        let data = Data(CanonicalJSON.object(fields).utf8)
        guard data.count <= maximumBytes else { throw OnboardingDraftError.invalidReceipt }
        return data
    }

    // Internal directory/time seam for safe IO tests; production always uses
    // the app's own Documents directory and the one fixed receipt filename.
    static func writeEnrollmentReceipt(enrollment: Enrollment?, unavailable: Bool,
                                       in directory: URL, now: Date) throws {
        let directoryDescriptor = directory.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) } ?? -1
        }
        guard directoryDescriptor >= 0 else { throw OnboardingDraftError.receiptStorageUnavailable }
        defer { Darwin.close(directoryDescriptor) }
        let temporary = ".boring-login-enrollment." + UUID().uuidString + ".tmp"
        defer { _ = temporary.withCString { unlinkat(directoryDescriptor, $0, 0) } }
        do {
            var existing = stat()
            let inspected = receiptFilename.withCString {
                fstatat(directoryDescriptor, $0, &existing, AT_SYMLINK_NOFOLLOW)
            }
            guard (inspected == 0 && (existing.st_mode & S_IFMT) == S_IFREG) ||
                  (inspected != 0 && errno == ENOENT)
            else { throw OnboardingDraftError.receiptStorageUnavailable }
            let data = try serializeEnrollmentReceipt(enrollment: enrollment, unavailable: unavailable, now: now)
            let descriptor = temporary.withCString {
                openat(directoryDescriptor, $0, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                       mode_t(0o600))
            }
            guard descriptor >= 0 else { throw OnboardingDraftError.receiptStorageUnavailable }
            defer { Darwin.close(descriptor) }
            var offset = 0
            while offset < data.count {
                let count = data.withUnsafeBytes { buffer in
                    guard let base = buffer.baseAddress else { return 0 }
                    return Darwin.write(descriptor, base.advanced(by: offset), data.count - offset)
                }
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw OnboardingDraftError.receiptStorageUnavailable }
                offset += count
            }
            guard fsync(descriptor) == 0 else { throw OnboardingDraftError.receiptStorageUnavailable }
            let published = temporary.withCString { source in
                receiptFilename.withCString { target in
                    renameat(directoryDescriptor, source, directoryDescriptor, target)
                }
            }
            guard published == 0 else { throw OnboardingDraftError.receiptStorageUnavailable }
        } catch {
            // Never leave an older PAIRED receipt after a failed refresh if it
            // can be removed. unlinkat never follows a symlink or recurses.
            _ = receiptFilename.withCString { unlinkat(directoryDescriptor, $0, 0) }
            if let safe = error as? OnboardingDraftError { throw safe }
            throw OnboardingDraftError.receiptStorageUnavailable
        }
    }

    private static func importURL() throws -> URL {
        try documentsDirectory().appendingPathComponent(filename, isDirectory: false)
    }

    private static func documentsDirectory() throws -> URL {
        guard let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
        else { throw OnboardingDraftError.storageUnavailable }
        return directory
    }

    // Internal path-taking variant permits filesystem adversarial tests without
    // touching the app's enrollment, real Documents import, or device Keychain.
    static func consume(at url: URL, now: Date) throws -> PairingSetupDraft? {
        let descriptor = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.open($0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) } ?? -1
        }
        guard descriptor >= 0 else {
            if errno == ENOENT { return nil }
            if errno == ELOOP {
                try removeExactFile(at: url)
                throw OnboardingDraftError.invalidFile
            }
            throw OnboardingDraftError.storageUnavailable
        }
        defer { Darwin.close(descriptor) }
        var info = stat()
        let inspected = fstat(descriptor, &info) == 0
        // Unlink before parsing, including malformed/expired/oversized inputs.
        // A second consumer cannot successfully claim the same pathname.
        try removeExactFile(at: url, missingIsSuccess: false)
        guard inspected, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 0, info.st_size <= maximumBytes else { throw OnboardingDraftError.invalidFile }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: maximumBytes + 1)
        while data.count <= maximumBytes {
            let count = buffer.withUnsafeMutableBytes {
                Darwin.read(descriptor, $0.baseAddress, maximumBytes + 1 - data.count)
            }
            if count < 0 {
                if errno == EINTR { continue }
                throw OnboardingDraftError.storageUnavailable
            }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        guard data.count <= maximumBytes else { throw OnboardingDraftError.invalidFile }
        return try parse(data: data, now: now)
    }

    private static func removeExactFile(at url: URL, missingIsSuccess: Bool = true) throws {
        let result = url.withUnsafeFileSystemRepresentation { path in
            path.map { Darwin.unlink($0) } ?? -1
        }
        guard result == 0 || (missingIsSuccess && errno == ENOENT)
        else { throw OnboardingDraftError.storageUnavailable }
    }
}

/// A small flat-object decoder preserves duplicate keys and numeric spelling.
/// Foundation dictionary decoding would discard duplicate keys and can bridge
/// JSON true to NSNumber(1). Strings still use Foundation's JSON escape decoder.
private struct DraftJSONObject {
    enum Value: Equatable { case string(String), token(String) }
    let bytes: [UInt8]
    private var index = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func decode() throws -> [String: Value] {
        var fields: [String: Value] = [:]
        whitespace()
        try take(123)
        whitespace()
        if current == 125 { index += 1 }
        else {
            while true {
                let key = try string()
                guard fields[key] == nil else { throw OnboardingDraftError.invalidPacket }
                whitespace()
                try take(58)
                whitespace()
                if current == 34 { fields[key] = .string(try string()) }
                else {
                    let start = index
                    while let byte = current, ![9, 10, 13, 32, 44, 125].contains(byte) { index += 1 }
                    guard index > start else { throw OnboardingDraftError.invalidPacket }
                    fields[key] = .token(String(decoding: bytes[start..<index], as: UTF8.self))
                }
                whitespace()
                if current == 125 { index += 1; break }
                try take(44)
                whitespace()
            }
        }
        whitespace()
        guard index == bytes.count else { throw OnboardingDraftError.invalidPacket }
        return fields
    }

    private var current: UInt8? { index < bytes.count ? bytes[index] : nil }

    private mutating func whitespace() {
        while let byte = current, [9, 10, 13, 32].contains(byte) { index += 1 }
    }

    private mutating func take(_ byte: UInt8) throws {
        guard current == byte else { throw OnboardingDraftError.invalidPacket }
        index += 1
    }

    private mutating func string() throws -> String {
        let start = index
        try take(34)
        while let byte = current {
            index += 1
            if byte == 34 {
                do {
                    guard let text = try JSONSerialization.jsonObject(with: Data(bytes[start..<index]),
                                                                     options: [.fragmentsAllowed]) as? String
                    else { throw OnboardingDraftError.invalidPacket }
                    return text
                } catch { throw OnboardingDraftError.invalidPacket }
            }
            if byte == 92 {
                guard current != nil else { throw OnboardingDraftError.invalidPacket }
                index += 1
            }
        }
        throw OnboardingDraftError.invalidPacket
    }
}
