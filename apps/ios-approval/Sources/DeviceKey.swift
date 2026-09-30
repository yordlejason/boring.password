import Foundation
import LocalAuthentication
import Security

enum DeviceKeychain {
    private static let service = "login.boring.approval.enrollment"
    private static let account = "paired-device-v1"

    static func load() throws -> Enrollment? {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                   kSecAttrAccount: account, kSecReturnData: true,
                                   kSecMatchLimit: kSecMatchLimitOne]
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = value as? Data else { throw ApprovalError.unavailableKey }
        return try JSONDecoder().decode(Enrollment.self, from: data)
    }

    static func save(_ enrollment: Enrollment) throws {
        let data = try JSONEncoder().encode(enrollment)
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                   kSecAttrAccount: account]
        let update: [CFString: Any] = [kSecValueData: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData] = data
            item[kSecAttrAccessible] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            item[kSecAttrSynchronizable] = false
            guard SecItemAdd(item as CFDictionary, nil) == errSecSuccess else { throw ApprovalError.unavailableKey }
        } else if status != errSecSuccess {
            throw ApprovalError.unavailableKey
        }
    }

    static func erase() throws {
        let query: [CFString: Any] = [kSecClass: kSecClassGenericPassword, kSecAttrService: service,
                                   kSecAttrAccount: account]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ApprovalError.unavailableKey }
    }
}

@MainActor
final class DeviceSigner {
    private var activeContext: LAContext?

    func makeKey(tag: String) throws -> String {
        let context = LAContext()
        defer { context.invalidate() }
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw ApprovalError.unavailableBiometrics
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet], &accessError
        ) else { throw ApprovalError.unavailableKey }
        let parameters: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits: 256,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: true,
                kSecAttrApplicationTag: Data(tag.utf8),
                kSecAttrAccessControl: access
            ] as [CFString: Any]
        ]
        var keyError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(parameters as CFDictionary, &keyError),
              let publicKey = SecKeyCopyPublicKey(key),
              let raw = SecKeyCopyExternalRepresentation(publicKey, &keyError) as Data?,
              raw.count == 65, raw.first == 0x04 else { throw ApprovalError.unavailableKey }
        // RFC 5480 SubjectPublicKeyInfo: id-ecPublicKey + prime256v1, then X9.63 point.
        let prefix: [UInt8] = [0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,
                               0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00]
        let spki = Data(prefix) + raw
        let base64 = spki.base64EncodedString()
        let lines = stride(from: 0, to: base64.count, by: 64).map { offset -> String in
            let start = base64.index(base64.startIndex, offsetBy: offset)
            let end = base64.index(start, offsetBy: min(64, base64.count - offset))
            return String(base64[start..<end])
        }
        return "-----BEGIN PUBLIC KEY-----\n" + lines.joined(separator: "\n") + "\n-----END PUBLIC KEY-----\n"
    }

    func sign(bytes: Data, keyTag: String) async throws -> Data {
        guard activeContext == nil else { throw ApprovalError.interrupted }
        let context = LAContext() // One new context for this one challenge, never cached.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedFallbackTitle = ""
        activeContext = context
        defer {
            context.invalidate()
            if activeContext === context { activeContext = nil }
        }
        var availabilityError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &availabilityError) else {
            throw ApprovalError.unavailableBiometrics
        }
        let success: Bool = try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                                   localizedReason: "Sign this reviewed authentication request once.") { accepted, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: accepted) }
            }
        }
        guard success, !Task.isCancelled, activeContext === context else { throw ApprovalError.interrupted }
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey, kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag: Data(keyTag.utf8), kSecReturnRef: true,
            kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
            kSecUseAuthenticationContext: context
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let result else { throw ApprovalError.unavailableKey }
        let key = result as! SecKey
        guard SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256),
              !Task.isCancelled, activeContext === context else { throw ApprovalError.interrupted }
        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256,
                                                   bytes as CFData, &signingError) as Data? else {
            throw ApprovalError.unavailableKey
        }
        guard !Task.isCancelled, activeContext === context else { throw ApprovalError.interrupted }
        return signature // ASN.1 DER ECDSA over SHA-256 of the exact received message bytes.
    }

    func cancel() {
        activeContext?.invalidate()
        activeContext = nil
    }

    static func eraseKey(tag: String) throws {
        let query: [CFString: Any] = [kSecClass: kSecClassKey,
                                   kSecAttrApplicationTag: Data(tag.utf8),
                                   kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ApprovalError.unavailableKey }
    }
}
