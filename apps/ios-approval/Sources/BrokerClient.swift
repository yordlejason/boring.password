import CryptoKit
import Foundation
import Security

struct EnrollmentResponse: Decodable, Sendable {
    let deviceID: String
    let ownerID: String
    let brokerID: String
    let deviceToken: String
    let status: String
    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id", ownerID = "owner_id", brokerID = "broker_id"
        case deviceToken = "device_token", status
    }
}

struct ChallengeResponse: Decodable, Sendable {
    let status: String
    let challenges: [WireChallenge]
}

private final class TLSFailure: @unchecked Sendable {
    // URLSession invokes delegate callbacks on its queue; all mutable state is locked.
    private let lock = NSLock()
    private var error: ApprovalError?

    func record(_ error: ApprovalError) { lock.withLock { self.error = error } }
    func value() -> ApprovalError? { lock.withLock { error } }
}

private final class PinnedTLSDelegate: NSObject, URLSessionDelegate, URLSessionTaskDelegate, Sendable {
    let host: String
    let fingerprint: String
    let failure = TLSFailure()

    init(host: String, fingerprint: String) {
        self.host = host
        self.fingerprint = fingerprint
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              challenge.protectionSpace.host == host,
              let trust = challenge.protectionSpace.serverTrust,
              SecTrustEvaluateWithError(trust, nil),
              let certificates = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = certificates.first
        else {
            failure.record(.certificateTrust)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        guard ApprovalPayload.sha256(SecCertificateCopyData(leaf) as Data) == fingerprint else {
            failure.record(.certificatePin)
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // Never forward pairing or device tokens across a redirect.
    }
}

final class BrokerClient: Sendable {
    let origin: URL
    let fingerprint: String

    init(origin: URL, fingerprint: String) throws {
        guard let components = URLComponents(url: origin, resolvingAgainstBaseURL: false),
              components.scheme == "https", let host = components.host, !host.isEmpty,
              components.user == nil, components.password == nil, components.query == nil,
              components.fragment == nil, ["", "/"].contains(components.path),
              fingerprint.count == 64,
              fingerprint.allSatisfy({ "0123456789abcdef".contains($0) })
        else { throw ApprovalError.invalidBroker }
        self.origin = origin
        self.fingerprint = fingerprint
    }

    func enroll(code: String, name: String, publicKey: String) async throws -> EnrollmentResponse {
        let response: EnrollmentResponse = try await request("device/enroll", method: "POST", token: nil, body: [
            "pairing_code": code, "device_name": name, "public_key": publicKey,
            "key_algorithm": "P256_SHA256_DER",
            "assurance_profile": "OWNER_ENROLLED_BIOMETRIC_PROTECTED_DEVICE"
        ])
        guard ["PENDING_CONFIRMATION", "ACTIVE"].contains(response.status),
              !response.deviceID.isEmpty, !response.ownerID.isEmpty, !response.brokerID.isEmpty,
              !response.deviceToken.isEmpty else { throw ApprovalError.invalidPayload }
        return response
    }

    func verifyConnection() async throws {
        // Public administration shell only: no tokens, key generation, enrollment, or approval.
        _ = try await send("", method: "GET", token: nil, body: nil)
    }

    func challenges(token: String) async throws -> ChallengeResponse {
        let response: ChallengeResponse = try await request("device/challenges", token: token)
        guard ["PENDING_CONFIRMATION", "ACTIVE"].contains(response.status), response.challenges.count <= 50,
              response.status != "PENDING_CONFIRMATION" || response.challenges.isEmpty
        else { throw ApprovalError.invalidPayload }
        return response
    }

    func approve(challenge: ReviewedChallenge, deviceID: String, signature: Data, token: String) async throws {
        try await submit("device/approve", token: token, body: [
            "challenge_id": challenge.id, "device_id": deviceID,
            "signature": signature.base64EncodedString()
        ])
    }

    func deny(challenge: ReviewedChallenge, deviceID: String, token: String) async throws {
        try await submit("device/deny", token: token, body: ["challenge_id": challenge.id, "device_id": deviceID])
    }

    private func request<T: Decodable & Sendable>(_ path: String, method: String = "GET", token: String?,
                                                 body: [String: String]? = nil) async throws -> T {
        let data = try await send(path, method: method, token: token, body: body)
        do { return try JSONDecoder().decode(T.self, from: data) }
        catch { throw ApprovalError.invalidPayload }
    }

    private func submit(_ path: String, token: String, body: [String: String]) async throws {
        _ = try await send(path, method: "POST", token: token, body: body)
    }

    private func send(_ path: String, method: String, token: String?, body: [String: String]?) async throws -> Data {
        // Isolate TLS diagnostics per request, and perform a fresh trust+pin handshake.
        let delegate = PinnedTLSDelegate(host: origin.host!, fingerprint: fingerprint)
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 25
        config.waitsForConnectivity = true // Wait for the first local-network permission decision.
        let session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: origin.appendingPathComponent(path))
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let token { request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try JSONEncoder().encode(body)
        }
        let data: Data
        let response: URLResponse
        do { (data, response) = try await session.data(for: request) }
        catch {
            if Task.isCancelled { throw ApprovalError.interrupted }
            if let failure = delegate.failure.value() { throw failure }
            throw Self.safeTransportError(error)
        }
        guard let response = response as? HTTPURLResponse,
              response.url?.host == origin.host else { throw ApprovalError.transport }
        guard (200..<300).contains(response.statusCode) else { throw ApprovalError.serverRejected(response.statusCode) }
        guard data.count <= 1_048_576 else { throw ApprovalError.invalidPayload }
        return data
    }

    static func safeTransportError(_ error: Error) -> ApprovalError {
        guard let urlError = error as? URLError else { return .transport }
        switch urlError.code {
        case .serverCertificateHasBadDate, .serverCertificateUntrusted, .serverCertificateHasUnknownRoot,
             .serverCertificateNotYetValid, .secureConnectionFailed: return .certificateTrust
        case .cannotFindHost, .dnsLookupFailed: return .hostUnavailable
        case .cannotConnectToHost, .networkConnectionLost, .notConnectedToInternet, .timedOut: return .networkUnavailable
        default: return .transport
        }
    }
}
