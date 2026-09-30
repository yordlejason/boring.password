import Foundation
import SwiftUI

@MainActor
final class ApprovalStore: ObservableObject {
    @Published private(set) var enrollment: Enrollment?
    @Published private(set) var challenges: [ReviewedChallenge] = []
    @Published private(set) var status = "Not paired"
    @Published private(set) var busy = false
    @Published var message: String?
    @Published var selected: ReviewedChallenge?
    @Published private(set) var foreground = false
    @Published private(set) var privacyCovered = true

    private static let pendingConfirmationMessage = "Owner: confirm this device in the broker administration interface before it can approve requests."
    private let signer = DeviceSigner()
    private var client: BrokerClient?
    private var polling: Task<Void, Never>?
    private var operation: Task<Void, Never>?
    private var foregroundGeneration = 0

    init() {
        do {
            enrollment = try DeviceKeychain.load()
            if let enrollment {
                client = try BrokerClient(origin: enrollment.brokerURL, fingerprint: enrollment.certificateFingerprint)
                status = "Checking device confirmation"
            }
        } catch { message = ApprovalError.unavailableKey.localizedDescription }
    }

    func sceneChanged(_ phase: ScenePhase) {
        privacyCovered = phase != .active
        if phase == .active {
            foreground = true
            startPolling()
        } else if phase == .background {
            foreground = false
            foregroundGeneration += 1
            signer.cancel()
            operation?.cancel()
            polling?.cancel()
            polling = nil
            selected = nil
            challenges = []
            if busy { message = ApprovalError.interrupted.localizedDescription }
        }
    }

    func pair(originText: String, fingerprintText: String, pairingCode: String, deviceName: String,
              fingerprintVerified: Bool) {
        guard !busy, foreground, fingerprintVerified,
              let origin = URL(string: originText.trimmingCharacters(in: .whitespacesAndNewlines)),
              !pairingCode.isEmpty, pairingCode.utf8.count <= 1_024,
              !deviceName.isEmpty, deviceName.utf16.count <= 100 else { return }
        busy = true
        operation = Task {
            message = nil
            let tag = "login.boring.approval." + UUID().uuidString
            var saved = false
            defer {
                busy = false
                operation = nil
                if !saved { try? DeviceSigner.eraseKey(tag: tag) }
            }
            do {
                let fingerprint = fingerprintText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                let broker = try BrokerClient(origin: origin, fingerprint: fingerprint)
                let publicKey = try signer.makeKey(tag: tag)
                let pemBody = publicKey.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined()
                guard let spki = Data(base64Encoded: pemBody) else { throw ApprovalError.unavailableKey }
                let response = try await broker.enroll(code: pairingCode, name: deviceName, publicKey: publicKey)
                try Task.checkCancellation()
                guard foreground else { throw ApprovalError.interrupted }
                let paired = Enrollment(brokerURL: origin, certificateFingerprint: fingerprint, keyTag: tag,
                                        brokerID: response.brokerID, ownerID: response.ownerID,
                                        deviceID: response.deviceID, deviceToken: response.deviceToken,
                                        publicKeyFingerprint: ApprovalPayload.sha256(spki))
                try DeviceKeychain.save(paired)
                saved = true
                enrollment = paired
                client = broker
                status = "Awaiting separate owner confirmation"
                message = Self.pendingConfirmationMessage
                startPolling()
            } catch { message = safeMessage(error) }
        }
    }

    func verifyBrokerConnection(originText: String, fingerprintText: String) {
        guard !busy, foreground,
              let origin = URL(string: originText.trimmingCharacters(in: .whitespacesAndNewlines)) else { return }
        busy = true
        let generation = foregroundGeneration
        operation = Task {
            message = nil
            defer { busy = false; operation = nil }
            do {
                let fingerprint = fingerprintText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                let broker = try BrokerClient(origin: origin, fingerprint: fingerprint)
                try await broker.verifyConnection()
                try Task.checkCancellation()
                guard foreground, foregroundGeneration == generation else { throw ApprovalError.interrupted }
                message = "HTTPS system trust and the entered certificate pin passed. Owner verification, pairing and separate confirmation are still required."
            } catch { message = safeMessage(error) }
        }
    }

    func refresh() async {
        guard foreground, !busy, let enrollment, let client else { return }
        let generation = foregroundGeneration
        do {
            let response = try await client.challenges(token: enrollment.deviceToken)
            try Task.checkCancellation()
            guard foreground, foregroundGeneration == generation else { return }
            if response.status == "PENDING_CONFIRMATION" {
                challenges = []
                selected = nil
                status = "Awaiting separate owner confirmation"
                return
            }
            var reviewed: [ReviewedChallenge] = []
            var ids = Set<String>()
            for wire in response.challenges {
                guard ids.insert(wire.challengeID).inserted else { throw ApprovalError.invalidPayload }
                reviewed.append(try ReviewedChallenge(wire: wire, enrollment: enrollment))
            }
            challenges = reviewed
            status = "Owner-confirmed device"
            if message == Self.pendingConfirmationMessage { message = nil }
            if let selected, !reviewed.contains(where: { $0.id == selected.id && $0.digest == selected.digest }) {
                self.selected = nil
            }
        } catch {
            guard foreground, foregroundGeneration == generation else { return }
            // Never leave a stale approval button usable after transport/identity/revocation failures.
            challenges = []
            selected = nil
            if !Task.isCancelled { message = safeMessage(error) }
            status = "Device connection blocked"
        }
    }

    func approve(_ challenge: ReviewedChallenge) {
        guard !busy, foreground, let enrollment, let client,
              challenges.contains(where: { $0.id == challenge.id && $0.digest == challenge.digest }) else { return }
        let generation = foregroundGeneration
        busy = true
        operation = Task {
            message = nil
            defer { busy = false; operation = nil }
            do {
                try challenge.payload.validate(enrollment: enrollment)
                let signature = try await signer.sign(bytes: challenge.bytes, keyTag: enrollment.keyTag)
                try Task.checkCancellation()
                guard foreground, foregroundGeneration == generation else { throw ApprovalError.interrupted }
                try challenge.payload.validate(enrollment: enrollment)
                try await client.approve(challenge: challenge, deviceID: enrollment.deviceID,
                                         signature: signature, token: enrollment.deviceToken)
                try Task.checkCancellation()
                selected = nil
                challenges.removeAll { $0.id == challenge.id }
                message = "The broker accepted the signed approval. Authentication status is managed by the broker."
            } catch {
                selected = nil
                challenges.removeAll { $0.id == challenge.id }
                message = safeMessage(error)
            }
        }
    }

    func deny(_ challenge: ReviewedChallenge) {
        guard !busy, foreground, let enrollment, let client else { return }
        busy = true
        operation = Task {
            message = nil
            defer { busy = false; operation = nil }
            do {
                try await client.deny(challenge: challenge, deviceID: enrollment.deviceID, token: enrollment.deviceToken)
                selected = nil
                challenges.removeAll { $0.id == challenge.id }
                message = "The broker accepted the denial."
            } catch { message = safeMessage(error) }
        }
    }

    func eraseLocalPairing() {
        guard !busy else { return }
        signer.cancel()
        polling?.cancel()
        polling = nil
        do {
            if let enrollment { try DeviceSigner.eraseKey(tag: enrollment.keyTag) }
            try DeviceKeychain.erase()
            enrollment = nil
            client = nil
            challenges = []
            selected = nil
            status = "Not paired"
            message = "Local key and pairing removed. The owner should revoke the device record in the broker administration interface."
        } catch { message = ApprovalError.unavailableKey.localizedDescription }
    }

    private func startPolling() {
        guard polling == nil, client != nil, foreground else { return }
        polling = Task {
            while !Task.isCancelled {
                await refresh()
                do { try await Task.sleep(for: .seconds(5)) }
                catch { break }
            }
        }
    }

    private func safeMessage(_ error: Error) -> String {
        // Underlying errors and response bodies never reach the UI or logs.
        if let approvalError = error as? ApprovalError { return approvalError.localizedDescription }
        if error is CancellationError { return ApprovalError.interrupted.localizedDescription }
        return "Approval did not complete. Biometric cancellation, failure, or an unavailable key cannot authorize a request."
    }
}
