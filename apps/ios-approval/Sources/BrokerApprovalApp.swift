import SwiftUI

@main
struct BrokerApprovalApp: App {
    @StateObject private var store = ApprovalStore()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ApprovalRootView(store: store)
                .privacySensitive()
                .onAppear { store.sceneChanged(scenePhase) }
                .onChange(of: scenePhase) { _, phase in store.sceneChanged(phase) }
        }
    }
}

struct ApprovalRootView: View {
    @ObservedObject var store: ApprovalStore
    @Environment(\.scenePhase) private var scenePhase
    @State private var showDevice = false
    @State private var setupDraft: PairingSetupDraft?
    @State private var setupMessage: String?

    var body: some View {
        NavigationStack {
            Group {
                if let enrollment = store.enrollment {
                    ApprovalHomeView(store: store, enrollment: enrollment)
                } else {
                    PairingView(store: store, draft: setupDraft, setupMessage: setupMessage)
                }
            }
            .navigationTitle(store.enrollment == nil ? "Connect your iPhone" : "Approvals")
            .toolbar {
                if store.enrollment != nil {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Device details", systemImage: "gearshape") { showDevice = true }
                    }
                }
            }
            .sheet(item: $store.selected) { challenge in
                ApprovalReviewView(store: store, challenge: challenge)
            }
            .sheet(isPresented: $showDevice) {
                if let enrollment = store.enrollment {
                    DeviceDetailsView(store: store, enrollment: enrollment)
                }
            }
            .overlay { if store.privacyCovered { PrivacyCover() } }
            .onAppear {
                loadPreparedSetup()
                updateEnrollmentReceipt()
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active {
                    loadPreparedSetup()
                    updateEnrollmentReceipt()
                }
            }
            .onChange(of: store.enrollment?.deviceID) { _, deviceID in
                if deviceID != nil { loadPreparedSetup() }
                updateEnrollmentReceipt()
            }
            .onChange(of: store.message) { _, _ in
                if store.enrollment == nil { updateEnrollmentReceipt() }
            }
        }
    }

    private func loadPreparedSetup() {
        if store.enrollment != nil {
            // Prepared values never replace an existing Keychain enrollment.
            try? PairingSetupDraft.discardPendingImport()
            setupDraft = nil
            setupMessage = nil
            return
        }
        guard !store.busy else { return }
        do {
            if let prepared = try PairingSetupDraft.consumeFromDocuments() {
                setupDraft = prepared
                setupMessage = nil
            }
        } catch {
            setupDraft = nil
            setupMessage = "Prepared setup could not be loaded. Prepare it again on your Mac, or enter the details manually."
        }
    }

    private func updateEnrollmentReceipt() {
        // Public metadata for setup coordination only; it supplies no approval authority.
        // Failure never changes enrollment, transport, or the protected signing key.
        try? PairingSetupDraft.writeEnrollmentReceipt(
            enrollment: store.enrollment,
            unavailable: enrollmentUnavailable
        )
    }

    private var enrollmentUnavailable: Bool {
        guard store.enrollment == nil, let message = store.message else { return false }
        // These two exact notices describe a successful action with no enrollment.
        // Every other unresolved message is conservatively treated as unavailable.
        switch message {
        case "HTTPS system trust and the entered certificate pin passed. Owner verification, pairing and separate confirmation are still required.",
             "Local key and pairing removed. The owner should revoke the device record in the broker administration interface.":
            return false
        default:
            return true
        }
    }
}

private struct ApprovalHomeView: View {
    @ObservedObject var store: ApprovalStore
    let enrollment: Enrollment

    private var ready: Bool { store.status == "Owner-confirmed device" }
    private var awaitingConfirmation: Bool { store.status == "Awaiting separate owner confirmation" }
    private var blocked: Bool { store.status == "Device connection blocked" }

    var body: some View {
        List {
            Section {
                HStack(alignment: .top, spacing: 14) {
                    Image(systemName: ready ? "checkmark.shield.fill" : blocked ? "exclamationmark.shield" : "shield.lefthalf.filled")
                        .font(.title2).foregroundStyle(ready ? Color.green : blocked ? Color.orange : Color.secondary)
                    VStack(alignment: .leading, spacing: 5) {
                        Text(ready ? "Ready" : awaitingConfirmation ? "Finish connecting" : blocked ? "Connection paused" : "Checking connection")
                            .font(.headline)
                        Text(enrollment.brokerURL.absoluteString)
                            .font(.subheadline).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                        if !ready { Text(store.status).font(.footnote).foregroundStyle(.secondary) }
                    }
                    Spacer(minLength: 0)
                }.padding(.vertical, 5)
            }
            if awaitingConfirmation {
                Section("One last check") {
                    Text("Compare this approval key with the owner console, then confirm the device there.")
                        .font(.subheadline).foregroundStyle(.secondary)
                    FingerprintView(title: "Approval key SHA-256", fingerprint: enrollment.publicKeyFingerprint)
                }
            }
            if let message = store.message,
               message != "Owner: confirm this device in the broker administration interface before it can approve requests." {
                Section { NoticeView(message: message) }
            }
            Section {
                if store.challenges.isEmpty {
                    VStack(spacing: 10) {
                        Image(systemName: "tray").font(.largeTitle).foregroundStyle(.tertiary)
                        Text(ready ? "You're all caught up" : "No requests to review").font(.headline)
                        Text(ready ? "When your AI needs to sign in, open this app to review its request." : "Requests appear after the owner confirms this device.")
                            .font(.subheadline).foregroundStyle(.secondary).multilineTextAlignment(.center)
                    }.frame(maxWidth: .infinity).padding(.vertical, 26)
                }
                ForEach(store.challenges) { challenge in
                    Button { store.selected = challenge } label: {
                        RequestSummaryRow(challenge: challenge)
                    }.buttonStyle(.plain).disabled(store.busy)
                }
            } header: {
                HStack {
                    Text("To review")
                    Spacer()
                    if !store.challenges.isEmpty { Text(String(store.challenges.count)) }
                }
            }
            Section {
                Text("Each approval requires Face ID or Touch ID and applies to one request.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
        }
        .refreshable { await store.refresh() }
    }
}

private struct RequestSummaryRow: View {
    let challenge: ReviewedChallenge

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: "person.badge.key.fill").font(.title3).foregroundStyle(.tint)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 5) {
                Text(challenge.payload.accountDisplayName).font(.headline)
                    .fixedSize(horizontal: false, vertical: true)
                Text(challenge.payload.destination).font(.subheadline)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Requested by \(challenge.payload.clientDisplayName)")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if challenge.payload.isLocalSyntheticDestination {
                    Text("Local test account").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            Image(systemName: "chevron.right").font(.footnote).foregroundStyle(.tertiary)
        }.padding(.vertical, 7)
    }
}

private struct PairingView: View {
    @ObservedObject var store: ApprovalStore
    let draft: PairingSetupDraft?
    let setupMessage: String?
    @State private var origin = ""
    @State private var fingerprint = ""
    @State private var code = ""
    @State private var name = "My iPhone"
    @State private var verified = false
    @State private var step = 1
    @State private var editConnection = false

    private var identityReady: Bool {
        guard let url = URL(string: origin.trimmingCharacters(in: .whitespacesAndNewlines)) else { return false }
        let pin = fingerprint.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return (try? BrokerClient(origin: url, fingerprint: pin)) != nil
    }

    var body: some View {
        Form {
            Section {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Step \(step) of 2", systemImage: step == 1 ? "network" : "iphone")
                        .font(.subheadline).foregroundStyle(.secondary)
                    Text(step == 1 ? "Connect to your broker" : "Pair this iPhone").font(.title2.bold())
                    Text(step == 1 ? (draft == nil ? "Enter the details from your owner console." : "Compare the fingerprint with your owner console.") : "Create your protected approval key, then confirm it in the owner console.")
                        .font(.subheadline).foregroundStyle(.secondary)
                    if step == 1, let draft {
                        HStack(spacing: 4) {
                            Text("Prepared on your Mac · \(draft.pairingCode.isEmpty ? "Setup" : "Pairing code") expires")
                            Text(draft.expiresAt, style: .time)
                        }.font(.caption).foregroundStyle(.secondary)
                    }
                }.padding(.vertical, 2)
            }
            if step == 1 {
                Section("Connection") {
                    if draft != nil {
                        ReviewField("Broker", origin)
                        FingerprintView(title: "Compare this certificate SHA-256", fingerprint: fingerprint)
                        DisclosureGroup("Edit connection details", isExpanded: $editConnection) {
                            connectionFields
                        }
                    } else {
                        connectionFields
                    }
                    Button("Check HTTPS connection") {
                        store.verifyBrokerConnection(originText: origin, fingerprintText: fingerprint)
                    }.disabled(!identityReady || store.busy)
                }
                Section {
                    Toggle("I compared this fingerprint with my owner console", isOn: $verified)
                        .disabled(!identityReady || store.busy)
                } footer: {
                    Text("A connection check does not replace this identity comparison.")
                }
            } else {
                Section {
                    LabeledContent("Broker") {
                        Text(origin.trimmingCharacters(in: .whitespacesAndNewlines))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    SecureField("One-use pairing code", text: $code)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .disabled(store.busy)
                    TextField("Device name", text: $name).disabled(store.busy)
                } header: {
                    Text("Pairing")
                } footer: {
                    Text("Get a fresh code from the owner console. Complete pairing directly on your iPhone; biometrics are unavailable during Mirroring.")
                }
                Section {
                    Button {
                        store.pair(originText: origin, fingerprintText: fingerprint, pairingCode: code,
                                   deviceName: name, fingerprintVerified: verified)
                        code = ""
                    } label: {
                        Label("Pair this iPhone", systemImage: "lock.shield")
                            .frame(maxWidth: .infinity)
                    }.buttonStyle(.borderedProminent)
                        .disabled(!verified || !identityReady || code.isEmpty || name.isEmpty || name.utf16.count > 100 || store.busy)
                    Button("Back to connection") { step = 1 }.disabled(store.busy)
                }
            }
            if let setupMessage { Section { NoticeView(message: setupMessage) } }
            if store.busy || store.message != nil {
                Section {
                    if store.busy { ProgressView("Connecting…") }
                    if let message = store.message { NoticeView(message: message) }
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if step == 1 {
                Button { step = 2 } label: {
                    Text("Continue").font(.headline).frame(maxWidth: .infinity).padding(.vertical, 7)
                }.buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(!verified || !identityReady || store.busy)
                    .padding(.horizontal, 20).padding(.top, 14).padding(.bottom, 10)
                    .frame(maxWidth: .infinity).background(.bar)
            }
        }
        .onChange(of: origin) { _, _ in identityChanged() }
        .onChange(of: fingerprint) { _, _ in identityChanged() }
        .onAppear { applyPreparedSetup() }
        .onChange(of: draft) { _, updated in
            identityChanged()
            if updated == nil { code = "" }
            applyPreparedSetup()
        }
    }

    private var connectionFields: some View {
        Group {
            TextField("https://broker.example", text: $origin)
                .keyboardType(.URL).textContentType(.URL)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .disabled(store.busy)
            VStack(alignment: .leading, spacing: 7) {
                Text("Certificate SHA-256").font(.caption).foregroundStyle(.secondary)
                TextField("64-character fingerprint", text: $fingerprint, axis: .vertical)
                    .font(.system(.footnote, design: .monospaced))
                    .textInputAutocapitalization(.never).autocorrectionDisabled()
                    .disabled(store.busy)
            }
        }
    }

    private func applyPreparedSetup() {
        guard !store.busy, let draft else { return }
        origin = draft.brokerURL
        fingerprint = draft.certificateFingerprint
        code = draft.pairingCode
        verified = false
        step = 1
        editConnection = false
    }

    private func identityChanged() {
        verified = false
        step = 1
        if store.message == "HTTPS system trust and the entered certificate pin passed. Owner verification, pairing and separate confirmation are still required." {
            store.message = nil
        }
    }
}

private struct ApprovalReviewView: View {
    @ObservedObject var store: ApprovalStore
    let challenge: ReviewedChallenge
    @Environment(\.dismiss) private var dismiss

    private var payload: ApprovalPayload { challenge.payload }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        Label("Sign-in request", systemImage: "person.badge.key.fill")
                            .font(.subheadline).foregroundStyle(.secondary)
                        Text(payload.accountDisplayName).font(.title2.bold())
                            .fixedSize(horizontal: false, vertical: true)
                        Text(payload.destination).font(.subheadline)
                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        if payload.isLocalSyntheticDestination {
                            Text("Local test account · your phone does not connect to this site.")
                                .font(.footnote).foregroundStyle(.secondary)
                        }
                    }.padding(.vertical, 7)
                    ReviewField("Requested by", payload.clientDisplayName)
                    ReviewField("Operation", payload.operation)
                    ReviewField("Allowed after login", payload.sessionActionProfile)
                    ReviewField("Authentication", payload.factors.joined(separator: " + "))
                    if let expiry = ApprovalPayload.date(payload.expiresAt) {
                        LabeledContent("Expires") {
                            Text(expiry, style: .time).foregroundStyle(.secondary)
                        }
                    }
                }
                Section("Purpose · stated by the AI") {
                    Text(payload.purpose.isEmpty ? "No purpose stated." : payload.purpose)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("This description is untrusted. Approval is limited to the site, account and access shown above.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Section {
                    DisclosureGroup("Full signed details") {
                        ReviewField("Protocol / action", String(payload.version) + " / " + payload.action)
                        ReviewField("Destination", payload.destination)
                        ReviewField("Account", payload.accountDisplayName + "\n" + payload.accountID)
                        ReviewField("Requested by", payload.clientDisplayName + "\n" + payload.clientID)
                        ReviewField("Authentication factors", payload.factors.joined(separator: " + "))
                        ReviewField("Operation", payload.operation)
                        ReviewField("Access after login", payload.sessionActionProfile)
                        ReviewField("Broker / boot epoch", payload.brokerID + "\n" + payload.bootEpoch)
                        ReviewField("Owner / device", payload.ownerID + "\n" + payload.deviceID)
                        ReviewField("Request / revision", payload.requestID + " / " + String(payload.revision))
                        ReviewField("Workload", payload.workloadID)
                        ReviewField("Runtime / generation", payload.runtimeID + " / " + String(payload.runtimeGeneration))
                        ReviewField("Credential binding version", String(payload.credentialBindingVersion))
                        ReviewField("Adapter / version", payload.adapterID + " / " + payload.adapterVersion)
                        ReviewField("Policy / version", payload.policyID + " / " + String(payload.policyVersion))
                        ReviewField("Issued", payload.issuedAt)
                        ReviewField("Expires", payload.expiresAt)
                        ReviewField("Nonce", payload.nonce)
                        ReviewField("Purpose", payload.purpose)
                        ReviewField("Purpose digest", payload.reviewDigest)
                        ReviewField("Signed payload SHA-256", challenge.digest)
                    }
                }
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                VStack(spacing: 10) {
                    if store.busy { ProgressView("Approving this request…") }
                    Button { store.approve(challenge) } label: {
                        Label("Approve with biometrics", systemImage: "faceid")
                            .font(.headline).frame(maxWidth: .infinity).padding(.vertical, 7)
                    }.buttonStyle(.borderedProminent).controlSize(.large)
                        .disabled(store.busy || !store.foreground)
                    Button("Deny request", role: .destructive) { store.deny(challenge) }
                        .disabled(store.busy || !store.foreground)
                    Text("One approval. This exact request only.")
                        .font(.caption).foregroundStyle(.secondary)
                }.padding(.horizontal, 20).padding(.top, 14).padding(.bottom, 10)
                    .frame(maxWidth: .infinity).background(.bar)
            }
            .navigationTitle("Review request").navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Close", systemImage: "xmark") { dismiss() }.disabled(store.busy)
                }
            }
            .interactiveDismissDisabled(store.busy)
            .overlay { if store.privacyCovered { PrivacyCover() } }
        }
    }
}

private struct DeviceDetailsView: View {
    @ObservedObject var store: ApprovalStore
    let enrollment: Enrollment
    @Environment(\.dismiss) private var dismiss
    @State private var confirmErase = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Connection") {
                    ReviewField("Status", store.status)
                    ReviewField("Broker", enrollment.brokerURL.absoluteString)
                    FingerprintView(title: "Certificate SHA-256", fingerprint: enrollment.certificateFingerprint)
                }
                Section("Approval device") {
                    FingerprintView(title: "Approval key SHA-256", fingerprint: enrollment.publicKeyFingerprint)
                    ReviewField("Broker ID", enrollment.brokerID)
                    ReviewField("Device ID", enrollment.deviceID)
                }
                Section {
                    Button("Refresh connection") { Task { await store.refresh() } }.disabled(store.busy)
                    Button("Remove this pairing", role: .destructive) { confirmErase = true }.disabled(store.busy)
                } footer: {
                    Text("Removing this pairing deletes its key on this phone. Revoke the device separately in the owner console.")
                }
            }
            .navigationTitle("Device details").navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .topBarTrailing) { Button("Done") { dismiss() } } }
            .alert("Remove device key and pairing?", isPresented: $confirmErase) {
                Button("Remove", role: .destructive) { store.eraseLocalPairing(); dismiss() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This removes the device signing key and token. Revoke the broker's device record separately in the owner console.")
            }
            .overlay { if store.privacyCovered { PrivacyCover() } }
        }
    }
}

private struct ReviewField: View {
    let title: String
    let value: String

    init(_ title: String, _ value: String) { self.title = title; self.value = value }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }.padding(.vertical, 2)
    }
}

private struct FingerprintView: View {
    let title: String
    let fingerprint: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(fingerprint).font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
        }.padding(.vertical, 3)
    }
}

private struct NoticeView: View {
    let message: String

    private var displayMessage: String {
        switch message {
        case "The broker accepted the signed approval. Authentication status is managed by the broker.":
            "Approval sent. Your broker is handling the sign-in."
        case "The broker accepted the denial.": "Request denied."
        case "Owner: confirm this device in the broker administration interface before it can approve requests.":
            "Waiting for the owner to confirm this device."
        case "HTTPS system trust and the entered certificate pin passed. Owner verification, pairing and separate confirmation are still required.":
            "HTTPS connection verified. Compare the fingerprint before continuing."
        default: message
        }
    }

    var body: some View {
        Label {
            Text(displayMessage).font(.subheadline).fixedSize(horizontal: false, vertical: true)
        } icon: {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
        }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        Color(.systemBackground).ignoresSafeArea()
            .overlay { Label("Broker Approval", systemImage: "lock.shield") }
    }
}
