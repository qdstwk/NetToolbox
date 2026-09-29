import SwiftUI
import Foundation
import Combine
import Security
#if canImport(UIKit)
import UIKit
#endif


#if canImport(UIKit)
/// Process-level foreground kill switch for the one active SSH transport.
///
/// This does not wait for SwiftUI view updates. UIKit lifecycle notifications
/// are delivered synchronously to this observer (queue: nil), and the current
/// transport is force-closed inside that notification callback.
private final class PrivateTailnetSSHForegroundGuard: @unchecked Sendable {
    static let shared = PrivateTailnetSSHForegroundGuard()

    private let lock = NSLock()
    private var client: IntegratedSSHClient?
    private var observers: [NSObjectProtocol] = []

    private init() {
        let center = NotificationCenter.default
        let names: [Notification.Name] = [
            UIScene.willDeactivateNotification,
            UIApplication.willResignActiveNotification,
            UIScene.didEnterBackgroundNotification,
            UIApplication.didEnterBackgroundNotification
        ]

        observers = names.map { name in
            center.addObserver(
                forName: name,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                self?.forceCloseImmediately()
            }
        }
    }

    func arm(_ client: IntegratedSSHClient) {
        lock.lock()
        self.client = client
        lock.unlock()
    }

    func disarm(_ client: IntegratedSSHClient) {
        lock.lock()
        if self.client === client {
            self.client = nil
        }
        lock.unlock()
    }

    func forceCloseImmediately() {
        lock.lock()
        let client = self.client
        self.client = nil
        lock.unlock()

        // NWConnection cancellation happens here, synchronously with the
        // lifecycle callback. UI cleanup may render later, but the network
        // authority is already revoked.
        client?.close()
    }
}
#endif

private enum PrivateTailnetSSHMode: String, CaseIterable, Identifiable {
    case exec = "Command"
    case shell = "Shell"

    var id: String { rawValue }
}

private enum PrivateTailnetSSHAppKeyboardTarget: String {
    case profileLabel
    case profileHost
    case profileUsername
    case password
    case command
    case shellInput

    var title: String {
        switch self {
        case .profileLabel: return "Label"
        case .profileHost: return "Tailnet IPv4"
        case .profileUsername: return "Username"
        case .password: return "SSH password"
        case .command: return "Command"
        case .shellInput: return "Shell input"
        }
    }

    var belongsToProfileEditor: Bool {
        switch self {
        case .profileLabel, .profileHost, .profileUsername: return true
        case .password, .command, .shellInput: return false
        }
    }
}

/// App-owned fallback keyboard for Swift Playgrounds App Preview.
///
/// It never reads hardware/system keyboard events and never touches the
/// clipboard. Each key is an ordinary SwiftUI Button that mutates only the
/// selected in-memory field.
private struct PrivateTailnetSSHAppKeyboard: View {
    private enum Page {
        case letters
        case numbers
        case symbols
    }

    let targetTitle: String
    let append: (String) -> Void
    let backspace: () -> Void
    let clear: () -> Void
    let dismiss: () -> Void

    @State private var page: Page = .letters
    @State private var shifted = false

    private let lowercaseRows: [[String]] = [
        ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
        ["a", "s", "d", "f", "g", "h", "j", "k", "l"],
        ["z", "x", "c", "v", "b", "n", "m"]
    ]

    private let uppercaseRows: [[String]] = [
        ["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"],
        ["A", "S", "D", "F", "G", "H", "J", "K", "L"],
        ["Z", "X", "C", "V", "B", "N", "M"]
    ]

    private let numberRows: [[String]] = [
        ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
        ["-", "_", ".", "/", ":", "@", "~", "$", "&", "|"],
        ["(", ")", "[", "]", "{", "}", "+", "=", "*", "?"]
    ]

    private let symbolRows: [[String]] = [
        ["!", "\"", "#", "$", "%", "&", "'", "(", ")", "*"],
        ["+", ",", "-", ".", "/", ":", ";", "<", "=", ">"],
        ["?", "@", "[", "\\", "]", "^", "_", "`", "{", "|"],
        ["}", "~"]
    ]

    private var rows: [[String]] {
        switch page {
        case .letters:
            return shifted ? uppercaseRows : lowercaseRows
        case .numbers:
            return numberRows
        case .symbols:
            return symbolRows
        }
    }

    var body: some View {
        VStack(spacing: 8) {
            HStack {
                Image(systemName: "keyboard")
                Text("App Keyboard · \(targetTitle)")
                    .font(.headline)
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(.bordered)
            }

            ForEach(Array(rows.enumerated()), id: \.offset) { _, row in
                HStack(spacing: 6) {
                    ForEach(Array(row.enumerated()), id: \.offset) { _, key in
                        Button {
                            append(key)
                            if shifted && page == .letters {
                                shifted = false
                            }
                        } label: {
                            Text(key)
                                .font(.body.monospaced())
                                .frame(maxWidth: .infinity, minHeight: 38)
                        }
                        .buttonStyle(.bordered)
                    }
                }
            }

            HStack(spacing: 6) {
                Button {
                    shifted.toggle()
                    page = .letters
                } label: {
                    Image(systemName: shifted ? "shift.fill" : "shift")
                        .frame(minWidth: 34, minHeight: 36)
                }
                .buttonStyle(.bordered)

                Button("ABC") {
                    page = .letters
                    shifted = false
                }
                .buttonStyle(.bordered)

                Button("123") {
                    page = .numbers
                    shifted = false
                }
                .buttonStyle(.bordered)

                Button("#+=") {
                    page = .symbols
                    shifted = false
                }
                .buttonStyle(.bordered)

                Button("Space") { append(" ") }
                    .buttonStyle(.bordered)
                    .frame(maxWidth: .infinity)

                Button {
                    backspace()
                } label: {
                    Image(systemName: "delete.left")
                        .frame(minWidth: 34, minHeight: 36)
                }
                .buttonStyle(.bordered)

                Button("Clear", role: .destructive) { clear() }
                    .buttonStyle(.bordered)
            }

            Text("Fallback input only · no clipboard · no key logging · no persistence")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .padding(10)
        .background(.regularMaterial)
        .overlay(alignment: .top) { Divider() }
    }
}

private enum PrivateTailnetSSHProfilePersistence {
    // Deliberately use a local-only Keychain item instead of UserDefaults.
    // Swift Playgrounds App Preview did not preserve the UserDefaults-backed
    // profile across a stop/re-run live test. The profile contains no login
    // password, but the exact Host Key pin is a security anchor and benefits
    // from durable, non-synchronizing local storage.
    private static let service = "PrivateTailnetSSH.profile-store.v1"
    private static let account = "profiles"

    static func load() -> [SSHConnectionProfile] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let decoded = try? JSONDecoder().decode([SSHConnectionProfile].self, from: data)
        else {
            return []
        }

        // Fail closed on stale/invalid records. v1 permits only canonical
        // 100.64.0.0/10 IPv4, fixed port 22, a non-empty username, and any
        // persisted pin must be bound to this exact host+port.
        return decoded.filter { profile in
            guard profile.port == 22,
                  SSHTailnetDestinationPolicy.allows(profile.host),
                  SSHTailnetDestinationPolicy.canonicalIPv4(profile.host) == profile.host,
                  !profile.username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            else {
                return false
            }

            if let pin = profile.pinnedHostKey {
                return pin.host == profile.host && pin.port == profile.port
            }
            return true
        }
    }

    static func save(_ profiles: [SSHConnectionProfile]) {
        guard let data = try? JSONEncoder().encode(profiles) else { return }

        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let update: [String: Any] = [
            kSecValueData as String: data,
            // v1 is explicitly local-only: do not make the trust database
            // migratable or synchronizable to another device.
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(
            identity as CFDictionary,
            update as CFDictionary
        )

        if updateStatus == errSecItemNotFound {
            var add = identity
            add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            add[kSecAttrSynchronizable as String] = kCFBooleanFalse
            _ = SecItemAdd(add as CFDictionary, nil)
        }
    }
}

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase

    @State private var profiles: [SSHConnectionProfile]
    @State private var selectedProfileID: UUID?

    @State private var showProfileEditor = false
    @State private var editingProfileID: UUID?
    @State private var editLabel = ""
    @State private var editHost = ""
    @State private var editUsername = ""
    @State private var profileEditorError = ""

    @State private var pendingHostKey: PinnedSSHHostKey?
    @State private var showResetPinConfirmation = false
    @State private var showDeleteProfileConfirmation = false

    @State private var mode: PrivateTailnetSSHMode = .exec
    @State private var password = ""
    @State private var command = ""
    @State private var execOutput = ""
    @State private var execExitStatus: Int?

    @State private var shellTranscript = ""
    @State private var shellInput = ""
    @State private var shellConnected = false
    @State private var shellReadTask: Task<Void, Never>?

    @State private var activeClient: IntegratedSSHClient?
    @State private var isBusy = false
    @State private var status = "Select or add a saved Tailnet host. No network connection starts automatically."
    @State private var appKeyboardTarget: PrivateTailnetSSHAppKeyboardTarget?

    init() {
        let loaded = PrivateTailnetSSHProfilePersistence.load()
        _profiles = State(initialValue: loaded)
        _selectedProfileID = State(initialValue: loaded.first?.id)
    }

    private var selectedProfile: SSHConnectionProfile? {
        guard let selectedProfileID else { return nil }
        return profiles.first(where: { $0.id == selectedProfileID })
    }

    private var controlsLocked: Bool {
        isBusy || shellConnected
    }

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedProfileID) {
                Section("Saved Tailnet hosts") {
                    if profiles.isEmpty {
                        Text("No saved hosts")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(profiles) { profile in
                            VStack(alignment: .leading, spacing: 3) {
                                Text(profile.label.isEmpty ? profile.host : profile.label)
                                Text("\(profile.username)@\(profile.host):22")
                                    .font(.caption.monospaced())
                                    .foregroundStyle(.secondary)
                            }
                            .tag(profile.id)
                        }
                    }
                }
            }
            .disabled(controlsLocked)
            .navigationTitle("PrivateTailnetSSH")
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button {
                        beginAddProfile()
                    } label: {
                        Label("Add host", systemImage: "plus")
                    }
                    .disabled(controlsLocked)
                }
            }
        } detail: {
            if let profile = selectedProfile {
                sessionView(profile)
            } else {
                ContentUnavailableView(
                    "No host selected",
                    systemImage: "terminal",
                    description: Text("Add a Tailnet host profile. Saving/selecting a profile never opens a network connection.")
                )
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            if let target = appKeyboardTarget,
               !target.belongsToProfileEditor,
               !showProfileEditor {
                appKeyboardPanel(for: target)
            }
        }
        .sheet(isPresented: $showProfileEditor) {
            profileEditor
        }
        .confirmationDialog(
            "Reset saved Host Key pin?",
            isPresented: $showResetPinConfirmation,
            titleVisibility: .visible
        ) {
            Button("Reset Host Key pin", role: .destructive) {
                resetSelectedPin()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("After reset, password entry is blocked until the server Host Key is verified and explicitly trusted again.")
        }
        .confirmationDialog(
            "Delete this host profile?",
            isPresented: $showDeleteProfileConfirmation,
            titleVisibility: .visible
        ) {
            Button("Delete host", role: .destructive) {
                deleteSelectedProfile()
            }
            Button("Cancel", role: .cancel) {}
        }
        .onChange(of: selectedProfileID) { _, _ in
            clearTransientStateForProfileChange()
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase != .active else { return }
            handleForegroundLoss(source: "SwiftUI scenePhase=\(phase)")
        }
#if canImport(UIKit)
        // Swift Playgrounds App Preview did not reliably propagate SwiftUI
        // scenePhase during the first live background test. Listen directly
        // to UIKit lifecycle notifications as an independent fail-closed path.
        // willDeactivate fires before backgrounding and also for interruptions;
        // that conservatism is intentional for this foreground-only admin tool.
        .onReceive(NotificationCenter.default.publisher(for: UIScene.willDeactivateNotification)) { _ in
            handleForegroundLoss(source: "UIScene.willDeactivate")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIScene.didEnterBackgroundNotification)) { _ in
            handleForegroundLoss(source: "UIScene.didEnterBackground")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.willResignActiveNotification)) { _ in
            handleForegroundLoss(source: "UIApplication.willResignActive")
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didEnterBackgroundNotification)) { _ in
            handleForegroundLoss(source: "UIApplication.didEnterBackground")
        }
#endif
        .onDisappear {
            forceLocalShutdown("DISCONNECTED: PrivateTailnetSSH view closed.")
        }
    }

    @ViewBuilder
    private func sessionView(_ profile: SSHConnectionProfile) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header(profile)
                profileSecurityCard(profile)
                operationCard(profile)
                statusCard

                if mode == .exec, !execOutput.isEmpty || execExitStatus != nil {
                    execResultCard
                }

                if mode == .shell {
                    shellCard(profile)
                }
            }
            .padding(20)
            .frame(maxWidth: 900)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .navigationTitle(profile.label.isEmpty ? profile.host : profile.label)
    }

    @ViewBuilder
    private func header(_ profile: SSHConnectionProfile) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(profile.label.isEmpty ? profile.host : profile.label)
                        .font(.title2.bold())
                    Text("\(profile.username)@\(profile.host):22")
                        .font(.body.monospaced())
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Menu {
                    Button {
                        beginEditProfile(profile)
                    } label: {
                        Label("Edit profile", systemImage: "pencil")
                    }

                    if profile.pinnedHostKey != nil {
                        Button(role: .destructive) {
                            showResetPinConfirmation = true
                        } label: {
                            Label("Reset Host Key pin", systemImage: "key.slash")
                        }
                    }

                    Button(role: .destructive) {
                        showDeleteProfileConfirmation = true
                    } label: {
                        Label("Delete profile", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                        .font(.title3)
                }
                .disabled(controlsLocked)
            }

            Text("v1 network scope: canonical Tailnet IPv4 only · SSH port 22 fixed · no auto-connect · foreground only")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func profileSecurityCard(_ profile: SSHConnectionProfile) -> some View {
        GroupBox("Server identity") {
            VStack(alignment: .leading, spacing: 12) {
                if let pin = profile.pinnedHostKey {
                    Label("Exact Host Key pin saved", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                    Text(pin.keyType)
                        .font(.caption.monospaced())
                    Text(pin.fingerprint)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)

                    Text("Every real-password connection must match this exact host+port+key type+key blob before user authentication.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Label("No trusted Host Key yet", systemImage: "exclamationmark.shield")
                        .foregroundStyle(.orange)

                    Text("Password entry stays disabled. Verify the server identity first; the preflight uses a non-secret sentinel and must stop before password authentication.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Button {
                        Task { await verifyFirstUseHostKey(profile) }
                    } label: {
                        Label("Verify Host Key", systemImage: "checkmark.shield")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isBusy || shellConnected)
                }

                if let pendingHostKey {
                    Divider()
                    Label("Verified first-use Host Key — explicit trust required", systemImage: "key.fill")
                        .foregroundStyle(.orange)
                    Text(pendingHostKey.keyType)
                        .font(.caption.monospaced())
                    Text(pendingHostKey.fingerprint)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)

                    HStack {
                        Button {
                            trustPendingHostKey(profile)
                        } label: {
                            Label("Trust & save exact key", systemImage: "checkmark.seal.fill")
                        }
                        .buttonStyle(.borderedProminent)

                        Button("Discard", role: .cancel) {
                            self.pendingHostKey = nil
                            status = "First-use Host Key was not trusted. Password entry remains blocked."
                        }
                        .buttonStyle(.bordered)
                    }
                    .disabled(isBusy || shellConnected)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func operationCard(_ profile: SSHConnectionProfile) -> some View {
        GroupBox("Connection") {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Mode", selection: $mode) {
                    ForEach(PrivateTailnetSSHMode.allCases) { item in
                        Text(item.rawValue).tag(item)
                    }
                }
                .pickerStyle(.segmented)
                .disabled(shellConnected || isBusy)

                HStack(spacing: 8) {
                    SecureField("SSH password — transient, local only", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                        .disabled(profile.pinnedHostKey == nil || controlsLocked)

                    appKeyboardButton(
                        .password,
                        disabled: profile.pinnedHostKey == nil || controlsLocked
                    )
                }

                Text("The password is never persisted in the profile. It is cleared from UI state before network authentication begins and again on completion/background/disconnect. Swift String memory is not formally zeroizable.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if mode == .exec {
                    HStack(alignment: .top, spacing: 8) {
                        TextField("Command", text: $command, axis: .vertical)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                            .disabled(controlsLocked)
                            .lineLimit(1...4)

                        appKeyboardButton(.command, disabled: controlsLocked)
                    }

                    Button {
                        Task { await runExec(profile) }
                    } label: {
                        Label(isBusy ? "Running…" : "Run command", systemImage: "play.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        profile.pinnedHostKey == nil ||
                        password.isEmpty ||
                        command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                        controlsLocked
                    )
                } else if !shellConnected {
                    Button {
                        Task { await connectShell(profile) }
                    } label: {
                        Label(isBusy ? "Connecting…" : "Connect shell", systemImage: "terminal")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(
                        profile.pinnedHostKey == nil ||
                        password.isEmpty ||
                        controlsLocked
                    )
                }

                if isBusy {
                    ProgressView()
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var statusCard: some View {
        GroupBox("Status") {
            Text(status)
                .font(.body.monospaced())
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var execResultCard: some View {
        GroupBox("Command result") {
            VStack(alignment: .leading, spacing: 10) {
                if let execExitStatus {
                    Text("exit-status: \(execExitStatus)")
                        .font(.caption.monospaced())
                }

                ScrollView(.horizontal) {
                    Text(execOutput.isEmpty ? "(no stdout/stderr text returned)" : execOutput)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    @ViewBuilder
    private func shellCard(_ profile: SSHConnectionProfile) -> some View {
        GroupBox("Interactive shell") {
            VStack(alignment: .leading, spacing: 12) {
                ScrollView {
                    Text(shellTranscript.isEmpty ? "(shell connected; waiting for output)" : shellTranscript)
                        .font(.body.monospaced())
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                }
                .frame(minHeight: 260, maxHeight: 520)
                .padding(10)
                .background(.black.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))

                if shellConnected {
                    HStack {
                        TextField("Shell input", text: $shellInput)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                            .onSubmit {
                                Task { await sendShellLine() }
                            }

                        appKeyboardButton(.shellInput, disabled: false)

                        Button {
                            Task { await sendShellLine() }
                        } label: {
                            Image(systemName: "return")
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(shellInput.isEmpty)
                    }

                    Button("Disconnect shell", role: .destructive) {
                        disconnectShell(reason: "Shell disconnected by user.")
                    }
                    .buttonStyle(.bordered)
                } else {
                    Text("No shell session is active.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var profileEditor: some View {
        NavigationStack {
            Form {
                Section("Saved host") {
                    HStack(spacing: 8) {
                        TextField("Label", text: $editLabel)
                        appKeyboardButton(.profileLabel, disabled: false)
                    }

                    HStack(spacing: 8) {
                        TextField("Tailnet IPv4", text: $editHost)
                            .font(.body.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                            .keyboardType(.numbersAndPunctuation)
                        appKeyboardButton(.profileHost, disabled: false)
                    }

                    HStack(spacing: 8) {
                        TextField("Username", text: $editUsername)
                            .font(.body.monospaced())
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled(true)
                        appKeyboardButton(.profileUsername, disabled: false)
                    }

                    LabeledContent("SSH port", value: "22 (fixed in v1)")
                }

                Section {
                    Text("Profiles persist only label, canonical Tailnet IPv4, port 22, username and the exact Host Key pin. Passwords are never saved.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                if !profileEditorError.isEmpty {
                    Section {
                        Text(profileEditorError)
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(editingProfileID == nil ? "Add host" : "Edit host")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        appKeyboardTarget = nil
                        showProfileEditor = false
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        saveProfileEditor()
                    }
                }
            }
            .safeAreaInset(edge: .bottom, spacing: 0) {
                if let target = appKeyboardTarget,
                   target.belongsToProfileEditor {
                    appKeyboardPanel(for: target)
                }
            }
        }
    }

    @ViewBuilder
    private func appKeyboardButton(
        _ target: PrivateTailnetSSHAppKeyboardTarget,
        disabled: Bool
    ) -> some View {
        Button {
            appKeyboardTarget = appKeyboardTarget == target ? nil : target
        } label: {
            Image(systemName: "keyboard")
        }
        .buttonStyle(.bordered)
        .disabled(disabled)
        .accessibilityLabel("App keyboard for \(target.title)")
    }

    @ViewBuilder
    private func appKeyboardPanel(
        for target: PrivateTailnetSSHAppKeyboardTarget
    ) -> some View {
        PrivateTailnetSSHAppKeyboard(
            targetTitle: target.title,
            append: { appendAppKeyboardText($0, to: target) },
            backspace: { backspaceAppKeyboardTarget(target) },
            clear: { clearAppKeyboardTarget(target) },
            dismiss: { appKeyboardTarget = nil }
        )
    }

    private func appendAppKeyboardText(
        _ text: String,
        to target: PrivateTailnetSSHAppKeyboardTarget
    ) {
        switch target {
        case .profileLabel: editLabel += text
        case .profileHost: editHost += text
        case .profileUsername: editUsername += text
        case .password: password += text
        case .command: command += text
        case .shellInput: shellInput += text
        }
    }

    private func backspaceAppKeyboardTarget(
        _ target: PrivateTailnetSSHAppKeyboardTarget
    ) {
        switch target {
        case .profileLabel:
            if !editLabel.isEmpty { editLabel.removeLast() }
        case .profileHost:
            if !editHost.isEmpty { editHost.removeLast() }
        case .profileUsername:
            if !editUsername.isEmpty { editUsername.removeLast() }
        case .password:
            if !password.isEmpty { password.removeLast() }
        case .command:
            if !command.isEmpty { command.removeLast() }
        case .shellInput:
            if !shellInput.isEmpty { shellInput.removeLast() }
        }
    }

    private func clearAppKeyboardTarget(
        _ target: PrivateTailnetSSHAppKeyboardTarget
    ) {
        switch target {
        case .profileLabel: editLabel = ""
        case .profileHost: editHost = ""
        case .profileUsername: editUsername = ""
        case .password: password = ""
        case .command: command = ""
        case .shellInput: shellInput = ""
        }
    }

    private func beginAddProfile() {
        editingProfileID = nil
        editLabel = ""
        editHost = ""
        editUsername = ""
        profileEditorError = ""
        appKeyboardTarget = nil
        showProfileEditor = true
    }

    private func beginEditProfile(_ profile: SSHConnectionProfile) {
        editingProfileID = profile.id
        editLabel = profile.label
        editHost = profile.host
        editUsername = profile.username
        profileEditorError = ""
        appKeyboardTarget = nil
        showProfileEditor = true
    }

    private func saveProfileEditor() {
        let trimmedHost = editHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedUser = editUsername.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedLabel = editLabel.trimmingCharacters(in: .whitespacesAndNewlines)

        guard SSHTailnetDestinationPolicy.allows(trimmedHost),
              let canonical = SSHTailnetDestinationPolicy.canonicalIPv4(trimmedHost),
              canonical == trimmedHost
        else {
            profileEditorError = "Host must be a canonical Tailnet IPv4 address in 100.64.0.0/10. DNS, MagicDNS, IPv6, LAN and public IPv4 are rejected in v1."
            return
        }

        guard !trimmedUser.isEmpty else {
            profileEditorError = "Username is required."
            return
        }

        let label = trimmedLabel.isEmpty ? canonical : trimmedLabel

        if let editingProfileID,
           let index = profiles.firstIndex(where: { $0.id == editingProfileID }) {
            let old = profiles[index]
            let preservePin = old.host == canonical && old.port == 22
            profiles[index] = SSHConnectionProfile(
                id: old.id,
                label: label,
                host: canonical,
                port: 22,
                username: trimmedUser,
                pinnedHostKey: preservePin ? old.pinnedHostKey : nil
            )
            selectedProfileID = old.id

            if !preservePin {
                pendingHostKey = nil
                password = ""
                status = "Host address changed. Previous Host Key pin was cleared; verify and explicitly trust the new server identity before authentication."
            }
        } else {
            let profile = SSHConnectionProfile(
                label: label,
                host: canonical,
                port: 22,
                username: trimmedUser,
                pinnedHostKey: nil
            )
            profiles.insert(profile, at: 0)
            selectedProfileID = profile.id
            status = "Host profile saved. No network connection was opened. Verify the Host Key before entering a password."
        }

        PrivateTailnetSSHProfilePersistence.save(profiles)
        appKeyboardTarget = nil
        showProfileEditor = false
    }

    private func deleteSelectedProfile() {
        guard let selectedProfileID else { return }
        forceLocalShutdown("Profile deleted. Any active transport was force-closed.")
        profiles.removeAll { $0.id == selectedProfileID }
        PrivateTailnetSSHProfilePersistence.save(profiles)
        self.selectedProfileID = profiles.first?.id
    }

    private func resetSelectedPin() {
        guard let selectedProfileID,
              let index = profiles.firstIndex(where: { $0.id == selectedProfileID })
        else { return }

        forceLocalShutdown("Host Key pin reset. Password entry is blocked until first-use verification and explicit trust are completed again.")
        profiles[index].pinnedHostKey = nil
        PrivateTailnetSSHProfilePersistence.save(profiles)
        pendingHostKey = nil
        password = ""
    }

    @MainActor
    private func verifyFirstUseHostKey(_ profile: SSHConnectionProfile) async {
        guard profile.pinnedHostKey == nil else {
            status = "This profile already has an exact Host Key pin."
            return
        }

        isBusy = true
        pendingHostKey = nil
        password = ""
        status = "Verifying SSH Host Key signature/possession. Real password authentication is not permitted in this step."

        guard let client = IntegratedSSHClient(
            host: profile.host,
            port: profile.port,
            pinnedHostKey: nil
        ) else {
            isBusy = false
            status = "FAIL: destination was rejected before TCP connect."
            return
        }

        activeClient = client
#if canImport(UIKit)
        PrivateTailnetSSHForegroundGuard.shared.arm(client)
#endif
        defer {
#if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
            if activeClient === client { activeClient = nil }
            isBusy = false
        }

        do {
            _ = try await client.run(
                username: profile.username,
                auth: .password("__PRIVATE_TAILNET_SSH_FIRST_USE_PREFLIGHT__"),
                command: "true",
                timeout: 10
            )
            status = "CRITICAL FAIL: first-use confirmation gate was bypassed. Do not enter a real password."
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            guard key.host == profile.host,
                  key.port == profile.port
            else {
                status = "HARD FAIL: verified Host Key was returned for an unexpected host/port binding."
                return
            }

            pendingHostKey = key
            status = "PASS: server Host Key signature/possession verified. Inspect the fingerprint and explicitly trust the exact key before password entry is enabled."
        } catch SSHError.authFailed {
            status = "CRITICAL FAIL: first-use sentinel reached password authentication. Do not enter a real password."
        } catch {
            status = "FAIL during Host Key preflight at Core stage \(client.stage): \(String(reflecting: error))"
        }
    }

    private func trustPendingHostKey(_ profile: SSHConnectionProfile) {
        guard let key = pendingHostKey,
              key.host == profile.host,
              key.port == profile.port,
              let index = profiles.firstIndex(where: { $0.id == profile.id })
        else {
            status = "HARD FAIL: pending Host Key no longer matches the selected profile."
            pendingHostKey = nil
            return
        }

        profiles[index].pinnedHostKey = key
        PrivateTailnetSSHProfilePersistence.save(profiles)
        pendingHostKey = nil
        password = ""
        status = "Exact Host Key pin saved locally. No SSH session is active. Enter the transient password only when you are ready to run a command or open a shell."
    }

    @MainActor
    private func runExec(_ profile: SSHConnectionProfile) async {
        guard let pin = profile.pinnedHostKey else {
            status = "STOP: no exact Host Key pin is stored for this profile."
            return
        }

        let trimmedCommand = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedCommand.isEmpty else {
            status = "STOP: enter a command first."
            return
        }

        guard !password.isEmpty else {
            status = "STOP: enter the transient SSH password locally."
            return
        }

        isBusy = true
        execOutput = ""
        execExitStatus = nil

        let enteredPassword = password
        password = ""

        guard let client = IntegratedSSHClient(
            host: profile.host,
            port: profile.port,
            pinnedHostKey: pin
        ) else {
            isBusy = false
            status = "FAIL: destination was rejected before TCP connect."
            return
        }

        activeClient = client
#if canImport(UIKit)
        PrivateTailnetSSHForegroundGuard.shared.arm(client)
#endif
        status = "Connecting to the exact pinned Host Key and running one command…"

        defer {
#if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
            if activeClient === client { activeClient = nil }
            password = ""
            isBusy = false
        }

        do {
            let result = try await client.run(
                username: profile.username,
                auth: .password(enteredPassword),
                command: trimmedCommand,
                timeout: 10
            )

            guard result.hostKeyVerified,
                  result.hostKeyType == pin.keyType,
                  result.fingerprint == pin.fingerprint
            else {
                status = "CRITICAL FAIL: command returned without the expected verified Host Key identity."
                return
            }

            execOutput = result.output
            execExitStatus = result.exitStatus
            status = "PASS: command completed after exact Host Key verification and real-password authentication. Transport closed."
        } catch SSHError.hostKeyChanged {
            status = "HARD FAIL: Host Key changed. Password authentication/command execution was blocked. Do not accept a replacement key from this error path; reset the saved pin only after independent verification."
        } catch SSHError.authFailed {
            status = "FAIL: server rejected password authentication. Password field was cleared."
        } catch SSHError.execTimeout {
            status = "FAIL: exec exceeded the hard deadline; transport was force-closed."
        } catch SSHError.concurrentSession {
            status = "FAIL CLOSED: another SSH session is already active."
        } catch {
            status = "FAIL at Core stage \(client.stage): \(String(reflecting: error))"
        }
    }

    @MainActor
    private func connectShell(_ profile: SSHConnectionProfile) async {
        guard let pin = profile.pinnedHostKey else {
            status = "STOP: no exact Host Key pin is stored for this profile."
            return
        }

        guard !password.isEmpty else {
            status = "STOP: enter the transient SSH password locally."
            return
        }

        isBusy = true
        shellTranscript = ""
        shellInput = ""

        let enteredPassword = password
        password = ""

        guard let client = IntegratedSSHClient(
            host: profile.host,
            port: profile.port,
            pinnedHostKey: pin
        ) else {
            isBusy = false
            status = "FAIL: destination was rejected before TCP connect."
            return
        }

        activeClient = client
#if canImport(UIKit)
        PrivateTailnetSSHForegroundGuard.shared.arm(client)
#endif
        status = "Opening one exact-pin authenticated PTY/shell session…"

        do {
            try await client.openShell(
                username: profile.username,
                auth: .password(enteredPassword),
                timeout: 10
            )

            shellConnected = true
            isBusy = false
            status = "Shell connected. One reader task is active. Leaving the app foreground will force-disconnect immediately."
            startShellReader(client)
        } catch SSHError.hostKeyChanged {
#if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
            activeClient = nil
            isBusy = false
            status = "HARD FAIL: Host Key changed before shell authentication."
        } catch SSHError.authFailed {
#if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
            activeClient = nil
            isBusy = false
            status = "FAIL: server rejected password authentication. Password field was cleared."
        } catch SSHError.shellSetupTimeout {
#if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
            activeClient = nil
            isBusy = false
            status = "FAIL: PTY/shell setup exceeded the hard deadline; transport was force-closed."
        } catch {
#if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
            activeClient = nil
            isBusy = false
            status = "FAIL during shell setup at Core stage \(client.stage): \(String(reflecting: error))"
        }
    }

    @MainActor
    private func startShellReader(_ client: IntegratedSSHClient) {
        shellReadTask?.cancel()
        shellReadTask = Task { @MainActor in
            do {
                while !Task.isCancelled {
                    guard let chunk = try await client.readShellChunk() else { break }
                    shellTranscript += chunk

                    if shellTranscript.utf8.count > 262_144 {
                        status = "FAIL CLOSED: shell transcript exceeded 256 KiB UI safety limit; transport was force-closed."
            #if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
                        break
                    }
                }
            } catch {
                if activeClient === client {
                    status = "Shell reader ended: \(String(reflecting: error))"
                }
            }

            if activeClient === client {
    #if canImport(UIKit)
            PrivateTailnetSSHForegroundGuard.shared.disarm(client)
#endif
            client.close()
                activeClient = nil
                shellConnected = false
                password = ""
                shellInput = ""
                if !status.hasPrefix("FAIL CLOSED") {
                    status = "Shell ended and transport closed."
                }
            }
        }
    }

    @MainActor
    private func sendShellLine() async {
        guard shellConnected,
              let client = activeClient
        else {
            status = "STOP: no shell session is active."
            return
        }

        let line = shellInput
        guard !line.isEmpty else { return }
        shellInput = ""

        do {
            try await client.sendShell(line + "\n")
        } catch {
            status = "FAIL sending shell input: \(String(reflecting: error))"
            disconnectShell(reason: "Shell transport closed after send failure.")
        }
    }

    private func disconnectShell(reason: String) {
        shellReadTask?.cancel()
        shellReadTask = nil
#if canImport(UIKit)
        PrivateTailnetSSHForegroundGuard.shared.forceCloseImmediately()
#else
        activeClient?.close()
#endif
        activeClient = nil
        shellConnected = false
        isBusy = false
        password = ""
        shellInput = ""
        status = reason
    }

    private func handleForegroundLoss(source: String) {
        // Idempotent by design: SwiftUI and UIKit may report the same
        // transition. Any one signal is enough to tear down the transport.
        let hadActiveSSH = activeClient != nil || shellConnected || isBusy
        forceLocalShutdown(
            hadActiveSSH
            ? "DISCONNECTED: foreground control was lost (\(source)). SSH transport was force-closed; password and transient trust state were cleared."
            : "Foreground control was lost (\(source)). No SSH session was active; transient password/trust state was cleared."
        )
    }

    private func forceLocalShutdown(_ reason: String) {
        shellReadTask?.cancel()
        shellReadTask = nil
#if canImport(UIKit)
        PrivateTailnetSSHForegroundGuard.shared.forceCloseImmediately()
#else
        activeClient?.close()
#endif
        activeClient = nil
        shellConnected = false
        isBusy = false

        password = ""
        pendingHostKey = nil
        shellInput = ""
        appKeyboardTarget = nil

        status = reason
    }

    private func clearTransientStateForProfileChange() {
        // Selection itself is never allowed to start a connection.
        password = ""
        pendingHostKey = nil
        execOutput = ""
        execExitStatus = nil
        shellTranscript = ""
        shellInput = ""
        appKeyboardTarget = nil
        status = "Profile selected. No network connection started."
    }
}
