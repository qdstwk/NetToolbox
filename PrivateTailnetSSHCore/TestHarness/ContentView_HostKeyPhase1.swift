import SwiftUI

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    // Phase 1 only: discover and display the server Host Key.
    // The Core must throw hostKeyConfirmationRequired BEFORE authentication,
    // so this placeholder must never be transmitted on a first-use connection.
    private let host = "100.69.114.104"
    private let port: UInt16 = 22
    private let username = "qdstwk"

    @State private var status = "Ready — no connection attempted yet."
    @State private var fingerprint = ""
    @State private var keyType = ""
    @State private var isRunning = false
    @State private var activeClient: IntegratedSSHClient?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("PrivateTailnetSSH — Host Key Test")
                .font(.title2.bold())

            Text("Target: \(username)@\(host):\(port)")
                .font(.system(.body, design: .monospaced))

            if !keyType.isEmpty {
                Text("Key type: \(keyType)")
                    .font(.system(.body, design: .monospaced))
            }

            if !fingerprint.isEmpty {
                Text("Fingerprint:")
                    .font(.headline)
                Text(fingerprint)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }

            Text(status)
                .textSelection(.enabled)

            Button(isRunning ? "Testing…" : "Test first-use Host Key") {
                Task { await testFirstUseHostKey() }
            }
            .disabled(isRunning)

            Spacer()
        }
        .padding(24)
        .onChange(of: scenePhase) { _, phase in
            guard phase != .active else { return }
            activeClient?.close()
            activeClient = nil
            isRunning = false
            status = "CANCELLED: app left the active foreground; SSH transport was force-closed."
        }
        .frame(minWidth: 620, minHeight: 360)
    }

    @MainActor
    private func testFirstUseHostKey() async {
        isRunning = true
        fingerprint = ""
        keyType = ""
        status = "Connecting and verifying SSH key exchange…"

        defer { isRunning = false }

        guard let client = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: nil
        ) else {
            status = "FAIL: Core rejected the destination before TCP connect."
            return
        }

        activeClient = client
        defer {
            client.close()
            activeClient = nil
        }

        do {
            _ = try await client.run(
                username: username,
                auth: .password("__MUST_NOT_BE_SENT_FIRST_USE__"),
                command: "true",
                timeout: 10
            )
            status = "FAIL: first-use connection unexpectedly passed the Host Key confirmation gate."
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            keyType = key.keyType
            fingerprint = key.fingerprint
            status = "PASS: server proved possession of the Host Key. First-use confirmation gate stopped the connection before password authentication."
        } catch SSHError.invalidHostKeySignature {
            status = "FAIL: server Host Key signature verification failed."
        } catch {
            status = "FAIL at Core stage: \(client.stage)\nRaw error: \(String(reflecting: error))\nLocalized: \(error.localizedDescription)"
        }
    }
}
