import SwiftUI

struct ContentView: View {
    // Negative security test:
    // Deliberately install a WRONG exact Host Key pin for the real HP-NAS.
    // The sentinel password must never reach SSH user authentication.
    private let host = "100.69.114.104"
    private let port: UInt16 = 22
    private let username = "qdstwk"

    @State private var status = "Ready — negative Host Key test not started."
    @State private var isRunning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("PrivateTailnetSSH — Changed Host Key Negative Test")
                .font(.title2.bold())

            Text("Target: \(username)@\(host):\(port)")
                .font(.system(.body, design: .monospaced))

            Text("Expected result: SSHError.hostKeyChanged BEFORE password authentication.")
                .font(.system(.body, design: .monospaced))

            Text(status)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)

            Button(isRunning ? "Testing…" : "Test wrong Host Key pin") {
                Task { await testWrongPin() }
            }
            .disabled(isRunning)

            Spacer()
        }
        .padding(24)
        .frame(minWidth: 700, minHeight: 380)
    }

    @MainActor
    private func testWrongPin() async {
        isRunning = true
        status = "Connecting with deliberately wrong pinned Host Key…"
        defer { isRunning = false }

        // This is intentionally NOT the HP-NAS key blob.
        // Exact pin comparison must therefore resolve to .changed.
        let deliberatelyWrongPin = PinnedSSHHostKey(
            host: host,
            port: port,
            keyType: "ssh-ed25519",
            keyBlob: Data([0x00, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
                          0x54, 0x41, 0x49, 0x4C, 0x4E, 0x45, 0x54, 0x53,
                          0x53, 0x48, 0x2D, 0x57, 0x52, 0x4F, 0x4E, 0x47])
        )

        guard let client = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: deliberatelyWrongPin
        ) else {
            status = "FAIL: Core rejected destination before TCP connect."
            return
        }

        defer { client.close() }

        do {
            _ = try await client.run(
                username: username,
                auth: .password("__MUST_NOT_BE_SENT_CHANGED_KEY__"),
                command: "true",
                timeout: 10
            )
            status = "FAIL: connection passed a deliberately wrong Host Key pin."
        } catch SSHError.hostKeyChanged {
            status = """
            PASS: changed/wrong Host Key pin was hard-blocked.
            Core returned SSHError.hostKeyChanged.
            Password-authentication path was not allowed to proceed.
            Sentinel password: __MUST_NOT_BE_SENT_CHANGED_KEY__
            """
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            status = """
            FAIL: Core treated an existing wrong pin as first-use.
            Presented: \(key.keyType) \(key.fingerprint)
            """
        } catch SSHError.authFailed {
            status = "CRITICAL FAIL: authentication was reached despite the wrong Host Key pin."
        } catch {
            status = """
            FAIL at Core stage: \(client.stage)
            Raw error: \(String(reflecting: error))
            Localized: \(error.localizedDescription)
            """
        }
    }
}
