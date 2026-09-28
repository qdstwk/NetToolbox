import SwiftUI

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase

    private let host = "100.69.114.104"
    private let port: UInt16 = 22
    private let username = "qdstwk"

    // Compile gate for the current hardened MacCandidate.
    // Older R3/Annotated copies do not contain this complete error set.
    private let requiredCurrentCoreCheck: [SSHError] = [
        .rekeyUnsupported,
        .concurrentSession,
        .concurrentSend,
        .concurrentReceive,
        .channelSetupTimeout,
        .execTimeout,
        .shellSetupTimeout
    ]

    @State private var status = "Ready — exact-pin reconnect test not started."
    @State private var isRunning = false
    @State private var activeClient: IntegratedSSHClient?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("PrivateTailnetSSH — Exact Pin Trusted Reconnect")
                .font(.title2.bold())

            Text("Target: \(username)@\(host):\(port)")
                .font(.system(.body, design: .monospaced))

            Text("Core gate symbols: \(requiredCurrentCoreCheck.count)")
                .font(.system(.caption, design: .monospaced))

            Text("Expected result: first connection captures the exact verified Host Key before auth; second connection accepts that exact pin and reaches password auth with a disposable sentinel, which must then be rejected as authFailed.")
                .font(.system(.body, design: .monospaced))

            Text(status)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)

            Button(isRunning ? "Testing…" : "Test exact-pin trusted reconnect") {
                Task { await testExactPinReconnect() }
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
        .frame(minWidth: 760, minHeight: 440)
    }

    @MainActor
    private func testExactPinReconnect() async {
        isRunning = true
        status = "Phase 1/2: re-reading the verified HP-NAS Host Key without entering authentication…"
        defer {
            activeClient?.close()
            activeClient = nil
            isRunning = false
        }

        guard let discoveryClient = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: nil
        ) else {
            status = "FAIL: Core rejected destination before TCP connect."
            return
        }

        activeClient = discoveryClient
        let exactPin: PinnedSSHHostKey

        do {
            _ = try await discoveryClient.run(
                username: username,
                auth: .password("__MUST_NOT_BE_SENT_EXACT_PIN_DISCOVERY__"),
                command: "true",
                timeout: 10
            )
            status = "FAIL: first-use discovery unexpectedly passed the Host Key confirmation gate."
            return
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            exactPin = key
            discoveryClient.close()
            activeClient = nil
        } catch SSHError.authFailed {
            status = "CRITICAL FAIL: discovery phase reached password authentication before explicit Host Key confirmation."
            return
        } catch {
            status = "FAIL in discovery phase at Core stage: \(discoveryClient.stage)\nRaw error: \(String(reflecting: error))\nLocalized: \(error.localizedDescription)"
            return
        }

        status = """
        Phase 1/2 PASS: exact verified Host Key captured in memory.
        Type: \(exactPin.keyType)
        Fingerprint: \(exactPin.fingerprint)
        Phase 2/2: reconnecting with that exact pin…
        """

        guard let trustedClient = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: exactPin
        ) else {
            status += "\nFAIL: Core rejected destination before trusted reconnect."
            return
        }

        activeClient = trustedClient

        do {
            _ = try await trustedClient.run(
                username: username,
                auth: .password("__EXPECTED_TO_FAIL_AFTER_EXACT_PIN_TRUST__"),
                command: "true",
                timeout: 10
            )
            status += "\nFAIL: disposable sentinel unexpectedly authenticated."
        } catch SSHError.authFailed {
            status += """
            
            PASS: exact-pin trusted reconnect accepted the exact Host Key.
            The Core reached password authentication only after exact pin match.
            Disposable sentinel was rejected as expected.
            No real password was used.
            """
        } catch SSHError.hostKeyChanged {
            status += "\nFAIL: the exact captured pin was incorrectly treated as changed."
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            status += "\nFAIL: reconnect incorrectly fell back to first-use. Presented: \(key.keyType) \(key.fingerprint)"
        } catch {
            status += "\nFAIL in trusted reconnect at Core stage: \(trustedClient.stage)\nRaw error: \(String(reflecting: error))\nLocalized: \(error.localizedDescription)"
        }
    }
}
