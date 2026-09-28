import SwiftUI

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase

    private let host = "100.69.114.104"
    private let port: UInt16 = 22
    private let username = "qdstwk"
    private let expectedKeyType = "ssh-ed25519"
    private let expectedFingerprintUTF8: [UInt8] = [
        83, 72, 65, 50, 53, 54, 58,
        51, 50, 116, 122, 89, 57, 73, 53, 53,
        82, 121, 52, 72, 109, 47, 49, 121, 119,
        43, 113, 102, 111, 84, 111, 75, 85, 81,
        87, 77, 117, 87, 115, 108, 81, 87, 51,
        78, 66, 57, 102, 122, 99, 77
    ]

    private let requiredCurrentCoreCheck: [SSHError] = [
        .rekeyUnsupported,
        .concurrentSession,
        .concurrentSend,
        .concurrentReceive,
        .channelSetupTimeout,
        .execTimeout,
        .shellSetupTimeout
    ]

    @State private var status = "Step 1: verify the HP-NAS Host Key."
    @State private var password = ""
    @State private var verifiedPin: PinnedSSHHostKey?
    @State private var activeClient: IntegratedSSHClient?
    @State private var isRunning = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("PrivateTailnetSSH — PTY / Shell Validation")
                .font(.title2.bold())

            Text("Target: \(username)@\(host):\(port)")
                .font(.system(.body, design: .monospaced))

            Text("Core gate symbols: \(requiredCurrentCoreCheck.count)")
                .font(.system(.caption, design: .monospaced))

            Text(status)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)

            Button(isRunning ? "Working…" : "1. Verify exact Host Key") {
                Task { await verifyHostKey() }
            }
            .disabled(isRunning)

            SecureField("HP-NAS SSH password — local only", text: $password)
                .textFieldStyle(.roundedBorder)
                .disabled(verifiedPin == nil || isRunning)

            Button(isRunning ? "Working…" : "2. Test PTY / shell") {
                Task { await testPTYAndShell() }
            }
            .disabled(verifiedPin == nil || password.isEmpty || isRunning)

            Text("This test opens one SSH session channel, requests xterm PTY + shell, sends one deterministic command line, reads with the single Core reader, and exits. Password is cleared from UI state before network use.")
                .font(.caption)

            Spacer()
        }
        .padding(24)
        .onChange(of: scenePhase) { _, phase in
            guard phase != .active else { return }
            activeClient?.close()
            activeClient = nil
            password = ""
            verifiedPin = nil
            isRunning = false
            status = "CANCELLED: app left the active foreground; SSH transport was force-closed."
        }
        .frame(minWidth: 820, minHeight: 560)
    }

    @MainActor
    private func verifyHostKey() async {
        isRunning = true
        password = ""
        verifiedPin = nil
        status = "Verifying server Host Key signature/possession before authentication…"

        defer {
            activeClient?.close()
            activeClient = nil
            isRunning = false
        }

        guard let client = IntegratedSSHClient(host: host, port: port, pinnedHostKey: nil) else {
            status = "FAIL: Core rejected destination before TCP connect."
            return
        }
        activeClient = client

        do {
            _ = try await client.run(
                username: username,
                auth: .password("__MUST_NOT_BE_SENT_PTY_PREFLIGHT__"),
                command: "true",
                timeout: 10
            )
            status = "CRITICAL FAIL: first-use Host Key confirmation gate was bypassed."
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            let typeMatches = key.keyType == expectedKeyType
            let fpMatches = Array(key.fingerprint.utf8) == expectedFingerprintUTF8
            guard typeMatches && fpMatches else {
                status = "HARD FAIL: HP-NAS Host Key identity mismatch. Do not enter the real password."
                return
            }
            verifiedPin = key
            status = """
            PASS: exact HP-NAS Host Key verified.
            You may now enter the real SSH password and run the PTY/shell test.
            """
        } catch SSHError.authFailed {
            status = "CRITICAL FAIL: preflight sentinel reached password authentication."
        } catch {
            status = "FAIL during Host Key preflight at stage \(client.stage): \(String(reflecting: error))"
        }
    }

    @MainActor
    private func testPTYAndShell() async {
        guard let pin = verifiedPin else {
            status = "STOP: exact Host Key has not been verified in this foreground session."
            return
        }
        guard !password.isEmpty else {
            status = "STOP: enter the HP-NAS SSH password locally."
            return
        }

        isRunning = true
        let enteredPassword = password
        password = ""

        defer {
            activeClient?.close()
            activeClient = nil
            verifiedPin = nil
            password = ""
            isRunning = false
        }

        guard let client = IntegratedSSHClient(host: host, port: port, pinnedHostKey: pin) else {
            status = "FAIL: Core rejected destination before trusted reconnect."
            return
        }
        activeClient = client
        status = "Opening exact-pin authenticated PTY + interactive shell…"

        do {
            try await client.openShell(
                username: username,
                auth: .password(enteredPassword),
                timeout: 10
            )

            // Markers are assembled remotely so terminal echo cannot create a false PASS.
            let command = """
            printf '%s%s\\n' 'PDA_SHELL_' 'OK'; if [ -t 0 ]; then printf '%s%s\\n' 'PDA_PTY_' 'PRESENT'; else printf '%s%s\\n' 'PDA_PTY_' 'MISSING'; fi; exit
            """
            try await client.sendShell(command + "\n")

            var transcript = ""
            while let chunk = try await client.readShellChunk() {
                transcript += chunk
                if transcript.count > 131_072 {
                    status = "FAIL: shell transcript exceeded 128 KiB safety limit."
                    return
                }
            }

            let shellOK = transcript.contains("PDA_SHELL_OK")
            let ptyOK = transcript.contains("PDA_PTY_PRESENT")
            let ptyMissing = transcript.contains("PDA_PTY_MISSING")

            guard shellOK && ptyOK && !ptyMissing else {
                status = """
                FAIL: PTY/shell interoperability mismatch.

                shell marker: \(shellOK ? "PASS" : "FAIL")
                PTY marker: \(ptyOK ? "PASS" : "FAIL")
                explicit PTY-missing marker seen: \(ptyMissing)

                Transcript:
                \(transcript)
                """
                return
            }

            status = """
            PASS: PTY / interactive shell interoperability verified.

            Exact Host Key:
            PASS

            Real password authentication:
            PASS

            Interactive shell startup:
            PASS

            PTY present on stdin:
            PASS

            Single-reader shell receive:
            PASS

            Shell exited and transport closed.
            Password field has been cleared.
            """
        } catch SSHError.authFailed {
            status = "FAIL: server rejected the real SSH password."
        } catch SSHError.hostKeyChanged {
            status = "HARD FAIL: Host Key changed before PTY/shell authentication."
        } catch SSHError.shellSetupTimeout {
            status = "FAIL: PTY/shell setup exceeded the 10-second hard deadline; transport was force-closed."
        } catch {
            status = """
            FAIL during PTY/shell validation.

            Core stage:
            \(client.stage)

            Raw error:
            \(String(reflecting: error))

            Localized:
            \(error.localizedDescription)
            """
        }
    }
}
