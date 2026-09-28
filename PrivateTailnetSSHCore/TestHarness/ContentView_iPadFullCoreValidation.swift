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

    // Compile gate for the current hardened Core.
    private let requiredCurrentCoreCheck: [SSHError] = [
        .rekeyUnsupported,
        .concurrentSession,
        .concurrentSend,
        .concurrentReceive,
        .channelSetupTimeout,
        .execTimeout,
        .shellSetupTimeout
    ]

    @State private var status = """
    Step 1: run iPad security preflight.
    This verifies wrong-pin hard fail + exact HP-NAS Host Key capture before any real password is allowed.
    """
    @State private var password = ""
    @State private var verifiedPin: PinnedSSHHostKey?
    @State private var activeClient: IntegratedSSHClient?
    @State private var isRunning = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("PrivateTailnetSSH — iPadOS Full-Core Validation")
                    .font(.title2.bold())

                Text("Target: \(username)@\(host):\(port)")
                    .font(.system(.body, design: .monospaced))

                Text("Core gate symbols: \(requiredCurrentCoreCheck.count)")
                    .font(.system(.caption, design: .monospaced))

                Text(status)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)

                Button(isRunning ? "Working…" : "1. Run security preflight") {
                    Task { await runSecurityPreflight() }
                }
                .disabled(isRunning)

                SecureField("HP-NAS SSH password — local only", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                    .disabled(verifiedPin == nil || isRunning)

                Button(isRunning ? "Working…" : "2. Run full Core: exec + PTY/shell") {
                    Task { await runFullCore() }
                }
                .disabled(verifiedPin == nil || password.isEmpty || isRunning)

                Text("""
                Full-Core success requires:
                wrong-pin hard fail → exact Host Key → real password → exec stdout/exit-status → PTY/shell → single-reader receive → clean close.
                Leaving the active foreground force-closes the current SSH transport and clears password/pin UI state.
                """)
                .font(.caption)
            }
            .padding(20)
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase != .active else { return }
            activeClient?.close()
            activeClient = nil
            password = ""
            verifiedPin = nil
            isRunning = false
            status = """
            CANCELLED:
            iPad app left the active foreground.
            Active SSH transport was force-closed.
            Password and in-memory test pin were cleared.
            """
        }
    }

    @MainActor
    private func runSecurityPreflight() async {
        isRunning = true
        password = ""
        verifiedPin = nil
        status = "Phase 1/2: testing deliberately wrong exact Host Key pin…"

        defer {
            activeClient?.close()
            activeClient = nil
            isRunning = false
        }

        // Deliberately not the HP-NAS key blob.
        let wrongPin = PinnedSSHHostKey(
            host: host,
            port: port,
            keyType: "ssh-ed25519",
            keyBlob: Data([
                0x00, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
                0x54, 0x41, 0x49, 0x4C, 0x4E, 0x45, 0x54, 0x53,
                0x53, 0x48, 0x2D, 0x57, 0x52, 0x4F, 0x4E, 0x47
            ])
        )

        guard let wrongClient = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: wrongPin
        ) else {
            status = "FAIL: Core rejected the valid Tailnet destination before wrong-pin test."
            return
        }

        activeClient = wrongClient

        do {
            _ = try await wrongClient.run(
                username: username,
                auth: .password("__MUST_NOT_BE_SENT_IPAD_WRONG_PIN__"),
                command: "true",
                timeout: 10
            )
            status = "CRITICAL FAIL: iPad connection passed a deliberately wrong Host Key pin."
            return
        } catch SSHError.hostKeyChanged {
            wrongClient.close()
            activeClient = nil
        } catch SSHError.authFailed {
            status = "CRITICAL FAIL: iPad reached authentication despite the wrong Host Key pin."
            return
        } catch {
            status = """
            FAIL during iPad wrong-pin phase.
            Core stage: \(wrongClient.stage)
            Raw error: \(String(reflecting: error))
            """
            return
        }

        status = """
        Phase 1/2 PASS:
        changed/wrong Host Key pin hard-blocked before authentication.

        Phase 2/2:
        verifying current HP-NAS Host Key and capturing exact key blob…
        """

        guard let discoveryClient = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: nil
        ) else {
            status = "FAIL: Core rejected destination before exact-key discovery."
            return
        }

        activeClient = discoveryClient

        do {
            _ = try await discoveryClient.run(
                username: username,
                auth: .password("__MUST_NOT_BE_SENT_IPAD_FIRST_USE__"),
                command: "true",
                timeout: 10
            )
            status = "CRITICAL FAIL: iPad first-use Host Key confirmation gate was bypassed."
            return
        } catch SSHError.hostKeyConfirmationRequired(let key) {
            let typeMatches = key.keyType == expectedKeyType
            let fingerprintMatches =
                Array(key.fingerprint.utf8) == expectedFingerprintUTF8

            guard typeMatches && fingerprintMatches else {
                status = """
                HARD FAIL:
                iPad received a Host Key that does not match the independently verified HP-NAS identity.

                Presented:
                \(key.keyType)
                \(key.fingerprint)

                DO NOT ENTER THE REAL PASSWORD.
                """
                return
            }

            verifiedPin = key
            discoveryClient.close()
            activeClient = nil

            status = """
            PASS: iPadOS security preflight complete.

            Wrong-pin negative:
            PASS

            Host Key signature/possession:
            PASS

            Exact HP-NAS identity:
            PASS

            First-use sentinel blocked before authentication:
            PASS

            You may now enter the real SSH password locally and run the full Core test.
            """
        } catch SSHError.authFailed {
            status = "CRITICAL FAIL: iPad first-use sentinel reached password authentication."
        } catch {
            status = """
            FAIL during iPad Host Key discovery.
            Core stage: \(discoveryClient.stage)
            Raw error: \(String(reflecting: error))
            """
        }
    }

    @MainActor
    private func runFullCore() async {
        guard let pin = verifiedPin else {
            status = "STOP: security preflight has not produced a verified exact Host Key pin."
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

        // ---- Stage A: exact-pin password auth + exec + stdout + exit status ----
        status = "Full Core 1/2: exact-pin password auth + exec on iPadOS…"

        guard let execClient = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: pin
        ) else {
            status = "FAIL: Core rejected destination before iPad exec test."
            return
        }

        activeClient = execClient

        let execResult: SSHRunResult
        do {
            execResult = try await execClient.run(
                username: username,
                auth: .password(enteredPassword),
                command: "printf 'PDA_IPAD_EXEC_OK'; exit 23",
                timeout: 10
            )
        } catch SSHError.authFailed {
            status = """
            FAIL: HP-NAS rejected the password on iPadOS before exec began.

            Exact Host Key / trusted reconnect:
            PASS

            Core stage:
            userauth

            No exec command was accepted.
            Re-enter the password locally; the field has already been cleared.
            """
            return
        } catch SSHError.hostKeyChanged {
            status = "HARD FAIL: HP-NAS Host Key changed before iPad password authentication."
            return
        } catch SSHError.execTimeout {
            status = "FAIL: iPad exec exceeded the hard deadline after authentication."
            return
        } catch {
            status = """
            FAIL during iPad exec stage.
            Core stage: \(execClient.stage)
            Raw error: \(String(reflecting: error))
            """
            return
        }

        guard execResult.hostKeyVerified,
              execResult.hostKeyType == expectedKeyType,
              Array(execResult.fingerprint.utf8) == expectedFingerprintUTF8,
              execResult.output == "PDA_IPAD_EXEC_OK",
              execResult.exitStatus == 23 else {
            status = """
            FAIL: iPad exec interoperability mismatch.

            Host Key verified: \(execResult.hostKeyVerified)
            Host Key type: \(execResult.hostKeyType)
            stdout: \(String(reflecting: execResult.output))
            exit status: \(String(describing: execResult.exitStatus))
            """
            return
        }

        execClient.close()
        activeClient = nil

        // ---- Stage B: exact-pin password auth + PTY + interactive shell ----
        status = """
        Full Core 1/2 PASS:
        exact-pin password auth + exec + stdout + exit status.

        Full Core 2/2:
        opening PTY + interactive shell on iPadOS…
        """

        guard let shellClient = IntegratedSSHClient(
            host: host,
            port: port,
            pinnedHostKey: pin
        ) else {
            status = "FAIL: Core rejected destination before iPad PTY/shell test."
            return
        }

        activeClient = shellClient

        do {
            try await shellClient.openShell(
                username: username,
                auth: .password(enteredPassword),
                timeout: 10
            )

            let command = """
            printf '%s%s\\n' 'PDA_IPAD_SHELL_' 'OK'; if [ -t 0 ]; then printf '%s%s\\n' 'PDA_IPAD_PTY_' 'PRESENT'; else printf '%s%s\\n' 'PDA_IPAD_PTY_' 'MISSING'; fi; exit
            """
            try await shellClient.sendShell(command + "\n")

            var transcript = ""
            while let chunk = try await shellClient.readShellChunk() {
                transcript += chunk
                if transcript.count > 131_072 {
                    status = "FAIL: iPad shell transcript exceeded 128 KiB safety limit."
                    return
                }
            }

            let shellOK = transcript.contains("PDA_IPAD_SHELL_OK")
            let ptyOK = transcript.contains("PDA_IPAD_PTY_PRESENT")
            let ptyMissing = transcript.contains("PDA_IPAD_PTY_MISSING")

            guard shellOK && ptyOK && !ptyMissing else {
                status = """
                FAIL: iPad PTY/shell interoperability mismatch.

                shell marker: \(shellOK ? "PASS" : "FAIL")
                PTY marker: \(ptyOK ? "PASS" : "FAIL")
                PTY-missing marker seen: \(ptyMissing)

                Transcript:
                \(transcript)
                """
                return
            }

            status = """
            PASS: iPadOS full SSH Core interoperability verified.

            Current hardened Core compiled on iPadOS:
            PASS

            Tailnet TCP / destination gate:
            PASS

            Wrong-pin hard fail before auth:
            PASS

            Exact Host Key verification/pinning:
            PASS

            Real password authentication:
            PASS

            Exec stdout:
            PDA_IPAD_EXEC_OK

            Exec exit status:
            23

            PTY allocation:
            PASS

            Interactive shell:
            PASS

            Single-reader shell receive:
            PASS

            Shell/transport close:
            PASS

            Password field has been cleared.
            """
        } catch SSHError.authFailed {
            status = "FAIL: HP-NAS rejected the real password during iPad PTY/shell stage."
        } catch SSHError.hostKeyChanged {
            status = "HARD FAIL: HP-NAS Host Key changed during iPad full-Core validation."
        } catch SSHError.shellSetupTimeout {
            status = "FAIL: iPad PTY/shell setup exceeded the 10-second hard deadline."
        } catch {
            status = """
            FAIL during iPad PTY/shell stage.

            Core stage:
            \(shellClient.stage)

            Raw error:
            \(String(reflecting: error))

            Localized:
            \(error.localizedDescription)
            """
        }
    }
}
