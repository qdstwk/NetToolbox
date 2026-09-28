import SwiftUI
import Network

struct ContentView: View {
    @Environment(\.scenePhase) private var scenePhase
    private let host = "100.69.114.104"
    private let port: UInt16 = 22

    @State private var status = "Ready — probe not started."
    @State private var isRunning = false
    @State private var activeConnection: NWConnection?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("PrivateTailnetSSH — NWConnection Probe")
                .font(.title2.bold())

            Text("Target: \(host):\(port)")
                .font(.system(.body, design: .monospaced))

            ScrollView {
                Text(status)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }

            Button(isRunning ? "Testing…" : "Test raw NWConnection") {
                runProbe()
            }
            .disabled(isRunning)

            Spacer()
        }
        .padding(24)
        .onChange(of: scenePhase) { _, phase in
            guard phase != .active else { return }
            activeConnection?.forceCancel()
            activeConnection = nil
            isRunning = false
            status = "CANCELLED: app left the active foreground; raw TCP probe was force-closed."
        }
        .frame(minWidth: 620, minHeight: 360)
    }

    @MainActor
    private func append(_ line: String) {
        status += "\n" + line
    }

    @MainActor
    private func finish(_ line: String) {
        append(line)
        isRunning = false
    }

    private func runProbe() {
        isRunning = true
        status = "Creating raw NWConnection…"

        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            status = "FAIL: invalid port."
            isRunning = false
            return
        }

        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: nwPort,
            using: .tcp
        )
        activeConnection = connection

        let queue = DispatchQueue(label: "PrivateTailnetSSH.NWProbe")

        connection.stateUpdateHandler = { state in
            Task { @MainActor in
                switch state {
                case .setup:
                    append("state: setup")
                case .preparing:
                    append("state: preparing")
                case .waiting(let error):
                    append("state: waiting")
                    append("NWError: \(String(reflecting: error))")
                case .ready:
                    append("state: READY")
                    append("PASS: raw Network.framework TCP connection reached .ready.")
                    isRunning = false
                    activeConnection = nil
                    connection.forceCancel()
                case .failed(let error):
                    append("state: FAILED")
                    append("NWError: \(String(reflecting: error))")
                    isRunning = false
                    activeConnection = nil
                    connection.forceCancel()
                case .cancelled:
                    append("state: cancelled")
                    if isRunning {
                        isRunning = false
                    }
                @unknown default:
                    append("state: unknown")
                }
            }
        }

        connection.start(queue: queue)

        queue.asyncAfter(deadline: .now() + 10) {
            Task { @MainActor in
                if isRunning {
                    append("TIMEOUT: no .ready/.failed after 10 seconds.")
                    isRunning = false
                    activeConnection = nil
                    connection.forceCancel()
                }
            }
        }
    }
}
