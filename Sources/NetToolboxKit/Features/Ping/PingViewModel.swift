import Foundation
import Observation

/// Drives a real ICMP (or ICMPv6) ping run with professional options:
/// request count / continuous, period between echoes, per-echo timeout,
/// payload size, TTL / hop-limit and an IPv6 preference. No port — it's a
/// genuine ICMP echo over the unprivileged datagram socket.
@MainActor
@Observable
final class PingViewModel {
    var host = ""

    // Options (mirrors a professional ping tool).
    var countText = "5"          // Number of Requests
    var intervalText = "1"       // Ping Period (s) — gap between echoes
    var timeoutText = "2"        // Ping Timeout (s)
    var payloadText = "56"       // Payload Size (bytes)
    var ttlText = "64"           // TTL / hop-limit
    var preferIPv6 = false       // Prefer IPv6
    var continuous = false       // keep pinging until stopped
    var fallbackPortText = "443" // TCP port used when ICMP is blocked

    /// True once the run has fallen back to TCP-connect timing because ICMP
    /// echoes went unanswered (common on iOS/cellular networks that filter it).
    private(set) var usingTCPFallback = false

    private(set) var attempts: [PingAttempt] = []
    private(set) var summary: PingSummary?
    private(set) var resolvedIP: String?
    private(set) var isRunning = false {
        didSet {
            guard !toolID.isEmpty, oldValue != isRunning else { return }
            if isRunning { activity?.start(toolID) } else { activity?.stop(toolID) }
        }
    }
    private(set) var errorMessage: String?
    /// This tool's own recent-runs log (newest first), kept while the app runs.
    private(set) var history: [String] = []
    private var currentCancellation: NetworkCancellationHandle?

    /// Set once by the view so a running operation can flag itself in the
    /// sidebar even after you navigate away.
    var activity: ActivityCenter?
    var toolID = ""

    func run() async {
        let target = host.trimmingCharacters(in: .whitespaces)
        guard !target.isEmpty else { return }

        let count = continuous ? Int.max : max(1, min(1000, Int(countText) ?? 5))
        let interval = max(0.1, Double(intervalText) ?? 1)
        let timeout = max(0.2, Double(timeoutText) ?? 2)
        let payload = max(0, min(65_500, Int(payloadText) ?? 56))
        let ttl = max(1, min(255, Int(ttlText) ?? 64))
        let fallbackPort = UInt16(fallbackPortText.trimmingCharacters(in: .whitespaces)) ?? 443

        isRunning = true
        errorMessage = nil
        attempts = []
        summary = nil
        resolvedIP = nil
        usingTCPFallback = false

        let lease: UnifiedNetworkInterface.Lease
        do {
            lease = try await UnifiedNetworkInterface.claim(operation: "ping", target: target)
        } catch {
            errorMessage = error.localizedDescription
            isRunning = false
            return
        }
        let cancellation = NetworkCancellationHandle()
        currentCancellation = cancellation
        await UnifiedNetworkInterface.registerCancellation(for: lease) { cancellation.cancel() }

        let resolved: ICMPPingEngine.Target?
        if InputClassifier.isIPv4(target) {
            resolved = .init(ip: target, isIPv6: false)
        } else if target.contains(":") {
            resolved = .init(ip: target, isIPv6: true)
        } else {
            let dns = UDPDNSResolver()
            let firstType: DNSRecordType = preferIPv6 ? .aaaa : .a
            let secondType: DNSRecordType = preferIPv6 ? .a : .aaaa
            let first = (try? await dns.resolve(name: target, type: firstType, server: "1.1.1.1", cancellation: cancellation)) ?? []
            var second: [DNSRecord] = []
            if first.isEmpty && !cancellation.isCancelled {
                second = (try? await dns.resolve(name: target, type: secondType, server: "1.1.1.1", cancellation: cancellation)) ?? []
            }
            if let value = (first.first ?? second.first)?.value {
                resolved = .init(ip: value, isIPv6: value.contains(":"))
            } else {
                resolved = nil
            }
        }
        guard let resolved else {
            errorMessage = L10nString("ping.error.resolve")
            currentCancellation = nil
            await UnifiedNetworkInterface.release(lease)
            isRunning = false
            return
        }
        resolvedIP = resolved.ip

        let tcpPinger = TCPPingService()
        var useICMP = true
        var collected: [PingAttempt] = []
        var sequence = 0
        while isRunning, sequence < count {
            sequence += 1
            var milliseconds: Double?
            if useICMP {
                let reply = await ICMPPingEngine.ping(
                    target: resolved, sequence: sequence, ttl: ttl, payloadSize: payload, timeout: timeout,
                    cancellation: cancellation
                )
                milliseconds = reply.milliseconds
                // If the very first ICMP echo goes unanswered the network is
                // almost certainly filtering ICMP — switch to a TCP handshake
                // (like other iOS ping tools) for the rest of the run.
                if milliseconds == nil, sequence == 1 {
                    useICMP = false
                    usingTCPFallback = true
                }
            }
            if milliseconds == nil {
                let tcp = await tcpPinger.attempt(host: resolved.ip, port: fallbackPort, timeout: timeout, cancellation: cancellation)
                milliseconds = tcp.milliseconds
            }
            collected.append(PingAttempt(sequence: sequence, milliseconds: milliseconds))
            attempts = collected
            summary = TCPPingService.summarize(collected)
            if isRunning, sequence < count {
                try? await Task.sleep(for: .seconds(interval))
            }
        }
        currentCancellation = nil
        await UnifiedNetworkInterface.release(lease)
        isRunning = false

        if let summary {
            let average = summary.avgMs.map { String(format: " · %.0f ms", $0) } ?? ""
            history.insert("\(target) (\(resolved.ip)) — \(summary.received)/\(summary.sent)\(average)", at: 0)
            if history.count > 10 { history.removeLast() }
        }
    }

    func stop() {
        currentCancellation?.cancel()
        isRunning = false
    }
}
