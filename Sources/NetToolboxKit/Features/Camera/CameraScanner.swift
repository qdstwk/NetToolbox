import Foundation

/// Discovers likely IP cameras by unicast TCP-probing the device's own /24 for
/// the RTSP port. WS-Discovery multicast needs an entitlement unavailable to a
/// Playgrounds-distributed app, so a direct port sweep is used instead.
struct CameraScanner: Sendable {
    private let provider: LocalIPProviding

    init(provider: LocalIPProviding = SystemLocalIPProvider()) {
        self.provider = provider
    }

    /// The `a.b.c.` prefix of the first non-loopback IPv4 address, if any.
    func subnetBase() -> String? {
        guard let address = provider.addresses().first(where: { !$0.isIPv6 }) else { return nil }
        let parts = address.address.split(separator: ".")
        guard parts.count == 4 else { return nil }
        return "\(parts[0]).\(parts[1]).\(parts[2])."
    }

    /// Probes `base`1…254 on `port`, returning the reachable hosts.
    func scan(base: String, port: UInt16 = 554, timeout: Double = 1.0, concurrency: Int = 24) async -> [String] {
        let lease: UnifiedNetworkInterface.Lease
        do {
            lease = try await UnifiedNetworkInterface.claim(operation: "camera-scan", target: base)
        } catch {
            return []
        }
        var found: [String] = []
        for host in 1...254 {
            if let ip = await Self.probe(base: base, host: host, port: port, timeout: timeout) {
                found.append(ip)
            }
        }
        await UnifiedNetworkInterface.release(lease)
        return found.sorted { lastOctet($0) < lastOctet($1) }
    }

    private static func probe(base: String, host: Int, port: UInt16, timeout: Double) async -> String? {
        let ip = "\(base)\(host)"
        if case .success = await TCPProbe.connectLatency(host: ip, port: port, timeout: timeout) {
            return ip
        }
        return nil
    }

    private func lastOctet(_ ip: String) -> Int {
        Int(ip.split(separator: ".").last ?? "0") ?? 0
    }
}
