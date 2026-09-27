import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A TCP-based path probe used when ICMP traceroute comes back empty (the
/// network filters ICMP, or iOS won't deliver Time-Exceeded to the datagram
/// socket). It can't name intermediate routers — that needs a raw socket iOS
/// doesn't grant — but by connecting with an increasing IP TTL it finds the
/// **hop distance** to the host and the round-trip time, which is a real,
/// useful result instead of a wall of stars.
enum TCPTraceProbe {
    /// Ports likely to be open (or to actively refuse), tried in order.
    static let ports: [UInt16] = [443, 80, 53]

    struct Result: Sendable, Equatable {
        let hops: Int
        let rttMs: Double
        let port: UInt16
    }

    static func trace(host: String, maxHops: Int, timeout: Double, cancellation: NetworkCancellationHandle) async -> Result? {
        for port in ports {
            if let result = await distance(host: host, port: port, maxHops: maxHops, timeout: timeout, cancellation: cancellation) {
                return result
            }
        }
        return nil
    }

    /// Probes TTLs strictly one at a time; first reach is the hop distance.
    private static func distance(host: String, port: UInt16, maxHops: Int, timeout: Double, cancellation: NetworkCancellationHandle) async -> Result? {
        for ttl in 1...maxHops {
            if Task.isCancelled || cancellation.isCancelled { return nil }
            if let hit = await reach(host: host, port: port, ttl: ttl, timeout: timeout, cancellation: cancellation) {
                return Result(hops: hit.0, rttMs: hit.1, port: port)
            }
        }
        return nil
    }

    private static func reach(host: String, port: UInt16, ttl: Int, timeout: Double, cancellation: NetworkCancellationHandle) async -> (Int, Double)? {
        await withCheckedContinuation { continuation in
            let shot = OneShot(continuation)
            DispatchQueue.global(qos: .userInitiated).async {
                shot.resume(blockingReach(host: host, port: port, ttl: ttl, timeout: timeout, cancellation: cancellation))
            }
        }
    }

    #if canImport(Darwin)
    private static func blockingReach(host: String, port: UInt16, ttl: Int, timeout: Double, cancellation: NetworkCancellationHandle) -> (Int, Double)? {
        var hints = addrinfo(
            ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil
        )
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &info) == 0, let info, let addr = info.pointee.ai_addr else {
            if info != nil { freeaddrinfo(info) }
            return nil
        }
        var dest = sockaddr_in()
        memcpy(&dest, addr, Int(MemoryLayout<sockaddr_in>.size))
        freeaddrinfo(info)

        if cancellation.isCancelled { return nil }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        let owner = TraceSocketOwner(fd)
        defer { owner.closeIfOpen(); cancellation.clear() }

        var ttlValue = Int32(ttl)
        setsockopt(fd, IPPROTO_IP, IP_TTL, &ttlValue, socklen_t(MemoryLayout<Int32>.size))
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)

        let clock = ContinuousClock()
        let start = clock.now
        func elapsedMs() -> Double {
            let elapsed = start.duration(to: clock.now)
            return Double(elapsed.components.seconds) * 1000
                + Double(elapsed.components.attoseconds) / 1_000_000_000_000_000
        }

        let result = withUnsafePointer(to: &dest) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result == 0 { return (ttl, elapsedMs()) }                     // reached instantly
        if result < 0, errno == ECONNREFUSED { return (ttl, elapsedMs()) } // reached (refused)
        if result < 0, errno != EINPROGRESS { return nil }
        cancellation.install { owner.cancel() }
        if cancellation.isCancelled { return nil }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, Int32(max(1, timeout * 1000))) > 0 else { return nil }   // TTL too small
        var socketError: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &socketError, &length)
        if socketError == 0 || socketError == ECONNREFUSED { return (ttl, elapsedMs()) }
        return nil
    }
    private final class TraceSocketOwner: @unchecked Sendable {
        private let lock = NSLock()
        private var fd: Int32?
        init(_ fd: Int32) { self.fd = fd }
        func cancel() {
            lock.lock(); let value = fd; fd = nil; lock.unlock()
            if let value { close(value) }
        }
        func closeIfOpen() { cancel() }
    }
    #else
    private static func blockingReach(host: String, port: UInt16, ttl: Int, timeout: Double, cancellation: NetworkCancellationHandle) -> (Int, Double)? { nil }
    #endif
}
