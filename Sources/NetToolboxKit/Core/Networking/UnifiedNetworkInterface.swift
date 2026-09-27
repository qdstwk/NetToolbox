import Foundation

/// The only app-level admission point for active network work.
///
/// Security invariants:
/// - At most one network operation exists in the whole app.
/// - A second operation is rejected immediately; nothing is queued.
/// - A lease is bound to one operation + one target.
/// - Only the exact lease owner can release the slot.
///
/// Transport implementations (TCP/UDP/HTTP/TLS) remain protocol-specific,
/// but Features must enter the network through this interface first.
final class NetworkCancellationHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var current: (@Sendable () -> Void)?

    func install(_ action: @escaping @Sendable () -> Void) {
        lock.lock()
        if cancelled {
            lock.unlock()
            action()
            return
        }
        current = action
        lock.unlock()
    }

    func clear() {
        lock.lock()
        current = nil
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        guard !cancelled else { lock.unlock(); return }
        cancelled = true
        let action = current
        current = nil
        lock.unlock()
        action?()
    }

    var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }
}

enum UnifiedNetworkInterface {
    struct Lease: Sendable, Equatable {
        fileprivate let id: UUID
        let operation: String
        let target: String
    }

    /// Synchronous, idempotent teardown hook owned by the active transport.
    /// It must never start network work; it may only cancel/close.
    struct Cancellation: @unchecked Sendable {
        let cancel: @Sendable () -> Void
    }

    enum InterfaceError: LocalizedError, Sendable {
        case busy(operation: String, target: String)
        case foregroundRequired
        case operationTimedOut(seconds: Double)

        var errorDescription: String? {
            switch self {
            case .busy(let operation, let target):
                return "Another network operation is already active: \(operation) → \(target)"
            case .foregroundRequired:
                return "Network operations are allowed only while the app is active in the foreground"
            case .operationTimedOut(let seconds):
                return "Network operation exceeded its (seconds)-second deadline"
            }
        }
    }

    private actor Admission {
        private var active: Lease?
        private var cancellation: (leaseID: UUID, hook: Cancellation)?
        private var foregroundActive = false
        private var lifecycleGeneration: UInt64 = 0
        private var revocationGeneration: UInt64 = 0

        func setForegroundActive(_ value: Bool) {
            foregroundActive = value
            if !value {
                // Revoke admission first, then synchronously tear down the one
                // permitted active transport. No background grace period.
                let hook = cancellation?.hook
                cancellation = nil
                active = nil
                revocationGeneration &+= 1
                hook?.cancel()
            }
        }

        func claim(operation: String, target: String) throws -> Lease {
            guard foregroundActive else { throw InterfaceError.foregroundRequired }
            if let active {
                throw InterfaceError.busy(operation: active.operation, target: active.target)
            }
            let lease = Lease(id: UUID(), operation: operation, target: target)
            active = lease
            return lease
        }

        func registerCancellation(_ hook: Cancellation, for lease: Lease) {
            guard foregroundActive, active?.id == lease.id else {
                hook.cancel()
                return
            }
            cancellation = (lease.id, hook)
        }

        func release(_ lease: Lease) {
            guard active?.id == lease.id else { return }
            cancellation = nil
            active = nil
        }

        func snapshot() -> Lease? { active }
    }

    private static let admission = Admission()

    /// Hard ceilings for a single foreground operation. These are total
    /// operation deadlines, not per-packet/per-read timeouts.
    enum Deadline {
        static let quick: Duration = .seconds(15)
        static let standard: Duration = .seconds(30)
        static let scan: Duration = .seconds(300)
        static let speedTest: Duration = .seconds(90)
        static let handshake: Duration = .seconds(30)
    }

    static func claim(operation: String, target: String) async throws -> Lease {
        try await admission.claim(
            operation: operation,
            target: canonicalTarget(target)
        )
    }

    static func registerCancellation(
        for lease: Lease,
        _ cancel: @escaping @Sendable () -> Void
    ) async {
        await admission.registerCancellation(Cancellation(cancel: cancel), for: lease)
    }

    static func release(_ lease: Lease) async {
        await admission.release(lease)
    }

    static func withDeadline<T: Sendable>(
        _ duration: Duration,
        operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(for: duration)
                throw InterfaceError.operationTimedOut(seconds: duration.secondsDouble)
            }
            guard let result = try await group.next() else {
                throw CancellationError()
            }
            group.cancelAll()
            return result
        }
    }

    static func httpData(
        for request: URLRequest,
        operation: String,
        target: String? = nil
    ) async throws -> (Data, URLResponse) {
        let resolvedTarget = target ?? request.url?.host ?? request.url?.absoluteString ?? "http"
        let lease = try await claim(operation: operation, target: resolvedTarget)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        configuration.waitsForConnectivity = false
        let session = URLSession(configuration: configuration)
        await registerCancellation(for: lease) { session.invalidateAndCancel() }
        do {
            let result = try await session.data(for: request)
            await release(lease)
            return result
        } catch {
            await release(lease)
            throw error
        }
    }

    static func httpData(
        from url: URL,
        operation: String,
        target: String? = nil
    ) async throws -> (Data, URLResponse) {
        try await httpData(for: URLRequest(url: url), operation: operation, target: target)
    }

    static func activeOperation() async -> Lease? {
        await admission.snapshot()
    }

    /// Called by the root scene lifecycle. Any non-active scene is fail closed:
    /// no new network operation can be admitted.
    static func setForegroundActive(_ active: Bool, generation: UInt64) async {
        await admission.setForegroundActive(active, generation: generation)
    }

    private static func canonicalTarget(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}


private extension Duration {
    var secondsDouble: Double {
        let c = components
        return Double(c.seconds) + Double(c.attoseconds) / 1_000_000_000_000_000_000
    }
}
