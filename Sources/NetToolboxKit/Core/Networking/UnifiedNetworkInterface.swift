import Foundation

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

/// Sole app-level admission point for network work.
///
/// Invariants:
/// - foreground only; scene revocation is synchronous at the root callback;
/// - at most one top-level operation/target;
/// - no queue: a second operation fails closed;
/// - a stale lease can never release a newer operation;
/// - the active transport exposes a synchronous, idempotent cancellation hook.
enum UnifiedNetworkInterface {
    struct Lease: Sendable, Equatable {
        fileprivate let id: UUID
        let operation: String
        let target: String
    }

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
                return "Network operation exceeded its \(seconds)-second deadline"
            }
        }
    }

    private final class ForegroundState: @unchecked Sendable {
        private let lock = NSLock()
        private var active = false
        private var generation: UInt64 = 0

        func set(_ value: Bool, generation newGeneration: UInt64) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            guard newGeneration >= generation else { return false }
            generation = newGeneration
            active = value
            return true
        }

        var isActive: Bool {
            lock.lock()
            defer { lock.unlock() }
            return active
        }
    }

    private final class CancellationBridge: @unchecked Sendable {
        private let lock = NSLock()
        private var foreground = false
        private var leaseID: UUID?
        private var hooks: [Cancellation] = []

        func setForeground(_ value: Bool) {
            lock.lock()
            foreground = value
            let pending = value ? [] : hooks
            if !value {
                leaseID = nil
                hooks = []
            }
            lock.unlock()
            pending.forEach { $0.cancel() }
        }

        func beginLease(_ id: UUID) {
            lock.lock()
            guard foreground else { lock.unlock(); return }
            leaseID = id
            hooks = []
            lock.unlock()
        }

        func install(_ hook: Cancellation, leaseID requestedID: UUID) {
            lock.lock()
            guard foreground, leaseID == requestedID else {
                lock.unlock()
                hook.cancel()
                return
            }
            hooks.append(hook)
            lock.unlock()
        }

        func installForCurrentLease(_ hook: Cancellation) {
            lock.lock()
            guard foreground, leaseID != nil else {
                lock.unlock()
                hook.cancel()
                return
            }
            hooks.append(hook)
            lock.unlock()
        }

        func clear(leaseID requestedID: UUID) {
            lock.lock()
            if leaseID == requestedID {
                leaseID = nil
                hooks = []
            }
            lock.unlock()
        }
    }

    private actor Admission {
        private var active: Lease?
        private var cancellation: (leaseID: UUID, hook: Cancellation)?
        private var foregroundActive = false
        private var lifecycleGeneration: UInt64 = 0

        func setForegroundActive(_ value: Bool, generation: UInt64) {
            guard generation >= lifecycleGeneration else { return }
            lifecycleGeneration = generation
            foregroundActive = value
            if !value {
                cancellation = nil
                active = nil
            }
        }

        func claim(operation: String, target: String) throws -> Lease {
            guard foregroundActive, UnifiedNetworkInterface.foregroundState.isActive else {
                throw InterfaceError.foregroundRequired
            }
            if let active {
                throw InterfaceError.busy(operation: active.operation, target: active.target)
            }
            let lease = Lease(id: UUID(), operation: operation, target: target)
            active = lease
            return lease
        }

        func registerCancellation(_ hook: Cancellation, for lease: Lease) -> Bool {
            guard foregroundActive, UnifiedNetworkInterface.foregroundState.isActive, active?.id == lease.id else {
                hook.cancel()
                return false
            }
            cancellation = (lease.id, hook)
            return true
        }

        func release(_ lease: Lease) {
            guard active?.id == lease.id else { return }
            cancellation = nil
            active = nil
        }

        func snapshot() -> Lease? { active }
    }

    private static let foregroundState = ForegroundState()
    private static let cancellationBridge = CancellationBridge()
    private static let admission = Admission()

    enum Deadline {
        static let quick: Duration = .seconds(15)
        static let standard: Duration = .seconds(30)
        static let scan: Duration = .seconds(300)
        static let speedTest: Duration = .seconds(90)
        static let handshake: Duration = .seconds(30)
    }

    static func claim(operation: String, target: String) async throws -> Lease {
        guard foregroundState.isActive else { throw InterfaceError.foregroundRequired }
        let lease = try await admission.claim(operation: operation, target: canonicalTarget(target))
        cancellationBridge.beginLease(lease.id)
        return lease
    }

    static func registerCancellation(
        for lease: Lease,
        _ cancel: @escaping @Sendable () -> Void
    ) async {
        let hook = Cancellation(cancel: cancel)
        let accepted = await admission.registerCancellation(hook, for: lease)
        if accepted { cancellationBridge.install(hook, leaseID: lease.id) }
    }

    static func registerTransportCancellation(_ cancel: @escaping @Sendable () -> Void) {
        cancellationBridge.installForCurrentLease(Cancellation(cancel: cancel))
    }

    static func release(_ lease: Lease) async {
        cancellationBridge.clear(leaseID: lease.id)
        await admission.release(lease)
    }

    /// Called synchronously from the scene-phase callback before any Task hop.
    /// A non-active scene closes the currently registered transport immediately
    /// and blocks new claims immediately.
    static func setForegroundActiveImmediately(_ active: Bool, generation: UInt64) {
        guard foregroundState.set(active, generation: generation) else { return }
        cancellationBridge.setForeground(active)
    }

    static func setForegroundActive(_ active: Bool, generation: UInt64) async {
        setForegroundActiveImmediately(active, generation: generation)
        await admission.setForegroundActive(active, generation: generation)
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
            guard let result = try await group.next() else { throw CancellationError() }
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
