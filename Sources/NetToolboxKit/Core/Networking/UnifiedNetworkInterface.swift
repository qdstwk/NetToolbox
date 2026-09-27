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

        var errorDescription: String? {
            switch self {
            case .busy(let operation, let target):
                return "Another network operation is already active: \(operation) → \(target)"
            case .foregroundRequired:
                return "Network operations are allowed only while the app is active in the foreground"
            }
        }
    }

    private actor Admission {
        private var active: Lease?
        private var cancellation: (leaseID: UUID, hook: Cancellation)?
        private var foregroundActive = false
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

    static func activeOperation() async -> Lease? {
        await admission.snapshot()
    }

    /// Called by the root scene lifecycle. Any non-active scene is fail closed:
    /// no new network operation can be admitted.
    static func setForegroundActive(_ active: Bool) async {
        await admission.setForegroundActive(active)
    }

    private static func canonicalTarget(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
