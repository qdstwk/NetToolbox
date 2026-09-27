import Foundation

/// App-wide fail-closed gate for target-directed network operations.
/// Exactly one operation against exactly one canonical target may be active.
/// Contending operations are rejected immediately; they are never queued.
actor GlobalNetworkOperationGate {
    static let shared = GlobalNetworkOperationGate()

    struct Lease: Sendable, Equatable {
        let id: UUID
        let operation: String
        let target: String
    }

    enum GateError: LocalizedError, Sendable {
        case busy(operation: String, target: String)

        var errorDescription: String? {
            switch self {
            case .busy(let operation, let target):
                return "Another network operation is already active: \(operation) → \(target)"
            }
        }
    }

    private var active: Lease?

    func claim(operation: String, target: String) throws -> Lease {
        if let active {
            throw GateError.busy(operation: active.operation, target: active.target)
        }
        let lease = Lease(id: UUID(), operation: operation, target: target)
        active = lease
        return lease
    }

    /// Token-matched release prevents a stale task from unlocking a newer operation.
    func release(_ lease: Lease) {
        guard active?.id == lease.id else { return }
        active = nil
    }

    func snapshot() -> Lease? { active }
}
