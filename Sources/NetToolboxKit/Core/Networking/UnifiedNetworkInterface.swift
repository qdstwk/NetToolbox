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

    enum InterfaceError: LocalizedError, Sendable {
        case busy(operation: String, target: String)

        var errorDescription: String? {
            switch self {
            case .busy(let operation, let target):
                return "Another network operation is already active: \(operation) → \(target)"
            }
        }
    }

    private actor Admission {
        private var active: Lease?

        func claim(operation: String, target: String) throws -> Lease {
            if let active {
                throw InterfaceError.busy(operation: active.operation, target: active.target)
            }
            let lease = Lease(id: UUID(), operation: operation, target: target)
            active = lease
            return lease
        }

        func release(_ lease: Lease) {
            guard active?.id == lease.id else { return }
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

    static func release(_ lease: Lease) async {
        await admission.release(lease)
    }

    static func activeOperation() async -> Lease? {
        await admission.snapshot()
    }

    private static func canonicalTarget(_ raw: String) -> String {
        raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
}
