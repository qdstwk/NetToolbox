import Foundation
import Network

enum SSHTransportError: Error, Sendable, Equatable {
    case invalidEndpoint
    case timeout
    case connection(String)
    case closed
}

private final class SSHOneShot<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?
    init(_ continuation: CheckedContinuation<Value, Never>) { self.continuation = continuation }
    func resume(_ value: Value) {
        lock.lock()
        let c = continuation
        continuation = nil
        lock.unlock()
        c?.resume(returning: value)
    }
}

private final class SSHAtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !claimed else { return false }
        claimed = true
        return true
    }
}

/// Long-lived TCP byte stream for the SSH transport.
/// Deliberately uses Network.framework directly: no NIO/Citadel/C target.
final class SSHTCPConnection: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "PrivateTailnetSSH.transport")

    init?(host: String, port: UInt16) {
        let h = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !h.isEmpty, let p = NWEndpoint.Port(rawValue: port) else { return nil }
        connection = NWConnection(host: NWEndpoint.Host(h), port: p, using: .tcp)
    }

    func open(timeout: Double) async -> Result<Void, SSHTransportError> {
        await withCheckedContinuation { continuation in
            let shot = SSHOneShot(continuation)
            let settled = SSHAtomicFlag()
            let connection = self.connection
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if settled.claim() { shot.resume(.success(())) }
                case .failed(let error), .waiting(let error):
                    if settled.claim() { shot.resume(.failure(.connection(error.localizedDescription))) }
                case .cancelled:
                    if settled.claim() { shot.resume(.failure(.closed)) }
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                if settled.claim() {
                    connection.cancel()
                    shot.resume(.failure(.timeout))
                }
            }
        }
    }

    func send(_ data: Data) async -> Result<Void, SSHTransportError> {
        await withCheckedContinuation { continuation in
            let shot = SSHOneShot(continuation)
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { shot.resume(.failure(.connection(error.localizedDescription))) }
                else { shot.resume(.success(())) }
            })
        }
    }

    func receive(maxLength: Int = 65_536) async -> Result<Data, SSHTransportError> {
        await withCheckedContinuation { continuation in
            let shot = SSHOneShot(continuation)
            connection.receive(minimumIncompleteLength: 1, maximumLength: maxLength) {
                data, _, isComplete, error in
                if let error { shot.resume(.failure(.connection(error.localizedDescription))) }
                else if let data, !data.isEmpty { shot.resume(.success(data)) }
                else if isComplete { shot.resume(.failure(.closed)) }
                else { shot.resume(.success(Data())) }
            }
        }
    }

    func cancel() { connection.cancel() }
}
