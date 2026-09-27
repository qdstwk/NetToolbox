import XCTest
@testable import NetToolboxKit

final class UnifiedNetworkInterfaceTests: XCTestCase {
    func testExclusiveAdmissionAndStaleRelease() async throws {
        await UnifiedNetworkInterface.setForegroundActive(true, generation: 10_000)
        let first = try await UnifiedNetworkInterface.claim(operation: "test-a", target: "a")
        do {
            _ = try await UnifiedNetworkInterface.claim(operation: "test-b", target: "b")
            XCTFail("Second concurrent lease must be rejected")
        } catch UnifiedNetworkInterface.InterfaceError.busy {
            // expected
        }
        await UnifiedNetworkInterface.release(first)
        let second = try await UnifiedNetworkInterface.claim(operation: "test-b", target: "b")
        await UnifiedNetworkInterface.release(first) // stale release must not clear second
        XCTAssertEqual(await UnifiedNetworkInterface.activeOperation()?.operation, "test-b")
        await UnifiedNetworkInterface.release(second)
    }

    func testForegroundRevocationCancelsAndDoesNotRestoreLease() async throws {
        await UnifiedNetworkInterface.setForegroundActive(true, generation: 20_000)
        let lease = try await UnifiedNetworkInterface.claim(operation: "test-c", target: "c")
        let counter = CancellationCounter()
        await UnifiedNetworkInterface.registerCancellation(for: lease) { counter.hit() }

        await UnifiedNetworkInterface.setForegroundActive(false, generation: 20_001)
        XCTAssertEqual(counter.value, 1)
        XCTAssertNil(await UnifiedNetworkInterface.activeOperation())

        do {
            _ = try await UnifiedNetworkInterface.claim(operation: "test-d", target: "d")
            XCTFail("Background admission must fail")
        } catch UnifiedNetworkInterface.InterfaceError.foregroundRequired {
            // expected
        }

        await UnifiedNetworkInterface.setForegroundActive(true, generation: 20_002)
        XCTAssertNil(await UnifiedNetworkInterface.activeOperation(), "Foreground return must not resurrect old work")
    }

    func testStaleLifecycleUpdateCannotReenableNetworking() async throws {
        await UnifiedNetworkInterface.setForegroundActive(false, generation: 30_001)
        await UnifiedNetworkInterface.setForegroundActive(true, generation: 30_000)
        do {
            _ = try await UnifiedNetworkInterface.claim(operation: "stale", target: "stale")
            XCTFail("Older lifecycle update must be ignored")
        } catch UnifiedNetworkInterface.InterfaceError.foregroundRequired {
            // expected
        }
    }
}

private final class CancellationCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func hit() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}
