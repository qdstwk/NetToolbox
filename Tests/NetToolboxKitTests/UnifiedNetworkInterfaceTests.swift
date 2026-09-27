import XCTest
@testable import NetToolboxKit

final class UnifiedNetworkInterfaceTests: XCTestCase {
    func testFailClosedLifecycleAndExclusiveAdmission() async throws {
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
        await UnifiedNetworkInterface.release(first)
        let activeAfterStaleRelease = await UnifiedNetworkInterface.activeOperation()?.operation
        XCTAssertEqual(activeAfterStaleRelease, "test-b")

        let counter = CancellationCounter()
        let transportCounter = CancellationCounter()
        await UnifiedNetworkInterface.registerCancellation(for: second) { counter.hit() }
        UnifiedNetworkInterface.registerTransportCancellation { transportCounter.hit() }
        UnifiedNetworkInterface.setForegroundActiveImmediately(false, generation: 10_001)
        XCTAssertEqual(counter.value, 1)
        XCTAssertEqual(transportCounter.value, 1)
        await UnifiedNetworkInterface.setForegroundActive(false, generation: 10_001)
        XCTAssertEqual(counter.value, 1)
        XCTAssertEqual(transportCounter.value, 1)
        let activeAfterRevocation = await UnifiedNetworkInterface.activeOperation()
        XCTAssertNil(activeAfterRevocation)

        await UnifiedNetworkInterface.setForegroundActive(true, generation: 10_000)
        do {
            _ = try await UnifiedNetworkInterface.claim(operation: "stale", target: "stale")
            XCTFail("Older lifecycle update must not re-enable networking")
        } catch UnifiedNetworkInterface.InterfaceError.foregroundRequired {
            // expected
        }

        await UnifiedNetworkInterface.setForegroundActive(true, generation: 10_002)
        let activeAfterForegroundReturn = await UnifiedNetworkInterface.activeOperation()
        XCTAssertNil(activeAfterForegroundReturn, "Foreground return must not resurrect old work")
        let final = try await UnifiedNetworkInterface.claim(operation: "final", target: "final")
        await UnifiedNetworkInterface.release(final)
    }
}

private final class CancellationCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func hit() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}
