import Foundation
import Observation

extension Notification.Name {
    /// Posted after iCloud values are pulled into `UserDefaults`, so stores
    /// backed by those keys can reload.
    static let cloudSyncDidPull = Notification.Name("nettoolbox.cloudsync.didPull")
}

/// Optional iCloud sync for **non-secret** settings only, via the user's own
/// `NSUbiquitousKeyValueStore`. Theme, saved hosts and speed-test history sync
/// across the user's devices; SSH/camera secrets stay in the local Keychain and
/// never leave the device, so the app still collects no data off-device.
///
/// Strict foreground policy: no launch/background/external-change auto-sync.
/// Sync occurs only after an explicit user action.
@MainActor
@Observable
final class CloudSync {
    private let enabledKey = "nettoolbox.cloudsync.enabled"
    /// Only non-secret keys are ever synced.
    private let syncedKeys = [
        "nettoolbox.theme",
        "nettoolbox.hosts.v1",
        "nettoolbox.speedhistory.v1",
    ]

    private(set) var isEnabled: Bool

    init() {
        isEnabled = UserDefaults.standard.bool(forKey: enabledKey)
    }

    /// No automatic network work. Enabling only records the preference.
    /// Synchronization must be initiated explicitly by the user while foregrounded.
    func start() {}

    func setEnabled(_ on: Bool) {
        isEnabled = on
        UserDefaults.standard.set(on, forKey: enabledKey)

    }

    /// Explicit foreground-only synchronization requested by the user.
    func syncNow() async throws {
        guard isEnabled else { return }
        let lease = try await UnifiedNetworkInterface.claim(operation: "icloud-sync", target: "icloud-key-value-store")
        pushAllLocal()
        NSUbiquitousKeyValueStore.default.synchronize()
        pullLocal()
        await UnifiedNetworkInterface.release(lease)
    }

    private func pushAllLocal() {
        guard isEnabled else { return }
        let defaults = UserDefaults.standard
        let store = NSUbiquitousKeyValueStore.default
        for key in syncedKeys {
            if let data = defaults.data(forKey: key) {
                store.set(data, forKey: key)
            } else if let string = defaults.string(forKey: key) {
                store.set(string, forKey: key)
            }
        }
        store.synchronize()
    }

    // MARK: - Private

    private func pullLocal() {
        let defaults = UserDefaults.standard
        let store = NSUbiquitousKeyValueStore.default
        var changed = false
        for key in syncedKeys {
            if let data = store.data(forKey: key) {
                defaults.set(data, forKey: key)
                changed = true
            } else if let string = store.string(forKey: key) {
                defaults.set(string, forKey: key)
                changed = true
            }
        }
        if changed {
            NotificationCenter.default.post(name: .cloudSyncDidPull, object: nil)
        }
    }

}
