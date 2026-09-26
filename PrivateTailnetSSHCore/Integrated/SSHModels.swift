import Foundation

struct SSHConnectionProfile: Codable, Identifiable, Sendable, Equatable {
    var id: UUID
    var label: String
    var host: String
    var port: UInt16
    var username: String
    var pinnedHostKey: PinnedSSHHostKey?

    init(id: UUID = UUID(), label: String, host: String, port: UInt16 = 22, username: String, pinnedHostKey: PinnedSSHHostKey? = nil) {
        self.id = id
        self.label = label
        self.host = host
        self.port = port
        self.username = username
        self.pinnedHostKey = pinnedHostKey
    }
}

/// Deliberately not Codable: a password must never become part of a persisted profile.
struct SSHPasswordCredential: Sendable {
    var password: String
}

struct SSHExecResult: Sendable, Equatable {
    var stdout: Data
    var stderr: Data
    var exitStatus: UInt32?
}

struct SSHTerminalSize: Sendable, Equatable {
    var columns: UInt32
    var rows: UInt32
    var pixelWidth: UInt32 = 0
    var pixelHeight: UInt32 = 0
}
