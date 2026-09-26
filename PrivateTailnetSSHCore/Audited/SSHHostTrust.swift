import Foundation
import CryptoKit

/// A locally trusted SSH server identity.
///
/// Security comparison is performed against `keyBlob` and `keyType`.
/// `fingerprint` is derived display metadata and is never the sole trust anchor.
struct PinnedSSHHostKey: Codable, Sendable, Equatable {
    let host: String
    let port: UInt16
    let keyType: String
    let keyBlob: Data
    let fingerprint: String
    let firstSeen: Date

    init(host: String, port: UInt16, keyType: String, keyBlob: Data, firstSeen: Date = Date()) {
        self.host = host
        self.port = port
        self.keyType = keyType
        self.keyBlob = keyBlob
        self.fingerprint = Self.sha256Fingerprint(of: keyBlob)
        self.firstSeen = firstSeen
    }

    func matches(host: String, port: UInt16, keyType: String, keyBlob: Data) -> Bool {
        self.host == host &&
        self.port == port &&
        self.keyType == keyType &&
        self.keyBlob == keyBlob
    }

    static func sha256Fingerprint(of keyBlob: Data) -> String {
        let digest = Data(SHA256.hash(data: keyBlob))
        return "SHA256:" + digest.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}

enum SSHHostTrustDecision: Sendable, Equatable {
    /// No pin exists. UI must show the fingerprint and obtain explicit approval
    /// before any password user-auth request is constructed or transmitted.
    case firstUse(PinnedSSHHostKey)

    /// Exact host:port, key type and key blob match.
    case trusted(PinnedSSHHostKey)

    /// A pin exists but the presented identity differs. This is always fatal.
    /// Reset/removal of the old pin is a separate explicit host-management action.
    case changed(expected: PinnedSSHHostKey, presented: PinnedSSHHostKey)
}

enum SSHHostTrust {
    static func evaluate(
        host: String,
        port: UInt16,
        keyType: String,
        keyBlob: Data,
        pinned: PinnedSSHHostKey?
    ) -> SSHHostTrustDecision {
        let presented = PinnedSSHHostKey(host: host, port: port, keyType: keyType, keyBlob: keyBlob)
        guard let pinned else { return .firstUse(presented) }
        return pinned.matches(host: host, port: port, keyType: keyType, keyBlob: keyBlob)
            ? .trusted(pinned)
            : .changed(expected: pinned, presented: presented)
    }
}
