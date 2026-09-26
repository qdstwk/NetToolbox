// PrivateTailnetSSHCore.swift
// Integrated single-file candidate for iPadOS Swift Playgrounds.
// Functional integration only; security approval requires the line-by-line audit.
// Sources/provenance are recorded in ../UPSTREAM_BASELINE.md and References/Rootshell/ROOTSHELL_BASELINE.md.
// Generated/frozen: 2026-09-26

import Foundation
import Network
import CryptoKit
import Security

// MARK: - SSHModels

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

// MARK: - SSHTCPConnection

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

// MARK: - SSHWire

/// SSH binary encoding primitives (RFC 4251 §5). Pure and unit-tested:
/// the transport layer builds and parses every packet through these.
enum IntegratedSSHWire {
    /// Appends a `uint32` in network byte order.
    static func putUInt32(_ value: UInt32, into data: inout Data) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Appends an SSH `string`: a `uint32` length followed by the raw bytes.
    static func putString(_ bytes: Data, into data: inout Data) {
        putUInt32(UInt32(bytes.count), into: &data)
        data.append(bytes)
    }

    /// Appends an SSH `string` from UTF-8 text.
    static func putString(_ text: String, into data: inout Data) {
        putString(Data(text.utf8), into: &data)
    }

    /// Appends a comma-joined `name-list` as an SSH `string`.
    static func putNameList(_ names: [String], into data: inout Data) {
        putString(names.joined(separator: ","), into: &data)
    }

    /// Appends an `mpint` (RFC 4251 §5): a two's-complement big-endian
    /// integer. A leading zero byte is inserted when the high bit is set so
    /// the value is never misread as negative; zero encodes as empty.
    static func putMPInt(_ magnitude: Data, into data: inout Data) {
        var bytes = Array(magnitude)
        while bytes.first == 0 { bytes.removeFirst() }   // strip leading zeros
        if bytes.isEmpty {
            putUInt32(0, into: &data)
            return
        }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        putString(Data(bytes), into: &data)
    }

    /// Sequential reader over an SSH payload.
    struct Reader {
        private let data: Data
        private var index: Int

        init(_ data: Data) {
            self.data = data
            self.index = data.startIndex
        }

        var isAtEnd: Bool { index >= data.endIndex }
        var remaining: Data { data[index...] }

        mutating func readByte() -> UInt8? {
            guard index < data.endIndex else { return nil }
            defer { index += 1 }
            return data[index]
        }

        mutating func readUInt32() -> UInt32? {
            guard index + 4 <= data.endIndex else { return nil }
            let slice = data[index..<index + 4]
            index += 4
            return slice.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        }

        mutating func readUInt64() -> UInt64? {
            guard index + 8 <= data.endIndex else { return nil }
            let slice = data[index..<index + 8]
            index += 8
            return slice.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }

        mutating func readString() -> Data? {
            guard let length = readUInt32() else { return nil }
            let count = Int(length)
            guard index + count <= data.endIndex else { return nil }
            let slice = data[index..<index + count]
            index += count
            return Data(slice)
        }

        mutating func readStringUTF8() -> String? {
            guard let bytes = readString() else { return nil }
            return String(decoding: bytes, as: UTF8.self)
        }

        mutating func readNameList() -> [String]? {
            guard let text = readStringUTF8() else { return nil }
            return text.isEmpty ? [] : text.components(separatedBy: ",")
        }
    }
}

// MARK: - SSHCrypto

#if canImport(Security)
#endif

/// The crypto used by the SSH transport, built entirely on CryptoKit and
/// Security — no third-party code, so it stays inside the Playgrounds
/// zero-dependency rule. Key exchange is `curve25519-sha256`, the cipher is
/// `aes256-gcm@openssh.com`, and host keys are verified for ed25519,
/// ecdsa-nistp256 and rsa-sha2-256/512.
enum IntegratedSSHCrypto {
    /// SHA-256 exchange hash H over the ordered kex fields (RFC 5656 §4).
    static func exchangeHash(
        clientVersion: String, serverVersion: String,
        clientKexInit: Data, serverKexInit: Data,
        hostKey: Data, clientEphemeral: Data, serverEphemeral: Data,
        sharedSecretMPInt: Data
    ) -> Data {
        var buffer = Data()
        IntegratedSSHWire.putString(clientVersion, into: &buffer)
        IntegratedSSHWire.putString(serverVersion, into: &buffer)
        IntegratedSSHWire.putString(clientKexInit, into: &buffer)
        IntegratedSSHWire.putString(serverKexInit, into: &buffer)
        IntegratedSSHWire.putString(hostKey, into: &buffer)
        IntegratedSSHWire.putString(clientEphemeral, into: &buffer)
        IntegratedSSHWire.putString(serverEphemeral, into: &buffer)
        buffer.append(sharedSecretMPInt)   // already length-prefixed by putMPInt
        return Data(SHA256.hash(data: buffer))
    }

    /// Derives one key stream (RFC 4253 §7.2): HASH(K || H || letter || id),
    /// extended by re-hashing K || H || sofar until `length` bytes exist.
    static func deriveKey(
        letter: UInt8, length: Int,
        sharedSecretMPInt K: Data, exchangeHash H: Data, sessionID: Data
    ) -> Data {
        var key = Data(SHA256.hash(data: K + H + Data([letter]) + sessionID))
        while key.count < length {
            key.append(Data(SHA256.hash(data: K + H + key)))
        }
        return key.prefix(length)
    }

    /// mpint magnitude bytes (strip leading zeros) for the shared secret, so
    /// the caller can pass it to both the hash and the KDF consistently.
    static func mpint(_ magnitude: Data) -> Data {
        var buffer = Data()
        IntegratedSSHWire.putMPInt(magnitude, into: &buffer)
        return buffer
    }

    // MARK: - Host key signature verification

    /// Verifies the server's signature over the exchange hash with the host
    /// key it presented. Returns false for any parse error or unknown type.
    static func verifyHostKey(blob: Data, signature: Data, over hash: Data) -> Bool {
        var keyReader = IntegratedSSHWire.Reader(blob)
        guard let keyType = keyReader.readStringUTF8() else { return false }
        var sigReader = IntegratedSSHWire.Reader(signature)
        guard let sigType = sigReader.readStringUTF8(),
              let sigBlob = sigReader.readString() else { return false }

        switch keyType {
        case "ssh-ed25519":
            guard sigType == "ssh-ed25519",
                  let pub = keyReader.readString(),
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
            return key.isValidSignature(sigBlob, for: hash)

        case "ecdsa-sha2-nistp256":
            guard sigType == "ecdsa-sha2-nistp256",
                  keyReader.readString() != nil,                // curve name
                  let point = keyReader.readString(),
                  let key = try? P256.Signing.PublicKey(x963Representation: point) else { return false }
            // The ecdsa signature blob is itself string(mpint r) || string(mpint s).
            var inner = IntegratedSSHWire.Reader(sigBlob)
            guard let r = inner.readString(), let s = inner.readString(),
                  let raw = try? P256.Signing.ECDSASignature(rawRepresentation: pad32(r) + pad32(s)) else { return false }
            return key.isValidSignature(raw, for: hash)

        case "ssh-rsa":
            return verifyRSA(keyReader: &keyReader, sigType: sigType, signature: sigBlob, hash: hash)

        default:
            return false
        }
    }

    /// Left-pads (or trims) an mpint magnitude to exactly 32 bytes for the
    /// fixed-width raw ECDSA representation CryptoKit expects.
    private static func pad32(_ value: Data) -> Data {
        var bytes = Array(value)
        while bytes.first == 0 { bytes.removeFirst() }
        if bytes.count >= 32 { return Data(bytes.suffix(32)) }
        return Data(repeating: 0, count: 32 - bytes.count) + Data(bytes)
    }

    private static func verifyRSA(
        keyReader: inout IntegratedSSHWire.Reader, sigType: String, signature: Data, hash: Data
    ) -> Bool {
        #if canImport(Security)
        guard let e = keyReader.readString(), let n = keyReader.readString() else { return false }
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let der = derSequence([derInteger(n), derInteger(e)])
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else { return false }
        let algorithm: SecKeyAlgorithm
        switch sigType {
        case "rsa-sha2-256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
        case "rsa-sha2-512": algorithm = .rsaSignatureMessagePKCS1v15SHA512
        default: return false
        }
        return SecKeyVerifySignature(key, algorithm, hash as CFData, signature as CFData, nil)
        #else
        return false
        #endif
    }

    // MARK: - Minimal DER

    private static func derLength(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 { bytes.insert(UInt8(value & 0xFF), at: 0); value >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

    private static func derInteger(_ magnitude: Data) -> Data {
        var bytes = Array(magnitude)
        while bytes.first == 0 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }   // keep it positive
        return Data([0x02]) + derLength(bytes.count) + Data(bytes)
    }

    private static func derSequence(_ elements: [Data]) -> Data {
        let body = elements.reduce(Data(), +)
        return Data([0x30]) + derLength(body.count) + body
    }
}

/// AES-256-GCM packet cipher for `aes256-gcm@openssh.com` (RFC 5647): a
/// 12-byte nonce of a fixed 4-byte prefix plus an 8-byte invocation counter
/// that increments after every packet.
struct IntegratedSSHGCMCipher {
    private let key: SymmetricKey
    private let fixed: Data           // 4 bytes
    private var counter: UInt64       // 8-byte invocation counter

    init(key: Data, iv: Data) {
        self.key = SymmetricKey(data: key)
        self.fixed = iv.prefix(4)
        self.counter = iv.dropFirst(4).prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private mutating func nextNonce() -> Data {
        var nonce = Data(fixed)
        var value = counter
        var tail = [UInt8](repeating: 0, count: 8)
        for index in stride(from: 7, through: 0, by: -1) {
            tail[index] = UInt8(value & 0xFF); value >>= 8
        }
        nonce.append(contentsOf: tail)
        counter &+= 1
        return nonce
    }

    /// Seals `plaintext` (padding_length || payload || padding) with the
    /// 4-byte `lengthField` as additional data. Returns ciphertext || tag.
    mutating func seal(plaintext: Data, lengthField: Data) -> Data? {
        guard let box = try? AES.GCM.seal(
            plaintext, using: key,
            nonce: try AES.GCM.Nonce(data: nextNonce()),
            authenticating: lengthField
        ) else { return nil }
        return box.ciphertext + box.tag
    }

    /// Opens `ciphertext` + 16-byte `tag` authenticated by `lengthField`.
    mutating func open(ciphertext: Data, tag: Data, lengthField: Data) -> Data? {
        guard let box = try? AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: nextNonce()),
            ciphertext: ciphertext, tag: tag
        ) else { return nil }
        return try? AES.GCM.open(box, using: key, authenticating: lengthField)
    }
}

// MARK: - SSHClient

/// Outcome of a one-shot SSH exec session.
struct SSHRunResult: Sendable {
    var output: String
    var fingerprint: String
    var hostKeyType: String
    var hostKeyVerified: Bool
    var exitStatus: Int?
}

/// How to authenticate an SSH session.
enum SSHAuth: Sendable { case password(String) }

enum SSHError: LocalizedError {
    case transport(String)
    case disconnected
    case disconnectedByServer(String)
    case unsupportedServer(String)
    case noCipher
    case kexFailed
    case authFailed
    case channelFailed
    case protocolError
    case encryptFailed
    case decryptFailed(verified: Bool)

    var errorDescription: String? {
        switch self {
        case .transport(let m): return m
        case .disconnected: return "SSH connection closed"
        case .disconnectedByServer(let m):
            return "SSH server closed connection" + (m.isEmpty ? "" : ": \(m)")
        case .unsupportedServer(let v):
            return "Unsupported SSH server:" + " \(v)"
        case .noCipher: return "No supported SSH cipher"
        case .kexFailed: return "SSH key exchange failed"
        case .authFailed: return "SSH authentication failed"
        case .channelFailed: return "SSH channel failed"
        case .protocolError: return "SSH protocol error"
        case .encryptFailed: return "SSH encryption failed"
        case .decryptFailed(let verified):
            return "SSH decryption failed (host key verified: \(verified))"
        }
    }
}

/// A minimal SSH-2 client (curve25519-sha256 + aes256-gcm@openssh.com;
/// password or public-key auth — ed25519, ECDSA nistp256/384/521, and RSA),
/// built entirely on CryptoKit/Security so the package keeps zero external
/// dependencies. Supports one-shot exec and a line-oriented interactive shell.
final class IntegratedSSHClient: @unchecked Sendable {
    private enum Msg {
        static let disconnect: UInt8 = 1
        static let ignore: UInt8 = 2
        static let debug: UInt8 = 4
        static let serviceRequest: UInt8 = 5
        static let serviceAccept: UInt8 = 6
        static let kexInit: UInt8 = 20
        static let newKeys: UInt8 = 21
        static let kexECDHInit: UInt8 = 30
        static let kexECDHReply: UInt8 = 31
        static let userauthRequest: UInt8 = 50
        static let userauthFailure: UInt8 = 51
        static let userauthSuccess: UInt8 = 52
        static let userauthBanner: UInt8 = 53
        static let globalRequest: UInt8 = 80
        static let requestFailure: UInt8 = 82
        static let channelOpen: UInt8 = 90
        static let channelOpenConfirm: UInt8 = 91
        static let channelWindowAdjust: UInt8 = 93
        static let channelData: UInt8 = 94
        static let channelExtData: UInt8 = 95
        static let channelEOF: UInt8 = 96
        static let channelClose: UInt8 = 97
        static let channelRequest: UInt8 = 98
        static let channelSuccess: UInt8 = 99
        static let channelFailure: UInt8 = 100
    }

    private let connection: SSHTCPConnection
    private var inbound: [UInt8] = []
    private var encrypt: IntegratedSSHGCMCipher?
    private var decrypt: IntegratedSSHGCMCipher?
    private var hostKeyVerified = false

    private(set) var diagnostics = ""
    private(set) var stage = "connect"
    private(set) var fingerprint = ""
    private(set) var hostKeyTypeName = "?"
    private var sessionID = Data()
    private var shellChannel: UInt32?

    init?(host: String, port: UInt16) {
        guard let connection = SSHTCPConnection(host: host, port: port) else { return nil }
        self.connection = connection
    }

    func close() { connection.cancel() }

    // MARK: - Handshake (shared by exec and shell)

    /// Runs the full transport handshake and user authentication, leaving the
    /// GCM ciphers active and the session ready for channel operations. Does
    /// NOT close the connection — callers own the lifecycle.
    private func establish(username: String, auth: SSHAuth, timeout: Double) async throws {
        switch await connection.open(timeout: timeout) {
        case .success: break
        case .failure(let error): throw SSHError.transport(error.localizedDescription)
        }

        let clientVersion = "SSH-2.0-NetToolbox_1.0"
        try await writeRaw(Data((clientVersion + "\r\n").utf8))
        var serverVersion = ""
        for _ in 0..<64 {
            let line = try await readLine()
            if line.hasPrefix("SSH-") { serverVersion = line; break }
        }
        guard serverVersion.hasPrefix("SSH-2.0") || serverVersion.hasPrefix("SSH-1.99") else {
            throw SSHError.unsupportedServer(serverVersion)
        }

        let clientKexInit = buildKexInit()
        try await sendPacket(clientKexInit)
        let serverKexInit = try await expect(Msg.kexInit)
        try requireCiphers(in: serverKexInit)

        let priv = Curve25519.KeyAgreement.PrivateKey()
        let qc = priv.publicKey.rawRepresentation
        var initPayload = Data([Msg.kexECDHInit])
        IntegratedSSHWire.putString(qc, into: &initPayload)
        try await sendPacket(initPayload)

        let reply = try await expect(Msg.kexECDHReply)
        var replyReader = IntegratedSSHWire.Reader(reply)
        _ = replyReader.readByte()
        guard let hostKey = replyReader.readString(),
              let qs = replyReader.readString(),
              let signature = replyReader.readString(),
              let serverPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: qs),
              let shared = try? priv.sharedSecretFromKeyAgreement(with: serverPub) else {
            throw SSHError.kexFailed
        }

        let sharedBytes = shared.withUnsafeBytes { Data($0) }
        let kMPInt = IntegratedSSHCrypto.mpint(sharedBytes)
        let exchangeHash = IntegratedSSHCrypto.exchangeHash(
            clientVersion: clientVersion, serverVersion: serverVersion,
            clientKexInit: clientKexInit, serverKexInit: serverKexInit,
            hostKey: hostKey, clientEphemeral: qc, serverEphemeral: qs,
            sharedSecretMPInt: kMPInt
        )
        hostKeyVerified = IntegratedSSHCrypto.verifyHostKey(blob: hostKey, signature: signature, over: exchangeHash)

        var keyTypeReader = IntegratedSSHWire.Reader(hostKey)
        hostKeyTypeName = keyTypeReader.readStringUTF8() ?? "?"
        fingerprint = "SHA256:" + Data(SHA256.hash(data: hostKey)).base64EncodedString()
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        let hHex = exchangeHash.prefix(6).map { String(format: "%02x", $0) }.joined()
        diagnostics = "SSHv2 host=\(hostKeyTypeName) verified=\(hostKeyVerified) vs=[\(serverVersion)] "
            + "ic=\(clientKexInit.count) is=\(serverKexInit.count) ks=\(hostKey.count) "
            + "qc=\(qc.count) qs=\(qs.count) K=\(sharedBytes.count) H=\(hHex)"

        stage = "newkeys"
        sessionID = exchangeHash
        let ivC2S = IntegratedSSHCrypto.deriveKey(letter: 0x41, length: 12, sharedSecretMPInt: kMPInt, exchangeHash: exchangeHash, sessionID: sessionID)
        let ivS2C = IntegratedSSHCrypto.deriveKey(letter: 0x42, length: 12, sharedSecretMPInt: kMPInt, exchangeHash: exchangeHash, sessionID: sessionID)
        let keyC2S = IntegratedSSHCrypto.deriveKey(letter: 0x43, length: 32, sharedSecretMPInt: kMPInt, exchangeHash: exchangeHash, sessionID: sessionID)
        let keyS2C = IntegratedSSHCrypto.deriveKey(letter: 0x44, length: 32, sharedSecretMPInt: kMPInt, exchangeHash: exchangeHash, sessionID: sessionID)

        try await sendPacket(Data([Msg.newKeys]))
        _ = try await expect(Msg.newKeys)
        encrypt = IntegratedSSHGCMCipher(key: keyC2S, iv: ivC2S)
        decrypt = IntegratedSSHGCMCipher(key: keyS2C, iv: ivS2C)

        stage = "service-request"
        var serviceRequest = Data([Msg.serviceRequest])
        IntegratedSSHWire.putString("ssh-userauth", into: &serviceRequest)
        try await sendPacket(serviceRequest)
        _ = try await expect(Msg.serviceAccept)
        stage = "userauth"
        try await authenticate(username: username, auth: auth)
    }

    /// Password or ed25519 public-key user authentication.
    private func authenticate(username: String, auth: SSHAuth) async throws {
        var request = Data([Msg.userauthRequest])
        IntegratedSSHWire.putString(username, into: &request)
        IntegratedSSHWire.putString("ssh-connection", into: &request)
        switch auth {
        case .password(let password):
            IntegratedSSHWire.putString("password", into: &request)
            request.append(0)                          // not changing the password
            IntegratedSSHWire.putString(password, into: &request)
        
        }
        try await sendPacket(request)

        while true {
            let payload = try await nextPayload()
            switch payload.first {
            case Msg.userauthSuccess: return
            case Msg.userauthBanner: continue
            case Msg.userauthFailure: throw SSHError.authFailed
            default: throw SSHError.protocolError
            }
        }
    }

    /// Opens a "session" channel and returns the server's channel id.
    private func openSessionChannel() async throws -> UInt32 {
        stage = "channel"
        var open = Data([Msg.channelOpen])
        IntegratedSSHWire.putString("session", into: &open)
        IntegratedSSHWire.putUInt32(0, into: &open)              // our channel
        IntegratedSSHWire.putUInt32(1_048_576, into: &open)      // initial window
        IntegratedSSHWire.putUInt32(32_768, into: &open)         // max packet
        try await sendPacket(open)

        let confirm = try await expect(Msg.channelOpenConfirm)
        var reader = IntegratedSSHWire.Reader(confirm)
        _ = reader.readByte()
        _ = reader.readUInt32()                        // our channel
        guard let remote = reader.readUInt32() else { throw SSHError.channelFailed }
        return remote
    }

    // MARK: - Exec

    func run(username: String, auth: SSHAuth, command: String, timeout: Double) async throws -> SSHRunResult {
        defer { connection.cancel() }
        try await establish(username: username, auth: auth, timeout: timeout)
        let remoteChannel = try await openSessionChannel()

        var exec = Data([Msg.channelRequest])
        IntegratedSSHWire.putUInt32(remoteChannel, into: &exec)
        IntegratedSSHWire.putString("exec", into: &exec)
        exec.append(1)                                 // want_reply
        IntegratedSSHWire.putString(command, into: &exec)
        try await sendPacket(exec)

        stage = "exec"
        var output = Data()
        var exitStatus: Int?
        var sinceAdjust = 0

        readLoop: while output.count < 4_000_000 {
            let payload = try await nextPayload()
            guard let code = payload.first else { continue }
            var reader = IntegratedSSHWire.Reader(payload)
            _ = reader.readByte()

            switch code {
            case Msg.channelData:
                _ = reader.readUInt32()
                if let chunk = reader.readString() {
                    output.append(chunk)
                    sinceAdjust += chunk.count
                }
            case Msg.channelExtData:
                _ = reader.readUInt32()
                _ = reader.readUInt32()                // data type (stderr)
                if let chunk = reader.readString() { output.append(chunk) }
            case Msg.channelRequest:
                _ = reader.readUInt32()
                let requestType = reader.readStringUTF8()
                _ = reader.readByte()                  // want_reply
                if requestType == "exit-status" { exitStatus = reader.readUInt32().map(Int.init) }
            case Msg.channelEOF, Msg.channelWindowAdjust:
                break
            case Msg.channelClose:
                var close = Data([Msg.channelClose])
                IntegratedSSHWire.putUInt32(remoteChannel, into: &close)
                try? await sendPacket(close)
                break readLoop
            default:
                break
            }

            if sinceAdjust >= 524_288 {
                try await sendWindowAdjust(remoteChannel, UInt32(sinceAdjust))
                sinceAdjust = 0
            }
        }

        return SSHRunResult(
            output: String(decoding: output, as: UTF8.self),
            fingerprint: fingerprint,
            hostKeyType: hostKeyTypeName,
            hostKeyVerified: hostKeyVerified,
            exitStatus: exitStatus
        )
    }

    // MARK: - Interactive shell (line oriented)

    /// Opens a pty + shell channel and leaves the session running. Drive it
    /// with `readShellChunk()` (a background reader) and `sendShell(_:)`.
    func openShell(username: String, auth: SSHAuth, timeout: Double) async throws {
        try await establish(username: username, auth: auth, timeout: timeout)
        let channel = try await openSessionChannel()
        shellChannel = channel

        var pty = Data([Msg.channelRequest])
        IntegratedSSHWire.putUInt32(channel, into: &pty)
        IntegratedSSHWire.putString("pty-req", into: &pty)
        pty.append(0)                                  // want_reply = false
        IntegratedSSHWire.putString("xterm", into: &pty)
        IntegratedSSHWire.putUInt32(80, into: &pty)              // columns
        IntegratedSSHWire.putUInt32(24, into: &pty)              // rows
        IntegratedSSHWire.putUInt32(0, into: &pty)               // width px
        IntegratedSSHWire.putUInt32(0, into: &pty)               // height px
        IntegratedSSHWire.putString(Data([0]), into: &pty)       // empty terminal modes (TTY_OP_END)
        try await sendPacket(pty)

        var shell = Data([Msg.channelRequest])
        IntegratedSSHWire.putUInt32(channel, into: &shell)
        IntegratedSSHWire.putString("shell", into: &shell)
        shell.append(0)                                // want_reply = false
        try await sendPacket(shell)
        stage = "shell"
    }

    /// Blocks until the next chunk of shell output arrives; returns nil when
    /// the channel closes. Called only from a single background reader task.
    func readShellChunk() async throws -> String? {
        guard shellChannel != nil else { return nil }
        while true {
            let payload = try await nextPayload()
            guard let code = payload.first else { continue }
            var reader = IntegratedSSHWire.Reader(payload)
            _ = reader.readByte()
            switch code {
            case Msg.channelData, Msg.channelExtData:
                if code == Msg.channelExtData { _ = reader.readUInt32() }
                _ = reader.readUInt32()
                if let chunk = reader.readString() { return String(decoding: chunk, as: UTF8.self) }
            case Msg.channelClose, Msg.channelEOF:
                return nil
            default:
                continue
            }
        }
    }

    /// Sends user input to the shell. Called only from the UI task, never
    /// concurrently with another send.
    func sendShell(_ text: String) async throws {
        guard let channel = shellChannel else { return }
        var data = Data([Msg.channelData])
        IntegratedSSHWire.putUInt32(channel, into: &data)
        IntegratedSSHWire.putString(Data(text.utf8), into: &data)
        try await sendPacket(data)
    }

    private func sendWindowAdjust(_ channel: UInt32, _ bytes: UInt32) async throws {
        var adjust = Data([Msg.channelWindowAdjust])
        IntegratedSSHWire.putUInt32(channel, into: &adjust)
        IntegratedSSHWire.putUInt32(bytes, into: &adjust)
        try await sendPacket(adjust)
    }

    // MARK: - KEXINIT

    private func buildKexInit() -> Data {
        var payload = Data([Msg.kexInit])
        payload.append(Data((0..<16).map { _ in UInt8.random(in: 0...255) }))   // cookie
        IntegratedSSHWire.putNameList(["curve25519-sha256", "curve25519-sha256@libssh.org"], into: &payload)
        IntegratedSSHWire.putNameList(["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"], into: &payload)
        IntegratedSSHWire.putNameList(["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"], into: &payload)   // c2s
        IntegratedSSHWire.putNameList(["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"], into: &payload)   // s2c
        IntegratedSSHWire.putNameList(["hmac-sha2-256", "hmac-sha2-512"], into: &payload)   // c2s (unused with GCM)
        IntegratedSSHWire.putNameList(["hmac-sha2-256", "hmac-sha2-512"], into: &payload)   // s2c
        IntegratedSSHWire.putNameList(["none"], into: &payload)     // compression c2s
        IntegratedSSHWire.putNameList(["none"], into: &payload)     // compression s2c
        IntegratedSSHWire.putNameList([], into: &payload)           // languages c2s
        IntegratedSSHWire.putNameList([], into: &payload)           // languages s2c
        payload.append(0)                                 // first_kex_packet_follows
        IntegratedSSHWire.putUInt32(0, into: &payload)              // reserved
        return payload
    }

    /// Confirms the server offers curve25519 key exchange and our GCM cipher
    /// in both directions — the only combination this client implements.
    private func requireCiphers(in kexInit: Data) throws {
        var reader = IntegratedSSHWire.Reader(kexInit)
        _ = reader.readByte()
        for _ in 0..<16 { _ = reader.readByte() }         // cookie
        guard let kex = reader.readNameList() else { throw SSHError.kexFailed }
        _ = reader.readNameList()                          // host keys
        guard let c2s = reader.readNameList(), let s2c = reader.readNameList() else { throw SSHError.kexFailed }
        let curve = kex.contains("curve25519-sha256") || kex.contains("curve25519-sha256@libssh.org")
        guard curve else { throw SSHError.noCipher }
        let ours = "aes256-gcm@openssh.com"
        guard c2s.contains(ours), s2c.contains(ours) else { throw SSHError.noCipher }
    }

    // MARK: - Packet framing

    private func sendPacket(_ payload: Data) async throws {
        if var cipher = encrypt {
            var pad = 16 - ((1 + payload.count) % 16)
            if pad < 4 { pad += 16 }
            var lengthField = Data()
            IntegratedSSHWire.putUInt32(UInt32(1 + payload.count + pad), into: &lengthField)
            let plaintext = Data([UInt8(pad)]) + payload + randomBytes(pad)
            guard let sealed = cipher.seal(plaintext: plaintext, lengthField: lengthField) else { throw SSHError.encryptFailed }
            encrypt = cipher
            try await writeRaw(lengthField + sealed)
        } else {
            var pad = 8 - ((4 + 1 + payload.count) % 8)
            if pad < 4 { pad += 8 }
            var packet = Data()
            IntegratedSSHWire.putUInt32(UInt32(1 + payload.count + pad), into: &packet)
            packet.append(UInt8(pad))
            packet.append(payload)
            packet.append(randomBytes(pad))
            try await writeRaw(packet)
        }
    }

    private func receivePacket() async throws -> Data {
        let lengthField = try await readExact(4)
        let packetLength = Int(lengthField.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) })
        guard packetLength > 0, packetLength <= 1_048_576 else { throw SSHError.protocolError }

        if var cipher = decrypt {
            let body = try await readExact(packetLength + 16)
            let ciphertext = Data(body.prefix(packetLength))
            let tag = Data(body.suffix(16))
            guard let plaintext = cipher.open(ciphertext: ciphertext, tag: tag, lengthField: lengthField) else {
                throw SSHError.decryptFailed(verified: hostKeyVerified)
            }
            decrypt = cipher
            return extractPayload(plaintext, packetLength: plaintext.count)
        } else {
            let rest = try await readExact(packetLength)
            return extractPayload(rest, packetLength: packetLength)
        }
    }

    /// Strips `padding_length` and the trailing padding from a packet body.
    private func extractPayload(_ body: Data, packetLength: Int) -> Data {
        let padLength = Int(body.first ?? 0)
        let payloadCount = packetLength - 1 - padLength
        guard payloadCount >= 0, body.count >= 1 + payloadCount else { return Data() }
        return Data(body.dropFirst().prefix(payloadCount))
    }

    /// Reads the next real payload, transparently handling transport-level
    /// housekeeping messages and turning DISCONNECT into an error.
    private func nextPayload() async throws -> Data {
        while true {
            let payload = try await receivePacket()
            guard let code = payload.first else { continue }
            switch code {
            case Msg.disconnect:
                var reader = IntegratedSSHWire.Reader(payload)
                _ = reader.readByte()
                _ = reader.readUInt32()
                throw SSHError.disconnectedByServer(reader.readStringUTF8() ?? "")
            case Msg.ignore, Msg.debug:
                continue
            case Msg.globalRequest:
                var reader = IntegratedSSHWire.Reader(payload)
                _ = reader.readByte()
                _ = reader.readStringUTF8()
                let wantReply = (reader.readByte() ?? 0) != 0
                if wantReply { try await sendPacket(Data([Msg.requestFailure])) }
                continue
            default:
                return payload
            }
        }
    }

    private func expect(_ code: UInt8) async throws -> Data {
        let payload = try await nextPayload()
        guard payload.first == code else { throw SSHError.protocolError }
        return payload
    }

    // MARK: - Raw byte I/O

    private func randomBytes(_ count: Int) -> Data {
        Data((0..<count).map { _ in UInt8.random(in: 0...255) })
    }

    private func writeRaw(_ data: Data) async throws {
        if case .failure(let error) = await connection.send(data) {
            throw SSHError.transport(error.localizedDescription)
        }
    }

    private func fill() async throws {
        switch await connection.receive() {
        case .success(let data):
            if data.isEmpty { throw SSHError.disconnected }
            inbound.append(contentsOf: data)
        case .failure(let error):
            throw SSHError.transport(error.localizedDescription)
        }
    }

    private func readExact(_ count: Int) async throws -> Data {
        while inbound.count < count { try await fill() }
        let head = Data(inbound[0..<count])
        inbound.removeFirst(count)
        return head
    }

    private func readLine() async throws -> String {
        while true {
            if let newline = inbound.firstIndex(of: 0x0A) {
                var line = Array(inbound[0...newline])
                inbound.removeFirst(newline + 1)
                // Trim trailing CR / LF at the BYTE level. Doing it on the
                // decoded String is wrong: Swift fuses "\r\n" into one grapheme
                // cluster, so `hasSuffix("\n")`/`hasSuffix("\r")` both miss it
                // and the CRLF survives — which corrupted V_S in the exchange
                // hash and broke key exchange against every \r\n server.
                while line.last == 0x0A || line.last == 0x0D { line.removeLast() }
                return String(decoding: line, as: UTF8.self)
            }
            try await fill()
        }
    }
}
