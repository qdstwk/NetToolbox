// PrivateTailnetSSHCore.swift
// Revision 3：面向 iPadOS Swift Playgrounds 的单文件 SSH Core。
// 本版本优先修复“真实密码测试”之前必须解决的安全边界；一般兼容性 Bug 留待实机测试。
// Sources/provenance are recorded in ../UPSTREAM_BASELINE.md and References/Rootshell/ROOTSHELL_BASELINE.md.
// Generated/frozen: 2026-09-26

import Foundation
import Network
import CryptoKit
import Security

// MARK: - SSHModels

// [ANNOTATION] 可持久化的连接配置。只保存地址、端口、用户名和可选 Host Key pin；密码不属于该模型。
struct SSHConnectionProfile: Codable, Identifiable, Sendable, Equatable {
    var id: UUID
    var label: String
    var host: String
    var port: UInt16
    var username: String
    var pinnedHostKey: PinnedSSHHostKey?

// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
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
// [ANNOTATION] 仅承载本次运行的密码，故意不遵循 Codable，避免无意进入持久化配置。
struct SSHPasswordCredential: Sendable {
    var password: String
}

// [ANNOTATION] 为 stdout/stderr/exit status 分离结果预留的数据模型；当前 run() 的公开返回路径仍使用 SSHRunResult。
struct SSHExecResult: Sendable, Equatable {
    var stdout: Data
    var stderr: Data
    var exitStatus: UInt32?
}

// [ANNOTATION] 终端尺寸模型；当前 openShell() 仍固定 80×24，后续 resize 能力尚未接入。
struct SSHTerminalSize: Sendable, Equatable {
    var columns: UInt32
    var rows: UInt32
    var pixelWidth: UInt32 = 0
    var pixelHeight: UInt32 = 0
}

// MARK: - SSHHostTrust

/// A locally trusted SSH server identity.
///
/// Security comparison is performed against `keyBlob` and `keyType`.
/// `fingerprint` is derived display metadata and is never the sole trust anchor.
// [ANNOTATION] 本地持久化的服务器身份锚点。真正比较的是 host+port+keyType+keyBlob；fingerprint 只用于人类确认显示。
struct PinnedSSHHostKey: Codable, Sendable, Equatable {
    let host: String
    let port: UInt16
    let keyType: String
    let keyBlob: Data
    let fingerprint: String
    let firstSeen: Date

// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
    init(host: String, port: UInt16, keyType: String, keyBlob: Data, firstSeen: Date = Date()) {
        self.host = host
        self.port = port
        self.keyType = keyType
        self.keyBlob = keyBlob
        self.fingerprint = Self.sha256Fingerprint(of: keyBlob)
        self.firstSeen = firstSeen
    }

// [ANNOTATION] 此函数封装本类型中的一个独立协议/状态操作；输入边界与错误返回保持原 R3 行为，不在注释版中改变控制流。
    func matches(host: String, port: UInt16, keyType: String, keyBlob: Data) -> Bool {
        self.host == host &&
        self.port == port &&
        self.keyType == keyType &&
        self.keyBlob == keyBlob
    }

// [ANNOTATION] 此函数封装本类型中的一个独立协议/状态操作；输入边界与错误返回保持原 R3 行为，不在注释版中改变控制流。
    static func sha256Fingerprint(of keyBlob: Data) -> String {
        let digest = Data(SHA256.hash(data: keyBlob))
        return "SHA256:" + digest.base64EncodedString().trimmingCharacters(in: CharacterSet(charactersIn: "="))
    }
}

// [ANNOTATION] 把 TOFU/pin 判断显式建模为首次使用、可信匹配、密钥变化三种互斥结果。
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
// [ANNOTATION] 执行 Host Key pin 决策：无 pin 为首次使用，完全匹配为 trusted，任何已 pin 后的差异为 changed。
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

// MARK: - SSHTCPConnection

// [ANNOTATION] TCP/目的地址门禁层的错误集合，与更高层 SSH 协议错误分开。
enum SSHTransportError: LocalizedError, Sendable, Equatable {
    case invalidEndpoint
    case destinationOutsideTailnet          // 目标不是允许的 Tailnet IPv4：在创建 socket 前拒绝
    case timeout
    case connection(String)
    case closed

    var errorDescription: String? {
        switch self {
        case .invalidEndpoint: return "Invalid TCP endpoint"
        case .destinationOutsideTailnet: return "Destination is outside the allowed Tailnet IPv4 range"
        case .timeout: return "TCP connection timed out"
        case .connection(let message): return "TCP connection failed: \(message)"
        case .closed: return "TCP connection closed"
        }
    }
}

// [ANNOTATION] 线程安全的一次性 continuation 容器，保证多个 NWConnection 状态回调只能完成等待者一次。
private final class SSHOneShot<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?
// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
    init(_ continuation: CheckedContinuation<Value, Never>) { self.continuation = continuation }
// [ANNOTATION] 此函数封装本类型中的一个独立协议/状态操作；输入边界与错误返回保持原 R3 行为，不在注释版中改变控制流。
    func resume(_ value: Value) {
        lock.lock()
        let c = continuation
        continuation = nil
        lock.unlock()
        c?.resume(returning: value)
    }
}

// [ANNOTATION] 用 NSLock 实现一次性 claim，配合 SSHOneShot 消除连接状态与 timeout 的竞态。
private final class SSHAtomicFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
// [ANNOTATION] 此函数封装本类型中的一个独立协议/状态操作；输入边界与错误返回保持原 R3 行为，不在注释版中改变控制流。
    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard !claimed else { return false }
        claimed = true
        return true
    }
}

/// Tailnet-only 出站策略。
/// 当前版本故意只接受 Tailscale 默认 IPv4 CGNAT 段 100.64.0.0/10。
/// 注意：100.64/10 本身并不能证明“属于我们的 tailnet”；真正的授权边界仍由 Tailscale Grants + Host Key pin 提供。
// [ANNOTATION] 在创建 socket 前执行目的地址策略；当前 v1 故意只接受规范的 100.64.0.0/10 IPv4。
enum SSHTailnetDestinationPolicy {
// [ANNOTATION] 把用户输入收紧为无歧义的规范十进制 IPv4；这是 Tailnet 出站门禁的第一步，任何 DNS、IPv6、符号、十六进制或前导零形式都不会进入连接层。
    static func canonicalIPv4(_ input: String) -> String? {
        let parts = input.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        octets.reserveCapacity(4)
        for part in parts {
            // 只接受十进制规范 IPv4；拒绝空段、符号、十六进制和可能产生歧义的前导零。
            guard !part.isEmpty, part.allSatisfy({ $0.isNumber }),
                  part.count == 1 || part.first != "0",
                  let value = UInt8(part) else { return nil }
            octets.append(value)
        }
        return octets.map(String.init).joined(separator: ".")
    }

// [ANNOTATION] 只允许 Tailscale 默认 CGNAT IPv4 范围 100.64.0.0/10。这里仅限制目的地址形态，不把该地址段误当作身份认证。
    static func allows(_ host: String) -> Bool {
        guard let ip = canonicalIPv4(host) else { return false } // 域名/IPv6/LAN/public IPv4 一律拒绝
        let o = ip.split(separator: ".").compactMap { UInt8($0) }
        guard o.count == 4 else { return false }
        // 100.64.0.0/10：首字节必须 100，第二字节高两位必须为 01，即 64...127。
        return o[0] == 100 && (64...127).contains(o[1])
    }
}

/// Long-lived TCP byte stream for the SSH transport.
/// Deliberately uses Network.framework directly: no NIO/Citadel/C target.
// [ANNOTATION] SSH Core 的 TCP 字节流适配层，直接使用 Apple Network.framework，不引入 NIO/Citadel/C runtime。
final class SSHTCPConnection: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "PrivateTailnetSSH.transport")

// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
    init?(host: String, port: UInt16) {
        let h = host.trimmingCharacters(in: .whitespacesAndNewlines)
        // 第一层硬门禁：不允许 DNS，也不允许普通 LAN/公网地址进入 NWConnection。
        guard SSHTailnetDestinationPolicy.allows(h),
              let canonical = SSHTailnetDestinationPolicy.canonicalIPv4(h),
              let p = NWEndpoint.Port(rawValue: port) else { return nil }
        connection = NWConnection(host: NWEndpoint.Host(canonical), port: p, using: .tcp)
    }

// [ANNOTATION] 使用当前 AES-GCM nonce 验证并解密服务器 packet；认证失败不会返回明文，并且 nonce 只在成功后推进。
    func open(timeout: Double) async -> Result<Void, SSHTransportError> {
        await withCheckedContinuation { continuation in
            let shot = SSHOneShot(continuation)
            let settled = SSHAtomicFlag()
            let connection = self.connection
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if settled.claim() { shot.resume(.success(())) }
                case .waiting:
                    // NWConnection.waiting is recoverable; let .ready/.failed/.cancelled or timeout decide.
                    break
                case .failed(let error):
                    if settled.claim() { shot.resume(.failure(.connection(String(reflecting: error)))) }
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

// [ANNOTATION] 把 Network.framework 的回调式发送包装成 async Result；只有 contentProcessed 成功才视为本次字节写入完成。
    func send(_ data: Data) async -> Result<Void, SSHTransportError> {
        await withCheckedContinuation { continuation in
            let shot = SSHOneShot(continuation)
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { shot.resume(.failure(.connection(error.localizedDescription))) }
                else { shot.resume(.success(())) }
            })
        }
    }

// [ANNOTATION] 从 TCP 字节流取得下一段数据；空数据与连接完成分别处理，供上层 readExact/fill 重新组装 SSH packet。
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

// [ANNOTATION] 此函数封装本类型中的一个独立协议/状态操作；输入边界与错误返回保持原 R3 行为，不在注释版中改变控制流。
    func cancel() { connection.cancel() }
}

// MARK: - SSHWire

/// SSH binary encoding primitives (RFC 4251 §5). Pure and unit-tested:
/// the transport layer builds and parses every packet through these.
// [ANNOTATION] SSH 二进制 wire-format 的最小编码/解码工具集。
enum IntegratedSSHWire {
    /// Appends a `uint32` in network byte order.
// [ANNOTATION] 按 SSH wire format 使用网络字节序写入 32 位无符号整数。
    static func putUInt32(_ value: UInt32, into input: Data) -> Data {
        var data = input
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
        return data
    }

    /// Appends an SSH `string`: a `uint32` length followed by the raw bytes.
// [ANNOTATION] 写入 SSH string：先写 4 字节长度，再写原始 payload；文本重载先转 UTF-8。
    static func putString(_ bytes: Data, into input: Data) -> Data {
        var data = input
        data = putUInt32(UInt32(bytes.count), into: data)
        data.append(bytes)
        return data
    }

    /// Appends an SSH `string` from UTF-8 text.
// [ANNOTATION] 写入 SSH string：先写 4 字节长度，再写原始 payload；文本重载先转 UTF-8。
    static func putString(_ text: String, into input: Data) -> Data {
        putString(Data(text.utf8), into: input)
    }

    /// Appends a comma-joined `name-list` as an SSH `string`.
// [ANNOTATION] 把算法列表用逗号连接后按 SSH string 编码，对应 SSH name-list。
    static func putNameList(_ names: [String], into input: Data) -> Data {
        putString(names.joined(separator: ","), into: input)
    }

    /// Appends an `mpint` (RFC 4251 §5): a two's-complement big-endian
    /// integer. A leading zero byte is inserted when the high bit is set so
    /// the value is never misread as negative; zero encodes as empty.
// [ANNOTATION] 按 RFC 4251 编码正 mpint：去掉多余前导零，必要时补 0x00 防止最高位被解释为负数。
    static func putMPInt(_ magnitude: Data, into input: Data) -> Data {
        let data = input
        var bytes = Array(magnitude)
        while bytes.first == 0 { bytes.removeFirst() }   // strip leading zeros
        if bytes.isEmpty {
            return putUInt32(0, into: data)
        }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return putString(Data(bytes), into: data)
    }

    /// Sequential reader over an SSH payload.
    struct Reader {
        private let data: Data
        private var index: Int

// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
        init(_ data: Data) {
            self.data = data
            self.index = data.startIndex
        }

        var isAtEnd: Bool { index >= data.endIndex }
        var remaining: Data { data[index...] }

// [ANNOTATION] 从当前游标读取一个字节并推进游标；越界返回 nil，让调用方 fail closed。
        mutating func readByte() -> UInt8? {
            guard index < data.endIndex else { return nil }
            defer { index += 1 }
            return data[index]
        }

// [ANNOTATION] 按网络字节序读取 uint32，并在长度不足时返回 nil。
        mutating func readUInt32() -> UInt32? {
            guard index + 4 <= data.endIndex else { return nil }
            let slice = data[index..<index + 4]
            index += 4
            return slice.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        }

// [ANNOTATION] 按网络字节序读取 uint64；主要用于固定宽度协议字段/计数器解析。
        mutating func readUInt64() -> UInt64? {
            guard index + 8 <= data.endIndex else { return nil }
            let slice = data[index..<index + 8]
            index += 8
            return slice.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }

// [ANNOTATION] 读取 SSH string 的长度前缀与对应字节，并检查边界，拒绝越界长度。
        mutating func readString() -> Data? {
            guard let length = readUInt32() else { return nil }
            let count = Int(length)
            guard index + count <= data.endIndex else { return nil }
            let slice = data[index..<index + count]
            index += count
            return Data(slice)
        }

// [ANNOTATION] 把 SSH string 解码为 UTF-8 文本；字节边界检查仍由 readString 负责。
        mutating func readStringUTF8() -> String? {
            guard let bytes = readString() else { return nil }
            return String(decoding: bytes, as: UTF8.self)
        }

// [ANNOTATION] 读取逗号分隔的 SSH name-list；空字符串按空列表处理。
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
// [ANNOTATION] 仅依赖 CryptoKit + Security 的 KEX/KDF/Host Key 验证实现。
enum IntegratedSSHCrypto {
    /// SHA-256 exchange hash H over the ordered kex fields (RFC 5656 §4).
// [ANNOTATION] 按 SSH KEX 规定顺序拼接版本、双方 KEXINIT、Host Key、双方临时公钥和共享秘密 K，再计算 SHA-256；字段顺序或编码变化都会导致 Host Key 签名验证失败。
    static func exchangeHash(
        clientVersion: String, serverVersion: String,
        clientKexInit: Data, serverKexInit: Data,
        hostKey: Data, clientEphemeral: Data, serverEphemeral: Data,
        sharedSecretMPInt: Data
    ) -> Data {
        var buffer = Data()
        buffer = IntegratedSSHWire.putString(clientVersion, into: buffer)
        buffer = IntegratedSSHWire.putString(serverVersion, into: buffer)
        buffer = IntegratedSSHWire.putString(clientKexInit, into: buffer)
        buffer = IntegratedSSHWire.putString(serverKexInit, into: buffer)
        buffer = IntegratedSSHWire.putString(hostKey, into: buffer)
        buffer = IntegratedSSHWire.putString(clientEphemeral, into: buffer)
        buffer = IntegratedSSHWire.putString(serverEphemeral, into: buffer)
        buffer.append(sharedSecretMPInt)   // already length-prefixed by putMPInt
        return Data(SHA256.hash(data: buffer))
    }

    /// Derives one key stream (RFC 4253 §7.2): HASH(K || H || letter || id),
    /// extended by re-hashing K || H || sofar until `length` bytes exist.
// [ANNOTATION] 实现 RFC 4253 KDF。使用 K、交换哈希 H、方向字母和 session ID 派生 IV/对称密钥，并在需要时扩展到目标长度。
    static func deriveKey(
        letter: UInt8, length: Int,
        sharedSecretMPInt K: Data, exchangeDigest H: Data, sessionID: Data
    ) -> Data {
        var initialInput = Data()
        initialInput.append(K)
        initialInput.append(H)
        initialInput.append(letter)
        initialInput.append(sessionID)
        var key = Data(SHA256.hash(data: initialInput))
        while key.count < length {
            var extensionInput = Data()
            extensionInput.append(K)
            extensionInput.append(H)
            extensionInput.append(key)
            key.append(Data(SHA256.hash(data: extensionInput)))
        }
        return Data(key.prefix(length))
    }

    /// mpint magnitude bytes (strip leading zeros) for the shared secret, so
    /// the caller can pass it to both the hash and the KDF consistently.
// [ANNOTATION] 把共享秘密的 magnitude 转成 SSH mpint 的完整 wire 表示，保证 exchange hash 与 KDF 使用同一编码。
    static func mpint(_ magnitude: Data) -> Data {
        var buffer = Data()
        buffer = IntegratedSSHWire.putMPInt(magnitude, into: buffer)
        return buffer
    }

    // MARK: - Host key signature verification

    /// Verifies the server's signature over the exchange hash with the host
    /// key it presented. Returns false for any parse error or unknown type.
// [ANNOTATION] 解析服务器 Host Key 与 signature blob，并按 ed25519 / ECDSA P-256 / RSA-SHA2 分支进行密码学验证；任何未知类型或解析异常都返回 false。
    static func verifyHostKey(blob: Data, signature: Data, over hash: Data) -> Bool {
        var keyReader = IntegratedSSHWire.Reader(blob)
        guard let keyType = keyReader.readStringUTF8() else { return false }
        var sigReader = IntegratedSSHWire.Reader(signature)
        guard let sigType = sigReader.readStringUTF8(),
              let sigBlob = sigReader.readString() else { return false }

        switch keyType {
        case "ssh-ed25519":
            guard sigType == "ssh-ed25519",
                  let pub = keyReader.readString(), pub.count == 32,
                  keyReader.isAtEnd, sigReader.isAtEnd,
                  let key = try? Curve25519.Signing.PublicKey(rawRepresentation: pub) else { return false }
            return key.isValidSignature(sigBlob, for: hash)

        case "ecdsa-sha2-nistp256":
            guard sigType == "ecdsa-sha2-nistp256",
                  keyReader.readStringUTF8() == "nistp256",     // 算法名与曲线名必须一致，拒绝算法混淆
                  let point = keyReader.readString(), keyReader.isAtEnd,
                  sigReader.isAtEnd,
                  let key = try? P256.Signing.PublicKey(x963Representation: point) else { return false }
            // The ecdsa signature blob is itself string(mpint r) || string(mpint s).
            var inner = IntegratedSSHWire.Reader(sigBlob)
            guard let r = inner.readString(), let s = inner.readString(), inner.isAtEnd,
                  let r32 = strictP256Scalar(r), let s32 = strictP256Scalar(s),
                  let raw = try? P256.Signing.ECDSASignature(rawRepresentation: r32 + s32) else { return false }
            return key.isValidSignature(raw, for: hash)

        case "ssh-rsa":
            return verifyRSA(keyReader: keyReader, sigType: sigType, signature: sigBlob, hash: hash)

        default:
            return false
        }
    }

    /// Left-pads (or trims) an mpint magnitude to exactly 32 bytes for the
    /// fixed-width raw ECDSA representation CryptoKit expects.
// [ANNOTATION] 把 SSH ECDSA 的正 mpint r/s 严格规范成 CryptoKit 要求的 32 字节标量；超长、空值直接拒绝。
    private static func strictP256Scalar(_ value: Data) -> Data? {
        // SSH ECDSA 的 r/s 是正 mpint；去掉合法的符号零后最多只能有 32 字节。
        var bytes = Array(value)
        while bytes.first == 0 { bytes.removeFirst() }
        guard !bytes.isEmpty, bytes.count <= 32 else { return nil }
        return Data(repeating: 0, count: 32 - bytes.count) + Data(bytes)
    }

// [ANNOTATION] 把 SSH RSA 的 n/e 转成 DER 公钥，通过 Security.framework 按协商的 rsa-sha2-256/512 验证交换哈希签名。
    private static func verifyRSA(
        keyReader inputReader: IntegratedSSHWire.Reader, sigType: String, signature: Data, hash: Data
    ) -> Bool {
        var keyReader = inputReader
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
        guard SecKeyIsAlgorithmSupported(key, .verify, algorithm) else { return false }
        return SecKeyVerifySignature(key, algorithm, hash as CFData, signature as CFData, nil)
        #else
        return false
        #endif
    }

    // MARK: - Minimal DER

// [ANNOTATION] 生成 DER length 字段，供临时构造 RSA Subject key material。
    private static func derLength(_ count: Int) -> Data {
        if count < 0x80 { return Data([UInt8(count)]) }
        var bytes: [UInt8] = []
        var value = count
        while value > 0 { bytes.insert(UInt8(value & 0xFF), at: 0); value >>= 8 }
        return Data([0x80 | UInt8(bytes.count)] + bytes)
    }

// [ANNOTATION] 把无符号 magnitude 编成正 DER INTEGER，必要时补符号零。
    private static func derInteger(_ magnitude: Data) -> Data {
        var bytes = Array(magnitude)
        while bytes.first == 0 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }   // keep it positive
        return Data([0x02]) + derLength(bytes.count) + Data(bytes)
    }

// [ANNOTATION] 把多个 DER 元素包装成 SEQUENCE。
    private static func derSequence(_ elements: [Data]) -> Data {
        let body = elements.reduce(Data(), +)
        return Data([0x30]) + derLength(body.count) + body
    }
}

/// AES-256-GCM packet cipher for `aes256-gcm@openssh.com` (RFC 5647): a
/// 12-byte nonce of a fixed 4-byte prefix plus an 8-byte invocation counter
/// that increments after every packet.
// [ANNOTATION] OpenSSH aes256-gcm@openssh.com 的每方向 packet cipher 状态，持有 key、固定 IV 前缀和单调 nonce counter。
struct IntegratedSSHGCMCipher {
    private let key: SymmetricKey
    private let fixed: Data           // 4 bytes
    private var counter: UInt64       // 8-byte invocation counter

// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
    init(key: Data, iv: Data) {
        self.key = SymmetricKey(data: key)
        self.fixed = iv.prefix(4)
        self.counter = iv.dropFirst(4).prefix(8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

// [ANNOTATION] 按 OpenSSH AES-GCM 约定推进 64 位 invocation counter；禁止溢出回绕以避免 nonce 重用。
    private mutating func nextNonce() throws -> Data {
        // AES-GCM 的同一 key 下绝不能重复 nonce；计数器耗尽时必须终止而不是回绕。
        guard counter != UInt64.max else { throw SSHError.encryptFailed }
        var nonce = Data(fixed)
        var value = counter
        var tail = [UInt8](repeating: 0, count: 8)
        for index in stride(from: 7, through: 0, by: -1) {
            tail[index] = UInt8(value & 0xFF); value >>= 8
        }
        nonce.append(contentsOf: tail)
        counter += 1
        return nonce
    }

    /// Seals `plaintext` (padding_length || payload || padding) with the
    /// 4-byte `lengthField` as additional data. Returns ciphertext || tag.
// [ANNOTATION] 使用当前 AES-GCM nonce 加密一个 SSH packet body，并把 4 字节 packet_length 作为 AAD；成功后只前进一次 nonce。
    mutating func seal(plaintext: Data, lengthField: Data) -> Data? {
        guard let box = try? AES.GCM.seal(
            plaintext, using: key,
            nonce: try AES.GCM.Nonce(data: try nextNonce()),
            authenticating: lengthField
        ) else { return nil }
        return box.ciphertext + box.tag
    }

    /// Opens `ciphertext` + 16-byte `tag` authenticated by `lengthField`.
// [ANNOTATION] 使用当前 AES-GCM nonce 验证并解密服务器 packet；认证失败不会返回明文，并且 nonce 只在成功后推进。
    mutating func open(ciphertext: Data, tag: Data, lengthField: Data) -> Data? {
        guard let box = try? AES.GCM.SealedBox(
            nonce: try AES.GCM.Nonce(data: try nextNonce()),
            ciphertext: ciphertext, tag: tag
        ) else { return nil }
        return try? AES.GCM.open(box, using: key, authenticating: lengthField)
    }
}


// [ANNOTATION] 异步发送互斥门，核心目的不是 UI 同步，而是确保 AES-GCM nonce 与 packet 顺序一一对应。
private actor SSHSendGate {
    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

// [ANNOTATION] 取得发送门；用于保证多个异步调用不会并发消费同一个 GCM 发送 nonce。
    func enter() async {
        if !busy { busy = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }

// [ANNOTATION] 释放发送门并唤醒下一个等待者，使 SSH packet 写入保持严格串行。
    func leave() {
        if waiters.isEmpty { busy = false }
        else { waiters.removeFirst().resume() }
    }
}

// MARK: - SSHClient

/// Outcome of a one-shot SSH exec session.
// [ANNOTATION] 一次 exec 对外返回的结果与已验证服务器身份摘要。
struct SSHRunResult: Sendable {
    var output: String
    var fingerprint: String
    var hostKeyType: String
    var hostKeyVerified: Bool
    var exitStatus: Int?
}

/// How to authenticate an SSH session.
// [ANNOTATION] 当前 v1 认证方式枚举；只实现 password。
enum SSHAuth: Sendable { case password(String) }

// [ANNOTATION] Core 对外暴露的安全、协议、认证、channel 与加解密错误。
enum SSHError: LocalizedError {
    case transport(String)
    case disconnected
    case disconnectedByServer(String)
    case unsupportedServer(String)
    case noCipher
    case kexFailed
    case invalidHostKeySignature              // 服务器无法证明自己持有 Host Key 私钥：必须在发送密码前终止
    case hostKeyConfirmationRequired(PinnedSSHHostKey) // 首次连接：把指纹交给 UI，由用户确认后重连
    case hostKeyChanged                       // 已固定的 Host Key 发生变化：硬阻断，绝不自动替换
    case authFailed
    case handshakeTimeout                    // TCP 已建立后，KEX/Host Key/NEWKEYS/userauth 超过总 deadline：强制关闭连接
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
        case .invalidHostKeySignature: return "SSH server host-key signature is invalid"
        case .hostKeyConfirmationRequired(let key): return "Confirm SSH host key before login: \(key.fingerprint)"
        case .hostKeyChanged: return "SSH host key changed; password was not sent"
        case .authFailed: return "SSH authentication failed"
        case .handshakeTimeout: return "SSH handshake/authentication timed out"
        case .channelFailed: return "SSH channel failed"
        case .protocolError: return "SSH protocol error"
        case .encryptFailed: return "SSH encryption failed"
        case .decryptFailed(let verified):
            return "SSH decryption failed (host key verified: \(verified))"
        }
    }
}

/// A minimal SSH-2 client (curve25519-sha256 + aes256-gcm@openssh.com;
/// password authentication only; host-key verification supports the algorithms listed below.
/// built entirely on CryptoKit/Security so the package keeps zero external
/// dependencies. Supports one-shot exec and a line-oriented interactive shell.
// [ANNOTATION] SSH v2 单连接客户端状态机：负责 KEX、Host Key 信任、认证、exec、line-oriented shell 与 packet framing。
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
    private let host: String                 // 当前连接目标；Host Key pin 必须绑定到这个主机
    private let port: UInt16                 // 当前 SSH 端口；同一主机不同端口分别建立信任
    private let pinnedHostKey: PinnedSSHHostKey? // UI/持久化层传入的既有 pin；这里绝不自动覆盖
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var inbound: [UInt8] = []
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var encrypt: IntegratedSSHGCMCipher?
// [ANNOTATION] 发送门保护 packet 顺序和 GCM nonce 的唯一消费；即使上层出现多个 Task，也不能绕过它直接并发写加密 packet。
    private let sendGate = SSHSendGate()       // 串行化所有 outbound packet，保护 AES-GCM nonce/counter 不发生并发复用
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var decrypt: IntegratedSSHGCMCipher?
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var hostKeyVerified = false
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var negotiatedHostKeyAlgorithm = "" // KEXINIT 实际选中的服务器签名算法；验签时必须与 Host Key 对应

    private(set) var diagnostics = ""
    private(set) var stage = "connect"
    private(set) var fingerprint = ""
    private(set) var hostKeyTypeName = "?"
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var sessionID = Data()
// [ANNOTATION] 这是 SSH 连接状态机的跨步骤状态；其生命周期覆盖后续 KEX/加密/channel 操作，不能在未理解状态转换的情况下重置或共享。
    private var shellChannel: UInt32?

// [ANNOTATION] 初始化仅建立当前类型所需状态；所有 guard/默认值均属于冻结 R3 的原始安全或协议行为。
    init?(host: String, port: UInt16, pinnedHostKey: PinnedSSHHostKey? = nil) {
        // 只接受能够建立明确 TCP endpoint 的主机；pin 与原始 host+port 一起绑定。
        let requestedHost = host.trimmingCharacters(in: .whitespacesAndNewlines)
        // 第二层门禁：Client 自身也拒绝非 Tailnet IPv4，避免未来替换 transport 时绕过策略。
        guard SSHTailnetDestinationPolicy.allows(requestedHost),
              let canonicalHost = SSHTailnetDestinationPolicy.canonicalIPv4(requestedHost),
              let connection = SSHTCPConnection(host: canonicalHost, port: port) else { return nil }
        self.connection = connection
        self.host = canonicalHost
        self.port = port
        self.pinnedHostKey = pinnedHostKey
    }

// [ANNOTATION] 此函数封装本类型中的一个独立协议/状态操作；输入边界与错误返回保持原 R3 行为，不在注释版中改变控制流。
    func close() { connection.cancel() }

    // MARK: - Handshake (shared by exec and shell)

    /// Runs the full transport handshake and user authentication, leaving the
    /// GCM ciphers active and the session ready for channel operations. Does
    /// NOT close the connection — callers own the lifecycle.
// [ANNOTATION] 完整 SSH 建链状态机：TCP → identification → KEXINIT → X25519 → Host Key 签名验证 → pin 决策 → NEWKEYS → userauth service → 密码认证。真实密码路径只能发生在 Host Key 验证与信任检查之后。
    private func establish(username: String, auth: SSHAuth, timeout: Double) async throws {
        switch await connection.open(timeout: timeout) {
        case .success: break
        case .failure(let error): throw SSHError.transport(error.localizedDescription)
        }

        // TCP READY 以后仍必须有独立的总 deadline。仅取消 Swift Task 不足以保证
        // Network.framework 的 pending receive 立即退出，因此 watchdog 到期时直接
        // cancel 底层 NWConnection；这会打断 readLine/readExact/expect/authenticate。
        let handshakeDeadline = max(timeout, 1.0)
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(handshakeDeadline))
        let watchdog = Task { [connection] in
            do {
                try await Task.sleep(for: .seconds(handshakeDeadline))
                guard !Task.isCancelled else { return }
                connection.cancel()
            } catch {
                // establish 正常结束时 watchdog 被 cancel；无需做任何事。
            }
        }
        defer { watchdog.cancel() }

        do {
            try await establishAfterTCPReady(username: username, auth: auth)
        } catch {
            if clock.now >= deadline { throw SSHError.handshakeTimeout }
            throw error
        }
        if clock.now >= deadline { throw SSHError.handshakeTimeout }
    }

    // TCP 已经 READY；本函数中的所有网络等待均受 establish() 的 watchdog 约束。
    private func establishAfterTCPReady(username: String, auth: SSHAuth) async throws {
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

        let clientKexInit = try buildKexInit()
        try await sendPacket(clientKexInit)
        let serverKexInit = try await expect(Msg.kexInit)
        negotiatedHostKeyAlgorithm = try requireAlgorithms(in: serverKexInit)

        let priv = Curve25519.KeyAgreement.PrivateKey()
        let qc = priv.publicKey.rawRepresentation
        var initPayload = Data([Msg.kexECDHInit])
        initPayload = IntegratedSSHWire.putString(qc, into: initPayload)
        try await sendPacket(initPayload)

        let reply = try await expect(Msg.kexECDHReply)
        var replyReader = IntegratedSSHWire.Reader(reply)
        _ = replyReader.readByte()
        guard let hostKey = replyReader.readString(),
              let qs = replyReader.readString(), qs.count == 32, // RFC 8731：X25519 公钥必须正好 32 字节
              let signature = replyReader.readString(), replyReader.isAtEnd,
              let serverPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: qs),
              let shared = try? priv.sharedSecretFromKeyAgreement(with: serverPub) else {
            throw SSHError.kexFailed
        }

        let sharedBytes = shared.withUnsafeBytes { Data($0) }
        // RFC 8731 要求全零共享秘密立即终止，防止低阶点导致无效密钥交换。
        guard sharedBytes.contains(where: { $0 != 0 }) else { throw SSHError.kexFailed }
        let kMPInt = IntegratedSSHCrypto.mpint(sharedBytes)
        let exchangeHash = IntegratedSSHCrypto.exchangeHash(
            clientVersion: clientVersion, serverVersion: serverVersion,
            clientKexInit: clientKexInit, serverKexInit: serverKexInit,
            hostKey: hostKey, clientEphemeral: qc, serverEphemeral: qs,
            sharedSecretMPInt: kMPInt
        )
        hostKeyVerified = IntegratedSSHCrypto.verifyHostKey(blob: hostKey, signature: signature, over: exchangeHash)
        // 安全边界 1：签名失败时服务器身份没有密码学证明；绝不能继续到 userauth。
        guard hostKeyVerified else { throw SSHError.invalidHostKeySignature }

        var keyTypeReader = IntegratedSSHWire.Reader(hostKey)
        hostKeyTypeName = keyTypeReader.readStringUTF8() ?? "?"
        // negotiated rsa-sha2-* 使用 ssh-rsa 公钥 blob；Ed25519/ECDSA 则算法名与 blob 类型相同。
        let expectedBlobType = negotiatedHostKeyAlgorithm.hasPrefix("rsa-sha2-") ? "ssh-rsa" : negotiatedHostKeyAlgorithm
        guard hostKeyTypeName == expectedBlobType else { throw SSHError.invalidHostKeySignature }
        // 签名 blob 内的算法名也必须等于 KEXINIT 真正协商出的 host-key algorithm。
        var negotiatedSigReader = IntegratedSSHWire.Reader(signature)
        guard negotiatedSigReader.readStringUTF8() == negotiatedHostKeyAlgorithm else { throw SSHError.invalidHostKeySignature }
        fingerprint = PinnedSSHHostKey.sha256Fingerprint(of: hostKey)
        // 安全边界 2：在构造任何密码认证包之前完成 TOFU/pin 决策。
        let trustDecision = SSHHostTrust.evaluate(
            host: host,
            port: port,
            keyType: hostKeyTypeName,
            keyBlob: hostKey,
            pinned: pinnedHostKey
        )
        switch trustDecision {
        case .trusted:
            break                                      // exact key match：允许进入 userauth
        case .firstUse(let presented):
            throw makeHostKeyConfirmationError(presented) // UI 确认并保存 pin 后重新连接
        case .changed:
            throw SSHError.hostKeyChanged              // key 变化绝不在本次连接中提供“继续”旁路
        }
        // 生产诊断只保留非秘密状态；不记录 H、K、密码或密钥材料。
        diagnostics = "SSHv2 host=\(hostKeyTypeName) verified=true server=[\(serverVersion)]"

        stage = "newkeys"
        sessionID = exchangeHash
        let ivC2S = IntegratedSSHCrypto.deriveKey(letter: 0x41, length: 12, sharedSecretMPInt: kMPInt, exchangeDigest: exchangeHash, sessionID: sessionID)
        let ivS2C = IntegratedSSHCrypto.deriveKey(letter: 0x42, length: 12, sharedSecretMPInt: kMPInt, exchangeDigest: exchangeHash, sessionID: sessionID)
        let keyC2S = IntegratedSSHCrypto.deriveKey(letter: 0x43, length: 32, sharedSecretMPInt: kMPInt, exchangeDigest: exchangeHash, sessionID: sessionID)
        let keyS2C = IntegratedSSHCrypto.deriveKey(letter: 0x44, length: 32, sharedSecretMPInt: kMPInt, exchangeDigest: exchangeHash, sessionID: sessionID)

        try await sendPacket(Data([Msg.newKeys]))
        _ = try await expect(Msg.newKeys)
        encrypt = IntegratedSSHGCMCipher(key: keyC2S, iv: ivC2S)
        decrypt = IntegratedSSHGCMCipher(key: keyS2C, iv: ivS2C)

        stage = "service-request"
        var serviceRequest = Data([Msg.serviceRequest])
        serviceRequest = IntegratedSSHWire.putString("ssh-userauth", into: serviceRequest)
        try await sendPacket(serviceRequest)
        _ = try await expect(Msg.serviceAccept)
        stage = "userauth"
        try await authenticate(username: username, auth: auth)
    }

    /// 密码认证：只有在 KEX 签名验证和 Host Key pin 检查全部通过后才会进入这里。
// [ANNOTATION] 构造 password userauth request 并等待 success/failure；发送后对承载明文密码的临时 Data 做 best-effort 清零。Swift String 本身仍无法保证内存零化。
    // Swift Playgrounds/Swift 6 diagnostic workaround: construct the payload-bearing
    // error in a tiny explicitly typed helper so the large establish() body does not
    // feed this enum construction into the same constraint-solver expression.
    private func makeHostKeyConfirmationError(_ key: PinnedSSHHostKey) -> SSHError {
        SSHError.hostKeyConfirmationRequired(key)
    }

    private func authenticate(username: String, auth: SSHAuth) async throws {
        var request = Data([Msg.userauthRequest])
        request = IntegratedSSHWire.putString(username, into: request)
        request = IntegratedSSHWire.putString("ssh-connection", into: request)
        switch auth {
        case .password(let password):
            request = IntegratedSSHWire.putString("password", into: request)
            request.append(0)                          // not changing the password
            request = IntegratedSSHWire.putString(password, into: request)
        
        }
        // sendPacket 返回后立即尽力擦除包含明文密码的临时 Data；Swift String 本身仍无法保证零化。
        do {
            try await sendPacket(request)
        } catch {
            request.resetBytes(in: 0..<request.count)
            throw error
        }
        request.resetBytes(in: 0..<request.count)

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
// [ANNOTATION] 打开 SSH session channel，声明本地 channel、初始窗口与最大 packet，并从确认包取得服务器 channel id。
    private func openSessionChannel() async throws -> UInt32 {
        stage = "channel"
        var open = Data([Msg.channelOpen])
        open = IntegratedSSHWire.putString("session", into: open)
        open = IntegratedSSHWire.putUInt32(0, into: open)              // our channel
        open = IntegratedSSHWire.putUInt32(1_048_576, into: open)      // initial window
        open = IntegratedSSHWire.putUInt32(32_768, into: open)         // max packet
        try await sendPacket(open)

        let confirm = try await expect(Msg.channelOpenConfirm)
        var reader = IntegratedSSHWire.Reader(confirm)
        _ = reader.readByte()
        _ = reader.readUInt32()                        // our channel
        guard let remote = reader.readUInt32() else { throw SSHError.channelFailed }
        return remote
    }

    // MARK: - Exec

// [ANNOTATION] 一次性 exec 流程：建链、认证、开 session、发送 exec 请求、收集 channel data/extended-data、记录 exit-status、维护接收窗口，最后返回结果。
    func run(username: String, auth: SSHAuth, command: String, timeout: Double) async throws -> SSHRunResult {
        defer { connection.cancel() }
        try await establish(username: username, auth: auth, timeout: timeout)
        let remoteChannel = try await openSessionChannel()

        var exec = Data([Msg.channelRequest])
        exec = IntegratedSSHWire.putUInt32(remoteChannel, into: exec)
        exec = IntegratedSSHWire.putString("exec", into: exec)
        exec.append(1)                                 // want_reply
        exec = IntegratedSSHWire.putString(command, into: exec)
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
                close = IntegratedSSHWire.putUInt32(remoteChannel, into: close)
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
// [ANNOTATION] 建立长连接 session，申请 xterm PTY 并请求 shell。当前 v1 固定 80×24，且是 line-oriented shell，不是完整终端模拟器。
    func openShell(username: String, auth: SSHAuth, timeout: Double) async throws {
        try await establish(username: username, auth: auth, timeout: timeout)
        let channel = try await openSessionChannel()
        shellChannel = channel

        var pty = Data([Msg.channelRequest])
        pty = IntegratedSSHWire.putUInt32(channel, into: pty)
        pty = IntegratedSSHWire.putString("pty-req", into: pty)
        pty.append(0)                                  // want_reply = false
        pty = IntegratedSSHWire.putString("xterm", into: pty)
        pty = IntegratedSSHWire.putUInt32(80, into: pty)              // columns
        pty = IntegratedSSHWire.putUInt32(24, into: pty)              // rows
        pty = IntegratedSSHWire.putUInt32(0, into: pty)               // width px
        pty = IntegratedSSHWire.putUInt32(0, into: pty)               // height px
        pty = IntegratedSSHWire.putString(Data([0]), into: pty)       // empty terminal modes (TTY_OP_END)
        try await sendPacket(pty)

        var shell = Data([Msg.channelRequest])
        shell = IntegratedSSHWire.putUInt32(channel, into: shell)
        shell = IntegratedSSHWire.putString("shell", into: shell)
        shell.append(0)                                // want_reply = false
        try await sendPacket(shell)
        stage = "shell"
    }

    /// Blocks until the next chunk of shell output arrives; returns nil when
    /// the channel closes. Called only from a single background reader task.
// [ANNOTATION] 等待交互 shell 的下一块 stdout/stderr channel 数据；EOF/close 返回 nil，由上层结束读取循环。
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
// [ANNOTATION] 把 UI 输入作为 SSH_MSG_CHANNEL_DATA 发给当前 shell channel；调用方应避免并发发送。
    func sendShell(_ text: String) async throws {
        guard let channel = shellChannel else { return }
        var data = Data([Msg.channelData])
        data = IntegratedSSHWire.putUInt32(channel, into: data)
        data = IntegratedSSHWire.putString(Data(text.utf8), into: data)
        try await sendPacket(data)
    }

// [ANNOTATION] 通知服务器增加接收窗口，防止长输出因窗口耗尽而停住。
    private func sendWindowAdjust(_ channel: UInt32, _ bytes: UInt32) async throws {
        var adjust = Data([Msg.channelWindowAdjust])
        adjust = IntegratedSSHWire.putUInt32(channel, into: adjust)
        adjust = IntegratedSSHWire.putUInt32(bytes, into: adjust)
        try await sendPacket(adjust)
    }

    // MARK: - KEXINIT

// [ANNOTATION] 构造客户端 KEXINIT，只宣告本 Core 真正实现并审计过的 KEX、Host Key、AES-GCM 与 none compression，避免协商到未实现算法。
    private func buildKexInit() throws -> Data {
        var payload = Data([Msg.kexInit])
        payload.append(try secureRandomBytes(16)) // KEX cookie 使用 Apple Security 的系统 CSPRNG
        payload = IntegratedSSHWire.putNameList(["curve25519-sha256"], into: payload) // 只宣告实际实现并准备审计的 KEX
        payload = IntegratedSSHWire.putNameList(["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"], into: payload)
        payload = IntegratedSSHWire.putNameList(["aes256-gcm@openssh.com"], into: payload) // 只宣告 AES-256-GCM
        payload = IntegratedSSHWire.putNameList(["aes256-gcm@openssh.com"], into: payload)
        payload = IntegratedSSHWire.putNameList(["hmac-sha2-256"], into: payload) // GCM 为 AEAD；此字段不承担实际包认证
        payload = IntegratedSSHWire.putNameList(["hmac-sha2-256"], into: payload)
        payload = IntegratedSSHWire.putNameList(["none"], into: payload)     // compression c2s
        payload = IntegratedSSHWire.putNameList(["none"], into: payload)     // compression s2c
        payload = IntegratedSSHWire.putNameList([], into: payload)           // languages c2s
        payload = IntegratedSSHWire.putNameList([], into: payload)           // languages s2c
        payload.append(0)                                 // first_kex_packet_follows
        payload = IntegratedSSHWire.putUInt32(0, into: payload)              // reserved
        return payload
    }

    /// Confirms the server offers curve25519 key exchange and our GCM cipher
    /// in both directions — the only combination this client implements.
// [ANNOTATION] 解析服务器 KEXINIT，确认双方存在本实现支持的算法交集，并按客户端 preference 选出实际 Host Key algorithm。
    private func requireAlgorithms(in kexInit: Data) throws -> String {
        var reader = IntegratedSSHWire.Reader(kexInit)
        _ = reader.readByte()
        for _ in 0..<16 { _ = reader.readByte() }         // cookie
        guard let kex = reader.readNameList() else { throw SSHError.kexFailed }
        guard let hostKeys = reader.readNameList(),
              let c2s = reader.readNameList(), let s2c = reader.readNameList(),
              reader.readNameList() != nil, reader.readNameList() != nil,
              let compC2S = reader.readNameList(), let compS2C = reader.readNameList() else { throw SSHError.kexFailed }
        // 我方每类只宣告一个实际实现；服务器不包含它就直接失败，避免“协商 A、执行 B”。
        guard kex.contains("curve25519-sha256"),
              c2s.contains("aes256-gcm@openssh.com"), s2c.contains("aes256-gcm@openssh.com"),
              compC2S.contains("none"), compS2C.contains("none") else { throw SSHError.noCipher }
        // RFC 4253：我方 preference list 中第一个也被服务器支持的算法才是实际协商结果。
        let ourHostPreference = ["ssh-ed25519","ecdsa-sha2-nistp256","rsa-sha2-512","rsa-sha2-256"]
        guard let selectedHostKey = ourHostPreference.first(where: { hostKeys.contains($0) }) else { throw SSHError.noCipher }
        return selectedHostKey
    }

    // MARK: - Packet framing

// [ANNOTATION] SSH packet 封装与发送入口。加密后使用 AES-GCM + packet_length AAD；加密前按 SSH 基础 framing。整个发送过程受 actor gate 串行化。
    private func sendPacket(_ payload: Data) async throws {
        // 多个 UI/reader task 即使同时要求发送，也必须严格串行；GCM nonce 每包只能消费一次。
        await sendGate.enter()
        defer { Task { await sendGate.leave() } }
        if var cipher = encrypt {
            var pad = 16 - ((1 + payload.count) % 16)
            if pad < 4 { pad += 16 }
            var lengthField = Data()
            lengthField = IntegratedSSHWire.putUInt32(UInt32(1 + payload.count + pad), into: lengthField)
            let plaintext = Data([UInt8(pad)]) + payload + (try randomBytes(pad))
            guard let sealed = cipher.seal(plaintext: plaintext, lengthField: lengthField) else { throw SSHError.encryptFailed }
            encrypt = cipher
            try await writeRaw(lengthField + sealed)
        } else {
            var pad = 8 - ((4 + 1 + payload.count) % 8)
            if pad < 4 { pad += 8 }
            var packet = Data()
            packet = IntegratedSSHWire.putUInt32(UInt32(1 + payload.count + pad), into: packet)
            packet.append(UInt8(pad))
            packet.append(payload)
            packet.append(try randomBytes(pad))
            try await writeRaw(packet)
        }
    }

// [ANNOTATION] 读取 packet_length 后按当前加密状态读取 packet；AES-GCM 模式额外读取 16 字节 tag，并在认证成功后提取 payload。
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
            return try extractPayload(plaintext, packetLength: plaintext.count)
        } else {
            let rest = try await readExact(packetLength)
            return try extractPayload(rest, packetLength: packetLength)
        }
    }

    /// Strips `padding_length` and the trailing padding from a packet body.
// [ANNOTATION] 校验 padding_length、packet 总长和 payload 长度关系，再剥离 padding；畸形 framing 直接 protocolError。
    private func extractPayload(_ body: Data, packetLength: Int) throws -> Data {
        let padLength = Int(body.first ?? 0)
        let payloadCount = packetLength - 1 - padLength
        guard padLength >= 4, padLength < 256,
              payloadCount >= 1, body.count == packetLength,
              1 + payloadCount + padLength == packetLength else { throw SSHError.protocolError }
        return Data(body.dropFirst().prefix(payloadCount))
    }

    /// Reads the next real payload, transparently handling transport-level
    /// housekeeping messages and turning DISCONNECT into an error.
// [ANNOTATION] 过滤 SSH transport housekeeping 消息；DISCONNECT 转成错误，IGNORE/DEBUG 跳过，GLOBAL_REQUEST 按 want-reply 必要时回复 failure。
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

// [ANNOTATION] 读取下一个有效 payload，并要求 message code 精确等于当前状态机预期值。
    private func expect(_ code: UInt8) async throws -> Data {
        let payload = try await nextPayload()
        guard payload.first == code else { throw SSHError.protocolError }
        return payload
    }

    // MARK: - Raw byte I/O

// [ANNOTATION] 通过 SecRandomCopyBytes 获取系统 CSPRNG 字节；失败即终止，不允许退化到非密码学随机源。
    private func secureRandomBytes(_ count: Int) throws -> Data {
        // SecRandomCopyBytes 直接使用系统 CSPRNG；失败时绝不退回伪随机数。
        guard count >= 0 else { throw SSHError.protocolError }
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else { throw SSHError.kexFailed }
        return Data(bytes)
    }

// [ANNOTATION] 统一的随机字节入口，当前直接委托 secureRandomBytes。
    private func randomBytes(_ count: Int) throws -> Data {
        try secureRandomBytes(count)
    }

// [ANNOTATION] 把完整 wire bytes 写到底层 TCP，并把 transport error 映射为 SSHError。
    private func writeRaw(_ data: Data) async throws {
        if case .failure(let error) = await connection.send(data) {
            throw SSHError.transport(error.localizedDescription)
        }
    }

// [ANNOTATION] 从 TCP 取得下一段字节追加到 inbound 缓冲；连接断开或 transport failure 转为 SSHError。
    private func fill() async throws {
        switch await connection.receive() {
        case .success(let data):
            if data.isEmpty { throw SSHError.disconnected }
            inbound.append(contentsOf: data)
        case .failure(let error):
            throw SSHError.transport(error.localizedDescription)
        }
    }

// [ANNOTATION] 在 inbound 中累计直到至少有指定字节数，再精确切出并消费；解决 TCP 分片与合并对 SSH packet 边界的影响。
    private func readExact(_ count: Int) async throws -> Data {
        while inbound.count < count { try await fill() }
        let head = Data(inbound[0..<count])
        inbound.removeFirst(count)
        return head
    }

// [ANNOTATION] 读取 SSH identification 文本行；限制缓存为 8192 字节，并在字节层剥离 CR/LF，避免 Swift grapheme 处理破坏 exchange-hash 中的 V_S。
    private func readLine() async throws -> String {
        while true {
            // SSH identification 行属于不可信网络输入；限制缓存，避免无换行数据无限增长。
            guard inbound.count <= 8_192 else { throw SSHError.protocolError }
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
