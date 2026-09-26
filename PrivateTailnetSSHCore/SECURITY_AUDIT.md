# Initial security audit — PrivateTailnetSSH

Baseline: a59bfa21ed2c86ce5f664408237d87ae8948e134
Status: findings are preliminary until cross-checked against SSH/OpenSSH specifications and independent implementations.

## Confirmed from source inspection

### PTSSH-001 — host-key signature failure is not enforced (critical design flaw)
SSHClient.establish assigns the result of SSHCrypto.verifyHostKey(...) to hostKeyVerified, but does not abort when it is false. It proceeds to derive transport keys, NEWKEYS, and user authentication. Final PrivateTailnetSSH must fail closed before authentication if the KEX host-key signature is invalid.

### PTSSH-002 — no persistent host-key pinning / known-host enforcement
The core computes a SHA-256 fingerprint and returns hostKeyVerified, but does not compare the presented host key against a previously trusted key. PrivateTailnetSSH requires first-use explicit confirmation and subsequent exact pin matching; changed keys must block authentication.

### PTSSH-003 — algorithm negotiation is incomplete
requireCiphers checks whether the server *contains* curve25519 and aes256-gcm, but SSH negotiation selects the first mutually supported algorithm according to the client/server preference rules. The implementation then unconditionally executes curve25519 + aes256-gcm without proving that those were the negotiated algorithms. Host-key algorithm selection is not checked there at all. Must be corrected before use.

### PTSSH-004 — packet padding/randomness needs a cryptographic RNG audit
KEX cookie and packet padding use Swift UInt8.random. This is not yet approved for the frozen security core. Replace/justify with an explicitly audited system CSPRNG path if required by the SSH specifications and platform behavior.

### PTSSH-005 — packet parser accepts structurally weak padding
extractPayload only checks that payloadCount is non-negative and enough body bytes exist. It does not enforce the SSH minimum padding length or all packet structural constraints. Fail closed on malformed packets.

### PTSSH-006 — password lifetime is broader than desired
SSHAuth.password(String) and construction of the full userauth request necessarily create additional immutable/copy-on-write values containing the password. Nothing persists it to disk in this core, but the final app's “transient only” requirement needs deliberate lifetime minimization and no diagnostics/logging.

## Positive findings so far
- No NIO/CNIO dependency in the selected transport/SSH files.
- TCP uses Apple Network.framework/NWConnection.
- Cryptographic primitives use CryptoKit; RSA verification conditionally uses Apple Security.framework.
- SSHWire performs bounds checks before reading UInt32/UInt64/string payloads.
- receivePacket caps declared SSH packet length at 1 MiB before allocating/reading the body.
- Password is sent only after NEWKEYS is installed; no source path observed so far that logs the password.
- Compression proposal is only "none".

## Still under audit
- RFC 4253 key derivation exact byte representation of K.
- RFC/OpenSSH curve25519 exchange hash construction.
- OpenSSH AES-GCM packet format, AAD, IV/counter semantics and rekey limits.
- RSA verification API semantics (message vs digest) and key encoding.
- ECDSA SSH mpint parsing/canonical validation.
- KEXINIT negotiation including first_kex_packet_follows.
- rekey handling.
- channel identifiers/window accounting/max-packet enforcement.
- concurrency/thread safety of mutable SSHClient state.
- timeout behavior after initial TCP connect.
- memory/resource DoS paths in banner/inbound/channel/SFTP buffers.
