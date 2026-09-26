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


## Trust-chain comparison — 2026-09-26

### PTSSH-007 — X25519 shared-secret SSH encoding is not yet proven correct (BLOCKER)
RFC 8731 section 3.1 requires the X25519 32-byte output to be interpreted as an unsigned fixed-length integer in network byte order and then encoded as SSH mpint. NetToolbox currently passes CryptoKit SharedSecret raw bytes directly to SSHCrypto.mpint(). The exact CryptoKit raw representation semantics must be proven with independent vectors before this path is approved. Do not infer correctness merely from interoperability.

### PTSSH-008 — explicit RFC 8731 X25519 input/secret validation missing (HIGH)
RFC 8731 requires received Curve25519 public keys to be exactly 32 bytes and requires abort on an all-zero computed shared secret. NetToolbox relies on CryptoKit construction/key-agreement failure but does not explicitly enforce both protocol requirements in its own SSH layer. Final core must fail closed and tests must cover malformed-length and low-order/all-zero cases.

### PTSSH-009 — trust decision must occur before password authentication (CRITICAL invariant)
RFC 4253 describes verification of K_S as server authentication and warns that accepting without verification makes the protocol insecure against active attacks. OpenSSH stores/checks known host keys and, on changed host identification, warns and disables password authentication. PrivateTailnetSSH will therefore enforce:
1. verify the KEX signature cryptographically;
2. derive/display the fingerprint from the exact host-key blob;
3. compare exact host-key blob + key type against the pin for exact host:port;
4. if first use, pause before userauth and require explicit user confirmation;
5. if changed, abort before password construction/transmission;
6. only after trust succeeds may ssh-userauth/password be constructed or sent.

### PTSSH-010 — Rootshell trust policy is useful but not copied wholesale
Rootshell provides persistent known-host records and exact public-key-data matching plus an in-memory accept-once path. These are useful behavioral references. Its persistence/sync model (SyncableFileStore/CloudKit integration) conflicts with PrivateTailnetSSH's local-only/no-cloud requirement and will not be copied. Its NIOSSHPublicKey delegate types also cannot enter the Playground core.

### Adopted design for PrivateTailnetSSH host pin
Persist locally:
- canonical host string as entered/configured
- port
- host key algorithm/type
- exact SSH host-key blob (Data/base64 representation)
- SHA-256 fingerprint for display
- first-seen timestamp (optional metadata)

Security comparison uses exact key blob/type, not the display fingerprint string alone. Fingerprint is UI/verification aid.

Changed key:
- hard failure;
- never silently replace pin;
- never send password;
- user must explicitly remove/reset the old pin through host management before a new first-use confirmation can occur.

Not adopted from Rootshell:
- CloudKit sync;
- generic sync/tombstone machinery;
- accept-once by default;
- NIOSSH/Citadel/NIO transport types.


### PTSSH-011 — KEX/cipher negotiation can disagree with the algorithm actually executed (HIGH)
Client KEXINIT advertises curve25519-sha256 before curve25519-sha256@libssh.org and aes256-gcm before aes128-gcm. requireCiphers merely checks that either Curve25519 name exists somewhere and that aes256-gcm exists somewhere. It does not compute the negotiated first mutual algorithm for every mandatory category. The code then unconditionally runs Curve25519 and derives 32-byte AES-256 keys. A server preference/list combination can therefore be accepted without proving that the transport being executed is the transport negotiated by RFC 4253 rules.

Final core will parse the complete server KEXINIT and compute/validate exact negotiated values before sending KEXECDH_INIT. For MVP, fail closed unless exact negotiated algorithms are in the audited set. Do not advertise aes128-gcm until an audited aes128 path exists.

### PTSSH-012 — advertised MAC list is misleading with AEAD-only implementation (MEDIUM)
The MVP transport implements OpenSSH AES-GCM AEAD and does not implement the advertised hmac-sha2-256/hmac-sha2-512 packet MAC paths. Although AEAD negotiation makes separate MAC selection irrelevant in the successful GCM path, advertising unsupported algorithms increases ambiguity and future negotiation risk. The audited KEXINIT should accurately describe only implemented behavior and explicitly handle AEAD semantics.

### Rootshell comparison: algorithm policy
Rootshell's SSHCustomAlgorithms demonstrates broader mature compatibility (additional KEX and CTR/ETM schemes), but these depend on NIOSSH/Citadel and are intentionally NOT imported into the Playground core. PrivateTailnetSSH prefers a narrow, audited algorithm set over broad compatibility for its known modern OpenSSH servers.
