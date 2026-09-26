# PrivateTailnetSSHCore line-by-line audit

Frozen audit target revision 2:
- file: PrivateTailnetSSHCore/PrivateTailnetSSHCore.swift
- commit: 6e95a7120980797ff1c8c8c7635ea0b28187a665
- size: 1029 lines
- date: 2026-09-26

Rule: revision 2 is the sole audit target. Do not edit it during this audit pass.

## Pass A — dependency and persistence boundary
- Imports are Foundation, Network, CryptoKit, Security only. No NIO/Citadel/swift-crypto package import.
- SSHConnectionProfile is Codable but contains no password.
- SSHPasswordCredential is deliberately not Codable. Swift String still cannot guarantee memory zeroization; review later.
- PinnedSSHHostKey is now included in the single file, so the previous merge blocker is fixed.

## Pass B — TCP and concurrency
- NWConnection is used directly over TCP, appropriate for SSH transport.
- Connect has a one-shot timeout race guard.
- send/receive after connect have no per-operation deadline: stalled peer can block indefinitely.
- SSHOneShot, SSHAtomicFlag and IntegratedSSHClient use @unchecked Sendable; compiler data-race enforcement is bypassed and client mutable state is not actor-isolated.

## Pass C — wire codec
- Reader bounds-checks byte, uint32, uint64 and string reads.
- putString converts Data.count to UInt32 without a size guard; oversized local data can trap.
- Packet declared length is later capped at 1 MiB, which is positive.

## Pass D — crypto candidate
- Exchange-hash and KDF shapes still require normative/vector verification.
- X25519 SharedSecret raw bytes are passed directly to SSH mpint encoding; representation must be proven against RFC 8731/test vectors.
- Host-key verifier returns Bool, but handshake does not require true before continuing: CRITICAL fail-open.
- ECDSA pad32 truncates oversized r/s instead of rejecting malformed values.
- ECDSA curve-name field is read but not checked for exact nistp256.
- RSA path uses SecKey message-signature algorithms while supplying an already-computed exchange hash; digest-vs-message semantics must be corrected/verified.
- AES-GCM nonce/AAD/framing requires OpenSSH protocol/vector verification; counter wraps with no rekey/exhaustion policy.

## Pass E — host trust and password boundary
- Exact host+port+key type+key blob pin model is present.
- IntegratedSSHClient does not call the trust evaluator before password authentication. Thus pinning exists as a model but is not enforced.
- Changed-key hard-fail behavior therefore is not yet wired into the handshake.
- Password is copied into the SSH userauth Data buffer. No logging or persistence path is visible in this file.
- Diagnostics retain partial exchange-hash metadata; unnecessary for production.

## Pass F — negotiation and authentication
- KEXINIT advertises more choices than the code proves it negotiated.
- requireCiphers checks list membership, not the RFC first-mutual selection for all categories.
- aes128-gcm is advertised although the implementation unconditionally derives a 32-byte AES-256 key.
- MAC names are advertised although only the AEAD packet path is implemented.
- SERVICE_ACCEPT message type is checked but accepted service name is not parsed/validated.

## Pass G — channels, exec and shell
- OPEN_CONFIRMATION recipient/local channel identity is not validated.
- Server initial window and maximum packet size are ignored.
- Several inbound channel recipient IDs are parsed then ignored.
- Exec merges stdout and stderr despite SSHExecResult defining separate streams.
- Output cap is loop-level rather than strict bounded append.
- Window adjustment counts stdout but not stderr.
- Interactive shell does not replenish receive window, so long sessions can stall.
- PTY and shell requests use want_reply=false, so server rejection is invisible.
- Terminal size model exists but PTY request is fixed at 80x24.

## Pass H — packet framing and raw input
- extractPayload does not enforce minimum SSH padding length and returns empty data on malformed structure instead of throwing.
- KEX cookie and packet padding use Swift UInt8.random; use an explicitly auditable system CSPRNG path or prove platform guarantee.
- Rekey KEXINIT is not handled for established long-lived sessions.
- readExact has no post-connect timeout.
- SSH identification line accumulation has no byte cap before newline.

## Current disposition
Revision 2 is a complete single-file integration candidate, but NOT security-approved. Critical/high findings must be fixed in a new revision only after the complete audit and normative cross-check are finished.
## Normative pass 1 — KEX / key derivation / RSA / AES-GCM

Audit target remains revision 2 commit 6e95a7120980797ff1c8c8c7635ea0b28187a665.

### X25519 / curve25519-sha256
- RFC 8731 requires peer Curve25519 public key length exactly 32 bytes and abort on an all-zero X25519 shared secret.
- RFC 8731 section 3.1 explicitly says X25519 output bytes are reinterpreted as an unsigned fixed-length network-byte-order integer, then encoded as SSH mpint.
- Current code does not explicitly enforce the all-zero rule and has no independent vector proving the SharedSecret raw-representation-to-mpint path. FIX REQUIRED.

### SSH key derivation
- RFC 4253 confirms A/B/C/D letter mapping used by the candidate: IV c2s=A, IV s2c=B, key c2s=C, key s2c=D.
- RFC 4253 confirms extension HASH(K || H || key-so-far). Candidate structure matches this shape. PASS pending K encoding correctness.

### Algorithm negotiation
- RFC 4253 requires selection by iterating the client's preference list and choosing the first mutually supported compatible algorithm; membership testing is insufficient.
- Current requireCiphers only tests contains(). FIX REQUIRED.

### RSA verification
- Apple Security exposes separate message and digest PKCS#1 v1.5 SHA-256 APIs.
- Candidate passes exchange hash H into rsaSignatureMessagePKCS1v15SHA256/512. Because H is already the SSH signed digest input for RSA-SHA2 verification, this API choice would hash H as a message again. Replace with the corresponding rsaSignatureDigestPKCS1v15SHA256/512 path, after checking SecKeyIsAlgorithmSupported. FIX REQUIRED.

### OpenSSH AES-GCM
- OpenSSH documents aes*-gcm@openssh.com separately from the original RFC 5647 negotiation behavior and points to the OpenSSH-compatible AES-GCM rules.
- OpenSSH cipher metadata confirms aes256-gcm uses 32-byte key, 12-byte IV, 16-byte auth tag and a 16-byte block size; packet/AAD/IV increment behavior still requires exact vector-level verification before approval.

### Commenting requirement for Revision 3
- Every security-relevant declaration, state field, protocol field, magic constant, guard, conversion, and state transition must carry a concise Chinese comment explaining purpose and failure/security meaning.
- Closing braces and syntactically self-evident punctuation do not need noise comments.
- Revision 3 will be generated only after the remaining normative passes are complete, so the commented repaired file is one coherent revision rather than a chain of moving partial fixes.
## Normative pass 2 — packet/channel/ECDSA/rekey

### Packet structure
- RFC 4253/RFC 5647 require random padding length at least 4 and below 256. Current extractPayload accepts padding_length below 4. FIX.
- RFC 5647 confirms the AES-GCM authentication tag occupies the SSH MAC field and the plaintext portion is padding_length + payload + random_padding. Exact OpenSSH variant details remain to be cross-checked.

### Channel flow control
- RFC 4254 states every non-open channel message carries the recipient channel number. Current code often reads and discards it. FIX: validate against the local channel.
- RFC 4254 requires send amount to respect BOTH remote window and remote maximum packet size. Current code ignores both values returned by CHANNEL_OPEN_CONFIRMATION. FIX.
- RFC 4254 states CHANNEL_EXTENDED_DATA consumes the same receive window as ordinary data. Current exec accounting excludes stderr. FIX.
- Interactive shell currently does not replenish its receive window. FIX.

### ECDSA host key
- RFC 5656 requires the embedded curve identifier and key/signature algorithm to correspond. Current verifier merely discards the curve-name field. FIX: require nistp256 exactly.
- RFC 5656 defines r and s as mpints. Oversized/noncanonical values must be rejected; current pad32 truncation is not acceptable. FIX.

### RSA SHA-2 host key
- RFC 8332 confirms an RSA host public-key blob remains encoded as ssh-rsa while the negotiated/signature algorithm is rsa-sha2-256 or rsa-sha2-512. Final negotiation code must distinguish public-key blob type from negotiated host-key algorithm.

### Rekey
- RFC 4253 permits either side to initiate rekey with SSH_MSG_KEXINIT; AES-GCM guidance also assumes fresh K/H/keys after rekey while session_id remains unchanged. Current established-session nextPayload does not implement this state transition. FIX before approving long-lived interactive shell.