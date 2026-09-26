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