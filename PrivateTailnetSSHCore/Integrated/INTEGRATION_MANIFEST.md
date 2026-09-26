# PrivateTailnetSSH integration manifest

Status: FUNCTIONAL INTEGRATION CANDIDATE — NOT SECURITY APPROVED.
Security review intentionally follows completion of this integration closure.

## Target
iPadOS Swift Playgrounds source-only SSH client with no external SwiftPM dependency and no C/Clang target.

## Included capabilities
- TCP byte stream: Apple Network.framework / NWConnection
- SSH binary wire codec
- CryptoKit/Security-based SSH cryptographic implementation candidate
- SSH-2 version exchange and KEX
- server host-key signature verification capability
- SHA-256 host-key fingerprint capability
- password user authentication
- session channel
- one-shot exec with stdout/stderr/exit-status
- PTY + interactive shell
- shell input/output
- channel window adjustment
- local connection profile model
- local pinned host-key model
- password credential type deliberately excluded from Codable persistence

## Source selection
NetToolbox chosen for:
- source-only Network.framework TCP transport
- source-only SSH packet/wire implementation
- CryptoKit/Security crypto path
- password authentication
- exec/session/PTY/shell path
- no runtime NIO/Citadel dependency

Rootshell chosen as behavioral/design reference for:
- known-host identity model
- explicit host-key confirmation workflow
- host-key changed state
- handshake/session state/error concepts
- banner/error presentation concepts

Rootshell code NOT imported into runtime where it requires:
- NIOCore / NIOPosix / NIOTransportServices
- NIOSSH
- Citadel
- swift-crypto package
- CloudKit/sync stores
- VPN/agent infrastructure

## Explicitly excluded from first integrated core
- SFTP
- SCP
- private-key authentication
- SSH agent
- FIDO/security-key authentication
- jump hosts / ProxyJump
- port forwarding
- VPN/tunnel features
- CloudKit/sync
- telemetry/analytics/backend
- external package dependencies

## Integrated files
- SSHModels.swift
- SSHTCPConnection.swift
- SSHWire.swift
- SSHCrypto.swift
- SSHClient.swift

## Next phase
Freeze this integration closure, then perform security/correctness review as a whole. Findings in SECURITY_AUDIT.md from the earlier reconnaissance remain useful but must not be interpreted as approval of the Integrated/ implementation.
