# Rootshell comparison baseline

Upstream: kitknox/rootshell
Frozen commit: b1233ed14ffbd83afa17e843bd48a4a789a8cde6
Frozen date: 2026-09-26
Repository license: MIT for original rootshell code, subject to per-file/third-party terms documented upstream.

## Important dependency finding
Rootshell is NOT a zero-dependency pure-Swift SSH transport suitable for direct inclusion in the iPad Swift Playgrounds target. Its resolved graph includes, among others:
- kitknox/swift-nio-ssh-rootshell 0.1.4
- apple/swift-nio 2.95.0
- kitknox/Citadel-rootshell 0.12.8
- apple/swift-crypto 3.15.1

CitadelSSHSession directly imports Citadel, NIOCore, NIOSSH, NIOPosix, NIOTransportServices, and Crypto.

Therefore these files are frozen as REFERENCE IMPLEMENTATIONS, not automatically approved source for the final Playground core.

## Frozen rootshell files
Host trust:
- KnownHost.swift
- KnownHostsManager.swift
- SSHHostKeyDelegate.swift
- SSHHostKeyFormatter.swift
- SSHHostPatternMatcher.swift
- SessionApprovedHostKeys.swift

Session/policy:
- SSHCustomAlgorithms.swift
- SSHHandshakeHandler.swift
- SSHBanner.swift
- SSHConnectionError.swift
- CitadelSSHSession.swift
- NIOChannelBytePipe.swift

## Comparison/replacement policy
Compare behavior by SSH protocol responsibility, not by whole-file replacement.

Priority:
1. Host-key verification and pinning/fail-closed behavior.
2. Algorithm negotiation/policy.
3. Handshake/error state handling.
4. Banner parsing/sanitization.
5. Authentication lifetime/logging behavior.
6. Session/channel flow control and cancellation.

A rootshell implementation may only be promoted if:
- its behavior is suitable for PrivateTailnetSSH,
- its license/provenance is compatible,
- all NIO/Citadel/Crypto-package types are removed or replaced by Apple SDK/pure Swift equivalents,
- it preserves the zero external dependency / zero C-target Playground requirement.

Do not copy NIO/Citadel glue into the final core merely because rootshell uses it.
