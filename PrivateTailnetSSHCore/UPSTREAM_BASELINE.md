# PrivateTailnetSSH frozen upstream baseline

Upstream project: M-S-JABER/NetToolbox
Fork: qdstwk/NetToolbox
Upstream/fork baseline commit: a59bfa21ed2c86ce5f664408237d87ae8948e134
Frozen: 2026-09-26
License: MIT; see ../../LICENSE.

Purpose:
This directory preserves the unmodified source inputs selected for the PrivateTailnetSSH security audit. Do not make security fixes in Upstream/. Audited/minimized code belongs in a separate directory/commit so every change remains diffable.

Frozen files and original blob SHAs:
- SSHClient.swift 692417936fb53be5470095074b635ae4326a5604
- SSHCrypto.swift 3cbf920be01695c41b5afe468f5a24aa9790e100
- SSHWire.swift 03ac196f1f06d45b1b16e844465f7e224f88e105
- SSHPrivateKey.swift 0ef8f546ec09e321788dac840ebd9ec26da27818
- SFTP.swift fdddf6142a3f55304a3d1da3f4e516667ce06f34
- NetProbe.swift cd48935eb8f1b5c41f287cd17f04070424b2749d

Initial PrivateTailnetSSH MVP scope:
- iPadOS Swift Playgrounds App
- TCP via Network.framework
- SSH-2 transport
- password authentication only
- strict host-key pinning (to be added after audit)
- one session channel
- exec first; interactive PTY/shell later
- no password persistence
- no SFTP in MVP
- no private-key authentication in MVP
- no external SwiftPM dependency
- no C/Clang target

Security rule:
The presence of a source file in Upstream/ is not approval of its security. Each protocol/crypto/transport path must be reviewed against specifications and independent mature implementations before promotion into the audited core.
