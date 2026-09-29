# PrivateTailnetSSH App v1 — Validated UI Baseline Record

Validation date: 2026-09-29

## Source anchors

- Repository: `qdstwk/NetToolbox`
- UI integration branch used for validation: `private-tailnet-ssh-app-ui-20260929`
- UI source: `PrivateTailnetSSHApp/ContentView_FinalAppCandidate.swift`
- UI blob SHA: `6e6e2345af81736d06968d1e0408b0a9b2527d9f`
- Frozen SSH Core source: `PrivateTailnetSSHCore/PrivateTailnetSSHCore_R3_MacCandidate.swift`
- Frozen Core blob SHA: `537ea89814d8dc77130225d289cfc665f1ee3638`
- Frozen Core authoritative commit: `bad164c22ed1a47b53f6462e0c105716b711f128`

The UI layer does not modify the frozen SSH Core.

## Live acceptance — iPadOS Swift Playgrounds

All items below passed live validation against HP-NAS:

1. Add/save/select profile does not auto-connect.
2. First-use Host Key signature/possession verification stops before real-password authentication.
3. User explicitly trusts and saves the exact Host Key pin before password entry becomes available.
4. Exact Host Key pin is used for real-password exec/shell connections.
5. Exec path returns expected stdout and exit status and closes transport.
6. PTY/interactive shell connects; one reader receives shell output; user input works; shell exit closes transport.
7. Foreground loss force-closes the active SSH transport at the earliest UIKit deactivation path after hardening.
8. Profile + exact Host Key pin persist across Swift Playgrounds stop/re-run via local-only Keychain.
9. Password does not persist across stop/re-run and no relaunch auto-connect occurs.
10. RFC1918 LAN IPv4, public IPv4 and non-canonical Tailnet IPv4 are rejected before profile creation.
11. Reset Host Key pin removes trust, re-disables password entry and requires fresh first-use verification + explicit trust.
12. Delete profile persists across stop/re-run and does not auto-connect.
13. While one interactive shell is active, final-UI controls remain locked so a second session cannot be initiated; frozen Core also retains its process-wide fail-closed single-session gate.

## Persisted vs transient data

Persisted locally on the same device:
- label
- canonical Tailnet IPv4
- port 22
- username
- exact `PinnedSSHHostKey`

Storage:
- Generic Keychain item
- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- `kSecAttrSynchronizable=false`

Never persisted:
- SSH login password

The password is transient Swift String state. It is cleared before network authentication begins and again on completion, disconnect and foreground loss. Swift String memory cannot be formally zeroized; that limitation remains explicit.

## Network/lifecycle constraints

- v1 destination form: canonical 100.64.0.0/10 IPv4 only
- SSH port: fixed 22
- no DNS / MagicDNS / IPv6 / RFC1918 LAN / public IPv4 target
- no automatic connection
- no reconnect loop
- no background SSH
- foreground loss force-closes active transport
- UI creates no alternate network transport; SSH flows only through frozen `IntegratedSSHClient`
- frozen Core single-session/single-sender/single-reader gates remain authoritative

## Freeze rule

The validated source is identified by exact commit/blob anchors, not by a mutable branch name. Any later UI or Core change must occur on a new development branch and must revalidate the affected acceptance items before a new frozen baseline replaces this one.
