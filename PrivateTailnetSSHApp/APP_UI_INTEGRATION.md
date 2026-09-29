# PrivateTailnetSSH — Final App UI Integration Candidate

Base / authority:

- Frozen validated Core commit: `bad164c22ed1a47b53f6462e0c105716b711f128`
- Frozen Core blob: `537ea89814d8dc77130225d289cfc665f1ee3638`
- UI integration branch: `private-tailnet-ssh-app-ui-20260929`
- Frozen Core file is not modified on this branch.

## v1 operating constraints carried into the UI

1. **Explicit user action only**
   - Saving/selecting a profile never opens a connection.
   - First-use Host Key verification requires a button press.
   - Exec requires a non-empty command + transient password + explicit Run.
   - Shell requires transient password + explicit Connect.
   - No reconnect loop / auto-connect / background maintenance.

2. **Single network path**
   - UI creates no `NWConnection`, listener, URLSession or alternate transport.
   - Every SSH connection goes through the frozen `IntegratedSSHClient`.
   - Frozen Core process-wide single-session gate remains authoritative.
   - Shell uses one reader Task only.

3. **Foreground-only**
   - `scenePhase != .active` force-closes the current Core transport.
   - Password, pending first-use trust and shell input are cleared.
   - Closing the view also force-closes.

4. **Destination scope**
   - Profiles accept canonical Tailnet IPv4 in `100.64.0.0/10` only.
   - SSH port is fixed to 22 in the v1 UI.
   - DNS / MagicDNS / IPv6 / RFC1918 LAN / public IPv4 are not accepted.

5. **Persisted profile data**
   - label
   - canonical Tailnet IPv4
   - port 22
   - username
   - exact `PinnedSSHHostKey` (host + port + key type + key blob + derived fingerprint)
   - **No password** is persisted.

6. **Host Key behavior**
   - First use: cryptographic Host Key verification runs before password auth; UI then requires explicit trust before saving the exact key.
   - Existing pin: every real-password operation uses that exact pin.
   - Changed key: hard fail. The error path never offers an "accept new key" shortcut.
   - Resetting a pin is a separate destructive profile-management action; real password entry is blocked until first-use verification/trust is repeated.

7. **Password handling**
   - Password exists only as transient Swift String state.
   - UI state is cleared before the network call and again on completion/disconnect/background.
   - Password is never written to UserDefaults, repository, logs or clipboard.
   - Swift String memory cannot be formally zeroized; this remains an explicit evidence boundary.

8. **Shell**
   - One active shell client and one reader Task.
   - Transcript UI is capped at 256 KiB; exceeding it force-closes the transport.
   - App/background loss force-closes the shell.

## Static scan of the first UI candidate

`ContentView_FinalAppCandidate.swift`:
- direct Network.framework / socket / URLSession creation: 0
- clipboard APIs: 0
- logging APIs: 0
- background-task APIs: 0
- password persistence matches: 0
- `IntegratedSSHClient` construction sites: 3 (first-use preflight, exec, shell)
- persisted storage API: UserDefaults for `[SSHConnectionProfile]` only
- frozen Core blob on UI branch matches validated blob exactly

## Required live validation before UI acceptance

Do not promote this UI candidate into the PDA reusable standard until the following are live-tested on iPadOS using the exact UI branch:

1. Add/save/select profile causes **no connection**.
2. Invalid/non-Tailnet destination cannot be saved.
3. First-use Host Key preflight stops before password auth.
4. Explicit Trust saves the exact key and enables password entry.
5. Relaunch restores profile + exact pin but never restores password.
6. Wrong/changed Host Key hard-fails with no accept shortcut.
7. Exec succeeds against HP-NAS and closes transport afterward.
8. PTY/shell connects, sends input, receives through one reader and disconnects.
9. Switching apps while exec/shell is active force-closes immediately.
10. While one session is active, no second host/profile can start another session.
11. Deleting/resetting a profile clears the relevant trust state without storing secrets.

Until these pass, status is **UI INTEGRATION CANDIDATE**, not a new validated/frozen app baseline.


## Foreground-loss hardening after first UI live test

The first final-UI live test on iPadOS showed that view-level SwiftUI lifecycle handling did not close the SSH transport quickly enough for the project's "switch app = disconnect" requirement.

The UI candidate now adds a process-level `PrivateTailnetSSHForegroundGuard`:

- it is armed only while an `IntegratedSSHClient` is the current active transport;
- it listens directly to `UIScene.willDeactivateNotification` and `UIApplication.willResignActiveNotification` (plus background notifications);
- observers use `NotificationCenter.addObserver(..., queue: nil)`, so the current client's `close()` runs synchronously inside the lifecycle notification delivery path instead of waiting for SwiftUI/Combine rendering;
- view-level lifecycle handlers remain only as a second path for UI/transient-state cleanup;
- no timer, keepalive, reconnect loop or background worker was added.

This change is UI/lifecycle orchestration only. The frozen validated Core blob remains unchanged.

Acceptance criterion for the next live test: while an interactive shell is connected, switching away from Swift Playgrounds must revoke the SSH transport at the earliest UIKit deactivation event; returning to the app must show no active shell and no automatic reconnect.


## Live validation progress

Validated on iPadOS Swift Playgrounds against HP-NAS:

- Add/save/select profile with no automatic connection: PASS
- First-use Host Key verification + explicit exact-pin trust: PASS
- Final-UI interactive shell connect + one-reader receive: PASS
- Final-UI shell input / user exit / clean close: PASS
- Foreground loss immediate force-close after direct UIKit lifecycle guard: PASS
- Final-UI exec: exact pin + real password + stdout + exit-status + clean close: PASS
- Relaunch persistence after Keychain migration: profile + exact Host Key pin restored; password not restored; no auto-connect: PASS
- Destination/profile gate: RFC1918 LAN IPv4, public IPv4 and non-canonical Tailnet IPv4 with leading zero were rejected before profile creation: PASS

Still open before UI freeze:

- Pin reset/delete behavior
- Single-session rejection while one session is active


## Persistence finding after first relaunch test

The first iPadOS App Preview stop/re-run test did **not** restore the HP-NAS profile from the original UserDefaults-backed implementation. Therefore profile/pin persistence was NOT accepted.

The UI candidate now stores the encoded `[SSHConnectionProfile]` in a local-only generic-password Keychain item using `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and `kSecAttrSynchronizable=false`.

Security boundary remains unchanged:
- the persisted record contains label, canonical Tailnet IPv4, fixed port 22, username and exact `PinnedSSHHostKey`;
- it contains no SSH login password;
- the trust database is device-local and intentionally non-synchronizing;
- frozen Core is unchanged.

Relaunch persistence was rerun on iPadOS after the Keychain migration and PASS: profile + exact Host Key pin restored, password did not restore, and the app did not auto-connect.
