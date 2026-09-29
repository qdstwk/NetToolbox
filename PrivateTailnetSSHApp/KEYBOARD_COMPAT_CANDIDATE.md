# PrivateTailnetSSH UI Keyboard Compatibility Candidate

Date: 2026-09-29

Status: **CANDIDATE — NOT FROZEN**

Derived from validated App v1 commit:
`a22157a39ee8cbb125fbfe72286b9e1653434eed`

Development branch:
`private-tailnet-ssh-ui-keyboard-compat-20260929`

Current UI blob:
`1af6a75e96cd3e60b530461c69763007105f2111`

Frozen Core blob:
`537ea89814d8dc77130225d289cfc665f1ee3638`

## Purpose

Swift Playgrounds App Preview on the iPad accepted focus in SwiftUI text fields, but the system software keyboard did not reliably appear even though the code editor keyboard still worked.

This candidate adds an app-owned fallback keyboard so the SSH tool does not depend on the App Preview software-keyboard presentation path.

## Security boundary

The fallback keyboard:

- uses ordinary SwiftUI buttons only;
- directly mutates the selected in-memory field;
- does not read hardware/system key events;
- does not use the clipboard;
- does not persist entered text;
- does not log entered text;
- does not create any network path;
- keeps the existing exact Host Key and password-authentication gates;
- keeps immediate foreground-loss disconnect behavior;
- does not modify the frozen SSH Core.

The password field remains transient Swift String state with the same previously recorded zeroization limitation.

## Fields supported

- Profile label
- Tailnet IPv4
- Username
- SSH password
- Exec command
- Shell input

The keyboard provides letters/shift, digits, common command/password symbols, space, backspace, clear and dismiss.

## Required live checks before any new freeze

1. App keyboard opens inside Add/Edit Host and can enter Label/Tailnet IPv4/Username.
2. App keyboard can enter the exact SSH password without clipboard use.
3. App keyboard can enter an exec command and the validated Mac/HP-NAS exec path still succeeds.
4. App keyboard can enter shell text and send works.
5. Password is still cleared after auth/completion/background/disconnect.
6. Foreground loss still immediately force-closes an active transport.
7. Profile/pin Keychain persistence remains unchanged.
8. Frozen Core blob remains exact.
