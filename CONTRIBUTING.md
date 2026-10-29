# Contributing to zest_ssh_core

Thank you for helping. zest_ssh_core is the SSH engine of [ZestSSH](https://zestssh.com), a fork of
[dartssh2](https://github.com/TerminalStudio/dartssh2) hardened for it. Bug reports, fixes and
improvements are welcome.

## Reporting a bug

Open an issue: https://github.com/AffluentMods/zest_ssh_core/issues

Say what you did, what you expected and what happened, with the Dart version, the platform, and the
SSH server you connected to (its version line, for example `SSH-2.0-OpenSSH_9.6`) where it matters.

**Security problems are not reported in issues.** Follow [SECURITY.md](SECURITY.md): a private
advisory under the Security tab, or an email to support@zestssh.com.

## Sending a change

1. Fork the repository and branch from `zest`, the default branch.
2. Make the change, with a test (see below).
3. Open a pull request against `zest`, saying what it changes and why.

Every pull request is read and answered. Small, focused changes are easiest to review.

## What a change needs to be accepted

- **Formatted:** `dart format .` leaves nothing to change (CI checks
  `dart format --output=none --set-exit-if-changed .`).
- **Clean analysis:** `dart analyze` reports no issues. The rules are the analyzer's defaults plus
  `package:lints` recommended (`analysis_options.yaml`).
- **Tested:** every fix and every new feature comes with a test under `test/` that fails without
  it, and `dart test` passes. Code that parses what a server sends gets a case in the fuzz tests
  (`test/fuzz`) where it fits.
- **Secure by default:** nothing weakens the default algorithms or checks. Older algorithms go
  behind an explicit opt-in, as the existing ones are.
- **Documented:** public API carries Dart doc comments, and a user-visible change gets a line in
  `CHANGELOG.md` under Unreleased.
- **Licensed under MIT:** by contributing you agree that your contribution is licensed under the
  project's [MIT license](LICENSE).

## Running the checks

```bash
dart pub get
dart format --output=none --set-exit-if-changed .
dart analyze
dart test
```

GitHub Actions runs the same on every push and pull request (`.github/workflows/test.yml`).
