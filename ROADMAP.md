# Roadmap

What zest_ssh_core aims to do over the next year (to the end of 2027), and what it will not do.
Plans change; this file is updated when they do.

## Goals

- **Secure defaults that keep up.** Follow the algorithms OpenSSH offers by default, keep the
  hybrid post-quantum key exchanges (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`) first, and
  raise floors as guidance moves (RSA host keys rose to 2048 bits in 0.2.2).
- **Tests and coverage.** Keep every fix behind a test, grow statement coverage above 80% and then
  towards 90%, and extend the fuzz tests (`test/fuzz`) to more of what a server sends.
- **Interoperability.** Keep checking against current OpenSSH releases and common servers, and say
  clearly why a connection was refused when a server only offers what the defaults leave out.
- **Signed releases.** Sign every release tag (from v0.2.2 on) and document how to check them
  ([docs/VERIFYING.md](docs/VERIFYING.md)).
- **Regular review.** A monthly review of the dependencies, the OpenSSF Scorecard and open
  reports, and a security review before each release.
- **Upstream.** Merge fixes from dartssh2 where they apply, and offer ours back where they fit.

## Non-goals

- **No weaker defaults for old servers.** SHA-1 exchanges, `ssh-rsa`, CBC ciphers, `hmac-md5` and
  short RSA host keys stay behind an explicit opt-in. Diffie-Hellman Group 1 is not offered at all.
- **No SSH-1.** Only SSH-2.0 (and servers that announce SSH-1.99).
- **No custom cryptography where a reviewed design exists.** New primitives follow published
  standards and their test vectors (for example FIPS 203 for ML-KEM).
- **No telemetry.** The library sends nothing anywhere but to the server it is asked to connect to.
