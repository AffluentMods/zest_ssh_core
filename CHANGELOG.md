# Changelog

This is the changelog for `zest_ssh_core`. For the history of dartssh2 up to the fork point, see
`CHANGELOG-dartssh2.md`.

## 0.1.0 - 2026-08-19

First public release of the fork. Forked from dartssh2 `2.14.0`.

### Hardened defaults

Weak algorithms are still implemented, but a connection no longer offers them unless the caller opts
in with a custom `SSHAlgorithms` profile.

- Removed from default key exchange: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `diffie-hellman-group-exchange-sha1`. SHA-1 is collision broken, so strong defaults must not be
  negotiable down to it.
- Removed from default host keys: `ssh-rsa` (SHA-1 signatures).
- Removed from default ciphers: all CBC modes (CVE-2008-5161 plaintext recovery when not paired with
  ETM MACs).
- Removed from default MACs: `hmac-md5`.
- Encrypt-then-MAC variants are preferred over plain HMAC, and AES-256 is preferred over AES-128.

### Added

- `chacha20-poly1305@openssh.com` AEAD cipher.
- Strict key exchange (`kex-strict-c-v00@openssh.com`), which is the mitigation for Terrapin
  (CVE-2023-48795).
- SSH certificate authentication.
- Ed448 host key support (implemented, not offered by default).
- AES-GCM ciphers (implemented, not offered by default).
- Client identification string `zest_ssh_core_<version>`, so this library is identifiable in server
  logs and scan results rather than being attributed to upstream.

### Security fixes

- ECDH now validates the peer's public key before using it: the point must be well formed, not the
  point at infinity, and actually on the negotiated curve. Without this check a malicious server can
  mount an invalid-curve attack and recover the ephemeral private key over repeated connections. A
  degenerate shared secret (0 or 1) is also rejected.
- One-time Poly1305 keys are zeroed immediately after use.
- SFTP read no longer loses data when a server returns fewer bytes than requested. The protocol
  explicitly permits a short read; the previous loop advanced its offset by the full requested length,
  so the gap was never re-requested and the download was silently truncated. Merged from upstream.
- P-521 ECDH private scalars are drawn from the full 521-bit range. The previous byte calculation
  produced 520 bits. Merged from upstream.

### Deliberately not taken from upstream

- The per-handshake `Isolate.run` offload of key exchange (upstream 2.20.0 through 3.3.0). Spawning an
  isolate per connection costs several times more than the curve operation it hides, and it can lose a
  race against a server's handshake timeout (upstream issue #226). This fork computes X25519 and the
  NIST curves synchronously, which is what upstream reverted to.
