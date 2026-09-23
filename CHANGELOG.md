# Changelog

This is the changelog for `zest_ssh_core`. For the history of dartssh2 up to the fork point, see
`CHANGELOG-dartssh2.md`.

## 0.2.1 - 2026-09-23

### Agent forwarding

- The forwarded agent signs asynchronously, so hardware-token and agent-backed keys (whose
  synchronous `sign()` throws) can answer a forwarded request. A key that refuses (a declined touch,
  a locked token, a local agent that went away) now returns a plain agent failure instead of an
  error, so the requester can try its next key.
- New `SSHWrappedKeyPair` interface for a key pair that presents other public material than the key
  it signs with, such as an SSH certificate wrapping a private key. The agent unwraps it, so an RSA
  sign request gets the hash it asked for (the server refuses any other).

## 0.2.0 - 2026-09-22

### Post-quantum key exchange

- `mlkem768x25519-sha256` (OpenSSH 9.9+ default) and `sntrup761x25519-sha512` plus its
  `@openssh.com` spelling (OpenSSH 9.0 to 9.8 default) are implemented and offered FIRST by
  default. Both are hybrids: the post-quantum KEM secret and the X25519 secret are hashed together,
  so a session is only as weak as the stronger of the two, and a recording of it cannot be
  decrypted by a future quantum computer. An older server that lists neither simply falls through
  to the classic exchanges.
- ML-KEM-768 is a pure Dart implementation of FIPS 203, checked against the NIST ACVP vectors
  (key generation, encapsulation, decapsulation including implicit rejection). Streamlined NTRU
  Prime 761 is a port of the public-domain reference (supercop-20240808 compact kem.c, as vendored
  by OpenSSH), keeping its data-independent control flow. Both verified end to end against an
  OpenSSH 10.2 server.
- `SSHKexType.isHybridPostQuantum` / `SSHKexType.isPostQuantumName` for callers that want to show
  it.
- `curve25519-sha256` (the RFC 8731 name) is now offered next to the `@libssh.org` one.

### Fixed

- Incoming-packet padding was validated with the AEAD alignment rule as soon as ChaCha20-Poly1305
  or AES-GCM was NEGOTIATED, before NEWKEYS, so a cleartext KEX reply whose payload length made the
  two rules differ was rejected with `Invalid padding length`. Seen with `ecdh-sha2-nistp256` and an
  Ed25519 host key against OpenSSH 10.2. The rule now follows the cipher actually in force.

### Changed

- The shared secret is carried in its wire encoding (`mpint` for the classic exchanges, `string`
  for the hybrids) through `SSHKexUtils.computeExchangeHash` and `deriveKey`; callers that used
  those helpers directly pass the encoded bytes now (`encodeSharedSecretMpint` /
  `encodeSharedSecretString`).

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
