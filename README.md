# zest_ssh_core

[![test](https://github.com/AffluentMods/zest_ssh_core/actions/workflows/test.yml/badge.svg)](https://github.com/AffluentMods/zest_ssh_core/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Dart SSH and SFTP library, forked from [dartssh2](https://github.com/TerminalStudio/dartssh2) and hardened for use in [ZestSSH](https://zestssh.com).

The reason it is public: the code that talks to your servers should be code you can read. This is the exact SSH stack ZestSSH ships, nothing stripped out for the open-source version. If you want to know how the client authenticates, what it negotiates, or how it handles a host key, it is all here.

MIT licensed, free to use, and staying that way.

## Relationship to dartssh2

This started as a fork of dartssh2 by TerminalStudio, which is also MIT. The upstream license is kept in `LICENSE`.

Fork point: dartssh2 `<FILL IN: exact upstream version or commit>`. The GitHub "forked from" header and the compare view show the full diff against upstream, so you can see every change rather than taking this README's word for it.

What changed, at a glance:

- Weak algorithms removed from the negotiated defaults (see the table below). They are still implemented, but a server has to be met with an explicit opt-in profile, not offered them by every connection.
- Terrapin (CVE-2023-48795) strict key exchange, with sequence-number reset after the first `NEWKEYS`.
- The client identification banner reports `zest_ssh_core`, not the upstream string, so a server operator or a scanner can attribute the behaviour to this library.
- A batch of reliability and SFTP fixes carried in from ZestSSH field use.

## Security posture

Two profiles. The default is what every connection proposes. The compatibility profile is opt-in, for reaching an old server that cannot do better, and you pass it deliberately.

| Category | Default (proposed to every server) | Compatibility only (opt-in) |
| --- | --- | --- |
| Key exchange | `curve25519-sha256@libssh.org`, `ecdh-sha2-nistp521`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp256`, `diffie-hellman-group-exchange-sha256`, `diffie-hellman-group14-sha256` | `diffie-hellman-group14-sha1`, `diffie-hellman-group-exchange-sha1`, `diffie-hellman-group1-sha1` |
| Host keys | `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`, `ecdsa-sha2-nistp521`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp256` | `ssh-rsa` (SHA-1) |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-ctr`, `aes128-ctr` | `aes256-cbc`, `aes192-cbc`, `aes128-cbc` |
| MACs | `hmac-sha2-512-etm`, `hmac-sha2-256-etm`, `hmac-sha2-512`, `hmac-sha2-256`, `hmac-sha1`, `hmac-sha2-512-96`, `hmac-sha2-256-96` | `hmac-md5` |

Two honest caveats:

- `hmac-sha1` is still in the default MACs, listed last, for older-server reach. The SHA-1 key exchanges and the `ssh-rsa` SHA-1 host key are the ones that were pulled from the defaults, because a SHA-1 collision matters far more in key exchange and signatures than in a MAC. If you want SHA-1 gone entirely, drop `SSHMacType.hmacSha1` from your `SSHAlgorithms`.
- A few algorithms exist in the source but are not in the default proposal (for example AES-GCM and `aes192-ctr`). The definitive lists are the `const` defaults in [`lib/src/ssh_algorithm.dart`](lib/src/ssh_algorithm.dart); that file is the source of truth, not this table.

### Terrapin

Verified with the [Terrapin scanner](https://github.com/RUB-NDS/Terrapin-Scanner) that strict key exchange is negotiated and that no vulnerable cipher and MAC combinations are offered by default. The scanner checks advertised algorithms and strict-KEX support, not runtime behaviour, so that is exactly what this claim covers, no more.

### Choosing the compatibility profile

The defaults are a `const SSHAlgorithms()`. To reach a legacy server, build your own and pass it:

```dart
final client = SSHClient(
  await SSHSocket.connect('legacy.example.com', 22),
  username: 'user',
  algorithms: SSHAlgorithms(
    cipher: [
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes256cbc, // opt back in, on purpose
    ],
  ),
  // ...
);
```

## Maintenance

Upstream dartssh2 security fixes are tracked and merged. The reason to keep this a real fork rather than a rewrite is exactly that: when something lands upstream, it can be pulled in instead of reimplemented. Anything out of scope for a security fix stays close to upstream so those merges keep working.

## Usage

```yaml
dependencies:
  zest_ssh_core:
    git: https://github.com/AffluentMods/zest_ssh_core.git
```

```dart
import 'dart:convert';

import 'package:zest_ssh_core/zest_ssh_core.dart';

void main() async {
  final client = SSHClient(
    await SSHSocket.connect('example.com', 22),
    username: 'user',
    onPasswordRequest: () => 'password',
  );

  final result = await client.run('uname -a');
  print(utf8.decode(result));

  client.close();
  await client.done;
}
```

More in [`example/`](example/): interactive shells, command execution, SFTP, local and remote and dynamic forwarding, jump hosts, and public-key auth.

## Security reporting

Found something? See [SECURITY.md](SECURITY.md). Reports go straight to a person, not a ticket queue.

## License

MIT. See [LICENSE](LICENSE). The upstream dartssh2 copyright is preserved there alongside this fork's.
