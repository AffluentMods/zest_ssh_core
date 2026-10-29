# Architecture

zest_ssh_core is an SSH-2 client library in pure Dart: transport, key exchange, user
authentication, channels (sessions, port forwarding, agent forwarding) and an SFTP client. It runs
wherever Dart runs with `dart:io` sockets, and in the browser through a WebSocket socket of your own.

## How a connection runs

1. **Socket.** `SSHSocket` (`lib/src/socket/`) is the byte stream: a TCP socket on `dart:io`, or a
   socket the caller supplies.
2. **Transport.** `SSHTransport` (`lib/src/ssh_transport.dart`) exchanges version lines, frames and
   encrypts packets (`ssh_packet.dart`, `algorithm/`), runs the key exchange and rekeys
   (`transport/ssh_rekey_manager.dart`), and checks the host key before anything else is trusted.
3. **Key exchange.** `lib/src/kex/` holds the exchanges: the hybrid post-quantum ML-KEM-768 and
   sntrup761 with X25519, Curve25519, the NIST curves, and finite-field Diffie-Hellman with group
   exchange. Which ones are offered, and in what order, is `SSHAlgorithms`
   (`lib/src/ssh_algorithm.dart`).
4. **Host keys.** `lib/src/hostkey/` verifies host key signatures (Ed25519, ECDSA and RSA by default;
   Ed448 is there but not offered by default); the caller decides whether to trust a key through the `onVerifyHostKey` callback.
5. **Client.** `SSHClient` (`lib/src/ssh_client.dart`) signs in (`ssh_userauth.dart`: none, public
   key, password, keyboard-interactive, in the order the server allows) and opens channels
   (`ssh_channel.dart`, `ssh_session.dart`, `ssh_forward.dart`, `ssh_agent.dart`).
6. **SFTP.** `SftpClient` (`lib/src/sftp/`) speaks SFTP version 3 over a channel.

Messages on the wire are in `lib/src/message/`, keys and their file formats in `ssh_key_pair.dart`,
`ssh_pem.dart` and `ssh_key_file.dart`, and errors in `ssh_errors.dart` and `exceptions/`.

## Where the security checks live

- **Algorithm floors and opt-ins:** `ssh_algorithm.dart` (the default and the compatibility lists,
  the shortest RSA host key and Diffie-Hellman group taken).
- **Handshake order and strict key exchange (Terrapin):** `ssh_transport.dart`.
- **Host key checks** (type, signature, RSA modulus and exponent): `ssh_transport.dart` and
  `hostkey/`.
- **Memory hygiene:** `utils/secure_memory.dart` zeroes keys that are replaced.

See [docs/ASSURANCE.md](docs/ASSURANCE.md) for why these checks are enough, and
[SECURITY.md](SECURITY.md) to report a problem.

## Tests

`test/` mirrors `lib/`: unit tests, key-exchange vectors (`test/kex`, including NIST ACVP vectors for
ML-KEM-768), fixtures, and fuzz tests over packets, messages and keys (`test/fuzz`). CI runs format,
analysis and every test on each push (`.github/workflows/test.yml`).
