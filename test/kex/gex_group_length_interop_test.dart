@Tags(['integration'])
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';

/// How long a group a real OpenSSH server names in a group exchange, for
/// what this client asks of it.
///
/// In a group exchange the client says how long a group it would like, and
/// the server picks from the groups it has the shortest that is at least
/// that long. The client said it would like 2048 bits, which is the
/// shortest it takes at all: a server that has longer groups too (OpenSSH
/// ships them from 2048 up to 8192 bits) named a group of 2048, the weakest
/// of everything both sides have. That is about 112 bits of work to break,
/// where every other key exchange this client offers is at 128 or more,
/// and the secret this client brings to a group exchange is made for 128.
///
/// It asks for 3072 bits now, which is that level. Against the test sshd of
/// tool/test_sshd.sh (skipped where it is not running).
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows
          ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test'
          : '${env['HOME']}/zestssh-sshd-test');
  final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';

  Future<bool> serverUp() async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return File(keyPath).existsSync();
    } catch (_) {
      return false;
    }
  }

  /// A client that has a group exchange and no other key exchange, signed
  /// in to the server: how long the group was that the server named, as the
  /// client's own lines say it, and whether a command runs under it.
  Future<({int bits, String said})> exchanged(SSHKexType kex) async {
    final lines = <String>[];
    final client = SSHClient(
      await SSHSocket.connect(host, port),
      username: user,
      identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
      algorithms: SSHAlgorithms(kex: [kex]),
      printDebug: (line) => lines.add('$line'),
    );
    addTearDown(client.close);
    await client.authenticated;
    final said = String.fromCharCodes(await client.run('echo under-the-group')).trim();
    final named = RegExp(r'the server named a group of (\d+) bits').firstMatch(lines.join('\n'));
    expect(named, isNotNull, reason: 'the client says how long the group is that it was named');
    return (bits: int.parse(named![1]!), said: said);
  }

  late bool up;
  setUpAll(() async => up = await serverUp());

  // (The exchange under its older name, with SHA-1, is one this server does not offer.)
  test('a real server names a group of the length that was asked for, and the session runs under it', () async {
    if (!up) return markTestSkipped('test sshd not running on $host:$port');
    final o = await exchanged(SSHKexType.dhGexSha256);
    expect(o.said, 'under-the-group');
    expect(o.bits, SSHKexDH.gexPref, reason: 'OpenSSH has a group of every length it may be asked for');
    expect(o.bits, 3072);
  });
}
