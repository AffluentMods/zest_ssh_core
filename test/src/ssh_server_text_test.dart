// SPDX-License-Identifier: MIT
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// A server whose notice before sign-in is not UTF-8, for real: an OpenSSH
/// server with a `Banner` file in ISO 8859-1 (tool/test_sshd.sh starts it on
/// 127.0.0.1:2295; its notice is "Zugang nur f?r Befugte." with the single
/// byte 0xFC where the question mark stands). The one byte was taken for a
/// packet that cannot be read, and the connection ended before sign-in:
/// such a host could not be connected to at all.
///
/// Skipped when that server is not running.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_BANNER_SSHD_PORT'] ?? '') ?? 2295;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
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

  test('a notice before sign-in with a byte that is no UTF-8: signed in all the same, and the notice handed over '
      'as far as it reads', () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server with a notice is not running');
      return;
    }
    final notices = <String>[];
    final client = SSHClient(
      await SSHSocket.connect(host, port),
      username: user,
      identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
      onUserauthBanner: notices.add,
    );
    addTearDown(client.close);
    await client.authenticated.timeout(const Duration(seconds: 15));
    // Where the byte could not be read: U+FFFD, the replacement character.
    final mark = String.fromCharCode(0xfffd);
    expect(notices, ['Zugang nur f${mark}r Befugte.\n']);
    expect(utf8.decode(await client.run('echo signed-in')).trim(), 'signed-in');
  });
}
