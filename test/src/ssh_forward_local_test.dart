// SPDX-License-Identifier: MIT
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// A connection that a server passes on to another host (direct-tcpip:
/// what `ssh -J` and a jump host are made of), against real OpenSSH servers
/// (tool/test_sshd.sh): the first (127.0.0.1:2299) is asked to pass a
/// connection on to the second (2297). Skipped when they are not running.
///
/// What a server answers when it does not open the way is what an
/// application tells its person apart by: reason code 1 where it passes no
/// connections on at all (forwarding turned off there, or not allowed for
/// the key that signed in), and reason code 2 where it tried and could not
/// reach the other host itself, with its own words for why.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
  final nextPort = int.tryParse(env['ZESTSSH_TEST_REKEY_SSHD_PORT'] ?? '') ?? 2297;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');

  Future<bool> listening(int port) async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return true;
    } catch (_) {
      return false;
    }
  }

  /// The test key [name], or null where the servers were set up without it.
  List<SSHKeyPair>? key(String name) {
    final file = File('$dir/$name');
    return file.existsSync() ? SSHKeyPair.fromPem(file.readAsStringSync()) : null;
  }

  /// A client signed in with [keys], to the server at [port] or over the
  /// connection [over].
  Future<SSHClient> signedIn(int port, List<SSHKeyPair> keys, {SSHSocket? over}) async {
    final client = SSHClient(
      over ?? await SSHSocket.connect(host, port, timeout: const Duration(seconds: 5)),
      username: user,
      identities: keys,
    );
    addTearDown(client.close);
    await client.authenticated.timeout(const Duration(seconds: 20));
    return client;
  }

  Future<Object?> failureOf(Future<Object?> doing) async {
    try {
      await doing.timeout(const Duration(seconds: 20));
      return null;
    } catch (e) {
      return e;
    }
  }

  test('a connection passed on to another host carries a whole connection of its own, and ends with the one it '
      'goes through', () async {
    final keys = key('client_ed25519');
    if (keys == null || !await listening(port) || !await listening(nextPort)) {
      markTestSkipped('the test OpenSSH servers are not running');
      return;
    }
    final first = await signedIn(port, keys);
    final way = await first.forwardLocal(host, nextPort).timeout(const Duration(seconds: 20));
    final second = await signedIn(nextPort, keys, over: way);
    expect(utf8.decode(await second.run('echo passed-on')), contains('passed-on'));
    // The second connection is inside the first: it ends when the first does.
    first.close();
    await second.done.timeout(const Duration(seconds: 20)).catchError((Object _) {});
    expect(second.isClosed, isTrue);
  });

  test('a key that may open no connection on: the server says no with reason code 1, and the connection goes on',
      () async {
    final keys = key('client_noforward_ed25519');
    if (keys == null || !await listening(port) || !await listening(nextPort)) {
      markTestSkipped('the test OpenSSH servers are not running, or were set up without the key that may not forward');
      return;
    }
    final first = await signedIn(port, keys);
    final failure = await failureOf(first.forwardLocal(host, nextPort));
    expect(failure, isA<SSHChannelOpenError>().having((e) => e.code, 'reason code', 1), reason: '$failure');
    // Whatever else the key may do still works.
    expect(utf8.decode(await first.run('echo still-here')), contains('still-here'));
  });

  test('a host the server cannot reach itself: reason code 2, with the server\'s own words for why, and the '
      'connection goes on', () async {
    final keys = key('client_ed25519');
    if (keys == null || !await listening(port)) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    final first = await signedIn(port, keys);
    // Nothing listens on port 1 of this machine.
    final failure = await failureOf(first.forwardLocal(host, 1));
    expect(
      failure,
      isA<SSHChannelOpenError>()
          .having((e) => e.code, 'reason code', 2)
          .having((e) => e.description.toLowerCase(), 'its words', contains('refused')),
      reason: '$failure',
    );
    expect(utf8.decode(await first.run('echo still-here')), contains('still-here'));
    // And the way to a host that is there is opened on the same connection afterwards.
    if (await listening(nextPort)) {
      final way = await first.forwardLocal(host, nextPort).timeout(const Duration(seconds: 20));
      final second = await signedIn(nextPort, keys, over: way);
      expect(utf8.decode(await second.run('echo passed-on')), contains('passed-on'));
    }
  });
}
