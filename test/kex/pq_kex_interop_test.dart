@Tags(['integration'])
library;

import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// Interop of the hybrid post-quantum key exchanges against a REAL OpenSSH
/// server (10.2 in WSL, started by scratchpad/setup_sshd.sh on
/// 127.0.0.1:2299 with a user-owned host key and an ed25519 client key).
///
/// Skipped when that server is not running, so the suite stays green on a
/// machine without it. Override the defaults with ZESTSSH_TEST_SSHD_HOST /
/// _PORT / _USER / _KEY.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? 'discr';
  final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ??
      r'\\wsl.localhost\Ubuntu\home\discr\zestssh-sshd-test\client_ed25519';

  Future<bool> serverUp() async {
    try {
      final s = await Socket.connect(host, port,
          timeout: const Duration(seconds: 2));
      s.destroy();
      return File(keyPath).existsSync();
    } catch (_) {
      return false;
    }
  }

  Future<String> runWith(SSHKexType kex, {String? expectNegotiated}) async {
    final socket = await SSHSocket.connect(host, port);
    final client = SSHClient(
      socket,
      username: user,
      identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
      algorithms: SSHAlgorithms(kex: [kex]),
    );
    await client.authenticated;
    final out = await client.run('echo PQ-OK');
    final negotiated = client.diagnostics.negotiatedKex;
    client.close();
    await client.done;
    expect(negotiated, expectNegotiated ?? kex.name);
    return String.fromCharCodes(out).trim();
  }

  group('post-quantum KEX against OpenSSH', () {
    late bool up;
    setUpAll(() async => up = await serverUp());

    test('mlkem768x25519-sha256 completes and authenticates', () async {
      if (!up) {
        markTestSkipped('test sshd not running on $host:$port');
        return;
      }
      expect(await runWith(SSHKexType.mlkem768x25519), 'PQ-OK');
    });

    test('sntrup761x25519-sha512 completes and authenticates', () async {
      if (!up) {
        markTestSkipped('test sshd not running on $host:$port');
        return;
      }
      expect(await runWith(SSHKexType.sntrup761x25519), 'PQ-OK');
    });

    test('sntrup761x25519-sha512@openssh.com completes and authenticates',
        () async {
      if (!up) {
        markTestSkipped('test sshd not running on $host:$port');
        return;
      }
      expect(await runWith(SSHKexType.sntrup761x25519OpenSSH), 'PQ-OK');
    });

    test('the default preference list negotiates the PQ exchange', () async {
      if (!up) {
        markTestSkipped('test sshd not running on $host:$port');
        return;
      }
      final socket = await SSHSocket.connect(host, port);
      final client = SSHClient(
        socket,
        username: user,
        identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
      );
      await client.authenticated;
      final negotiated = client.diagnostics.negotiatedKex;
      client.close();
      await client.done;
      expect(negotiated, 'mlkem768x25519-sha256');
    });

    // Regression for the K encoding refactor: every classic family still
    // completes (mpint K), one test each so a failure names the exchange.
    for (final kex in [
      SSHKexType.x25519,
      SSHKexType.x25519Iana,
      SSHKexType.nistp256,
      SSHKexType.nistp521,
      SSHKexType.dhGexSha256,
      SSHKexType.dh14Sha256,
    ]) {
      test('classic ${kex.name} still works', () async {
        if (!up) {
          markTestSkipped('test sshd not running on $host:$port');
          return;
        }
        expect(await runWith(kex), 'PQ-OK');
      });
    }
  });
}
