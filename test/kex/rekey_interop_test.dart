// SPDX-License-Identifier: MIT
@Tags(['integration'])
library;

import 'dart:io';
import 'dart:mirrors';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// A second key exchange on a live session, against a REAL OpenSSH server
/// (the one test/kex/pq_kex_interop_test.dart uses, started by
/// tool/test_sshd.sh on 127.0.0.1:2299).
///
/// An exchange takes one proposal, one answer and one NEWKEYS, each once
/// (ssh_transport.dart, `_kexStep`). These check that holding a server to
/// that does not stand in the way of what real servers do: every later
/// exchange on a session must still go through, asked for by this side or
/// by the server, and the session must carry on under the new keys.
///
/// Skipped when that server is not running. For the exchanges the SERVER
/// asks for, the second server of tool/test_sshd.sh is needed, the one with
/// a small `RekeyLimit` (ZESTSSH_TEST_REKEY_SSHD_PORT, default 2297);
/// skipped when it is not there.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
  final rekeyPort = int.tryParse(env['ZESTSSH_TEST_REKEY_SSHD_PORT'] ?? '') ?? 2297;
  // Nobody's name in here: the user is this machine's, and the key lies in
  // that user's home in WSL (or in $HOME where the tests run on Linux).
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows
          ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test'
          : '${env['HOME']}/zestssh-sshd-test');
  final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';

  Future<bool> serverUp(int port) async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return File(keyPath).existsSync();
    } catch (_) {
      return false;
    }
  }

  Future<SSHClient> connect(int port, {SSHAlgorithms algorithms = const SSHAlgorithms()}) async {
    final client = SSHClient(
      await SSHSocket.connect(host, port),
      username: user,
      identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
      algorithms: algorithms,
    );
    await client.authenticated;
    return client;
  }

  /// Asks the transport under [client] for a new key exchange, as an
  /// application could if the client offered it.
  void askForNewKeys(SSHClient client) {
    final library = reflectClass(SSHClient).owner as LibraryMirror;
    final transport = reflect(client).getField(MirrorSystem.getSymbol('_transport', library));
    transport.invoke(#rekey, const []);
  }

  Future<void> untilExchanged(SSHClient client, DateTime? before) async {
    final end = DateTime.now().add(const Duration(seconds: 10));
    while (client.diagnostics.kexCompleted == before) {
      if (DateTime.now().isAfter(end)) fail('no new key exchange was completed');
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  Future<String> said(SSHClient client, String word) async =>
      String.fromCharCodes(await client.run('echo $word')).trim();

  group('a key exchange this side asks for, on a live session', () {
    late bool up;
    setUpAll(() async => up = await serverUp(port));

    for (final (name, algorithms) in [
      ('the defaults (post-quantum hybrid, ChaCha20-Poly1305)', const SSHAlgorithms()),
      ('curve25519 with aes256-ctr and a MAC', const SSHAlgorithms(
          kex: [SSHKexType.x25519], cipher: [SSHCipherType.aes256ctr], mac: [SSHMacType.hmacSha256])),
      ('nistp256 with encrypt-then-MAC', const SSHAlgorithms(
          kex: [SSHKexType.nistp256], cipher: [SSHCipherType.aes256ctr], mac: [SSHMacType.hmacSha256Etm])),
      ('a group exchange', const SSHAlgorithms(kex: [SSHKexType.dhGexSha256])),
      ('sntrup761', const SSHAlgorithms(kex: [SSHKexType.sntrup761x25519])),
    ]) {
      test('$name: the session carries on under the new keys, twice over', () async {
        if (!up) {
          markTestSkipped('test sshd not running on $host:$port');
          return;
        }
        final client = await connect(port, algorithms: algorithms);
        addTearDown(client.close);
        expect(await said(client, 'before'), 'before');
        for (final round in ['first', 'second']) {
          final was = client.diagnostics.kexCompleted;
          askForNewKeys(client);
          await untilExchanged(client, was);
          expect(client.isClosed, isFalse, reason: 'after the $round exchange');
          expect(await said(client, round), round);
        }
      });
    }

    test('asked for while output is streaming: nothing is lost and the session carries on', () async {
      if (!up) {
        markTestSkipped('test sshd not running on $host:$port');
        return;
      }
      final client = await connect(port);
      addTearDown(client.close);
      final session = await client.execute('seq 1 200000');
      final was = client.diagnostics.kexCompleted;
      final lines = <int>[];
      var asked = false;
      final carry = StringBuffer();
      await for (final chunk in session.stdout) {
        carry.write(String.fromCharCodes(chunk));
        final text = carry.toString();
        final end = text.lastIndexOf('\n');
        if (end >= 0) {
          lines.addAll(text.substring(0, end).split('\n').where((l) => l.isNotEmpty).map(int.parse));
          carry
            ..clear()
            ..write(text.substring(end + 1));
        }
        if (!asked && lines.length > 20000) {
          asked = true;
          askForNewKeys(client);
        }
      }
      expect(asked, isTrue);
      expect(lines.length, 200000);
      expect(lines.first, 1);
      expect(lines.last, 200000);
      for (var i = 1; i < lines.length; i += 997) {
        expect(lines[i], i + 1);
      }
      await untilExchanged(client, was);
      expect(await said(client, 'after'), 'after');
    });
  });

  group('a key exchange the server asks for (RekeyLimit)', () {
    late bool up;
    setUpAll(() async => up = await serverUp(rekeyPort));

    for (final (name, algorithms) in [
      ('the defaults', const SSHAlgorithms()),
      ('aes256-ctr with a MAC', const SSHAlgorithms(cipher: [SSHCipherType.aes256ctr], mac: [SSHMacType.hmacSha256])),
    ]) {
      test('$name: megabytes of output across several exchanges arrive whole', () async {
        if (!up) {
          markTestSkipped('test sshd with a RekeyLimit not running on $host:$rekeyPort');
          return;
        }
        final client = await connect(rekeyPort, algorithms: algorithms);
        addTearDown(client.close);
        final first = client.diagnostics.kexCompleted;
        // About 2.9 MB of numbers: with a limit of a megabyte the server
        // asks for new keys at least twice on the way.
        final out = String.fromCharCodes(await client.run('seq 1 400000'));
        final lines = out.trim().split('\n');
        expect(lines.length, 400000);
        expect(lines.first, '1');
        expect(lines.last, '400000');
        expect(client.diagnostics.kexCompleted, isNot(first), reason: 'the server asked for new keys meanwhile');
        expect(client.isClosed, isFalse);
        expect(await said(client, 'after'), 'after');
      });
    }
  });
}
