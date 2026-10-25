import 'dart:async';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

import 'played_server.dart';
import 'real_openssh_server.dart';

/// AES-GCM is in the default proposal, after the ciphers that were in it.
///
/// The package has spoken aes256-gcm@openssh.com and aes128-gcm@openssh.com
/// for a long time, and offered neither unless it was asked to. A server
/// whose ciphers are set to those two alone, as some that are set up
/// strictly are, was one a default client had nothing in common with: "No
/// matching client cipher algorithm".
///
/// They are offered now, last: the first cipher of the client's list that
/// the server has too is the one agreed on (RFC 4253, 7.1), so a server
/// that has any of the three that were offered before is connected to under
/// the same cipher as before, and AES-GCM is agreed on only where a server
/// has nothing else.
///
/// The real servers are those of tool/test_sshd.sh: the first (2299), which
/// has what a current OpenSSH has, and the seventh (2289), whose ciphers
/// are the two AES-GCM ones and no other. Their tests skip themselves where
/// the servers are not running.
void main() {
  const offeredBefore = ['chacha20-poly1305@openssh.com', 'aes256-ctr', 'aes128-ctr'];
  const gcm = ['aes256-gcm@openssh.com', 'aes128-gcm@openssh.com'];
  List<String> names(List<SSHCipherType> ciphers) => [for (final cipher in ciphers) cipher.name];

  /// The proposal of every version before this one, as far as ciphers go.
  const asBefore = SSHAlgorithms(
    cipher: [SSHCipherType.chacha20poly1305, SSHCipherType.aes256ctr, SSHCipherType.aes128ctr],
  );

  test('the default proposal: the three ciphers that were in it, in their order, then the two AES-GCM ones', () {
    const algorithms = SSHAlgorithms();
    expect(names(algorithms.cipher), [...offeredBefore, ...gcm]);
    // What was offered before is what a list of one's own with those three is: nothing of it moved.
    expect(names(algorithms.cipher).sublist(0, 3), names(asBefore.cipher));
    // No CBC cipher by default, as before, and no cipher twice.
    expect(names(algorithms.cipher).where((name) => name.endsWith('-cbc')), isEmpty);
    expect(names(algorithms.cipher).toSet().length, algorithms.cipher.length);
    // Nothing else of the proposal changed with it.
    expect(asBefore.kex, algorithms.kex);
    expect(asBefore.hostkey, algorithms.hostkey);
    expect(asBefore.mac, algorithms.mac);
  });

  group('a server played by the test', () {
    /// A client that is told nothing of algorithms, or [algorithms], signed
    /// in to a played server that has the cipher of [suite] and no other.
    Future<PlayedServer> signedIn(PlayedSuite suite, {SSHAlgorithms? algorithms}) async {
      final server = await PlayedServer.signedIn(
        client: (socket, _) => algorithms == null
            ? SSHClient(socket, username: 'deploy', keepAliveInterval: null)
            : SSHClient(socket, username: 'deploy', keepAliveInterval: null, algorithms: algorithms),
        suite: suite,
      );
      addTearDown(server.client.close);
      return server;
    }

    for (final cipher in [SSHCipherType.aes256gcm, SSHCipherType.aes128gcm]) {
      test('a client that is told nothing of ciphers, and a server that has ${cipher.name} alone: signed in under '
          'it, with no MAC beside it', () async {
        final server = await signedIn(PlayedSuite(cipher));
        expect(server.client.diagnostics.negotiatedCipher, cipher.name);
        expect(server.client.diagnostics.negotiatedMac, '');
      });
    }

    test('a server that has one of the ciphers offered before is connected to under it, as before', () async {
      for (final suite in [PlayedSuite.chacha, PlayedSuite.ctr]) {
        final server = await signedIn(suite);
        expect(server.client.diagnostics.negotiatedCipher, suite.cipher.name);
      }
    });

    test('the proposal of before has nothing in common with a server that has AES-GCM alone, and says what each '
        'side offered', () async {
      final server = PlayedServer(suite: PlayedSuite.gcm);
      final client = SSHClient(server.socket, username: 'deploy', keepAliveInterval: null, algorithms: asBefore);
      addTearDown(client.close);
      unawaited(server.letIn().then((_) {}, onError: (Object _) {}));
      final failure = await client.authenticated
          .then<Object?>((_) => null, onError: (Object error) => error)
          .timeout(PlayedServer.patience);
      expect(failure, isA<SSHAuthAbortError>());
      final reason = (failure! as SSHAuthAbortError).reason;
      expect(reason, isA<SSHHandshakeError>());
      final handshake = reason! as SSHHandshakeError;
      expect(handshake.message, contains('cipher'));
      expect(handshake.offered, offeredBefore);
      expect(handshake.otherSideOffered, ['aes256-gcm@openssh.com']);
    });
  });

  group('a real OpenSSH server', () {
    final plain = RealOpenSshServer.fromEnvironment();
    final gcmOnly = RealOpenSshServer.gcmOnly();

    Future<SSHClient> connect(RealOpenSshServer server, {SSHAlgorithms? algorithms}) async {
      final socket = await SSHSocket.connect(server.host, server.port);
      final identities = SSHKeyPair.fromPem(File(server.keyPath).readAsStringSync());
      final client = algorithms == null
          ? SSHClient(socket, username: server.user, identities: identities, keepAliveInterval: null)
          : SSHClient(socket,
              username: server.user, identities: identities, keepAliveInterval: null, algorithms: algorithms);
      addTearDown(client.close);
      return client;
    }

    Future<String> said(SSHClient client, String command) async => String.fromCharCodes(await client.run(command));

    test('one whose ciphers are the two AES-GCM ones alone: a client that is told nothing of ciphers signs in, '
        'under aes256-gcm, and a session runs', () async {
      final skip = await gcmOnly.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final client = await connect(gcmOnly);
      await client.authenticated;
      expect(client.diagnostics.negotiatedCipher, 'aes256-gcm@openssh.com');
      expect(client.diagnostics.negotiatedMac, '');
      expect(await said(client, 'echo under-gcm'), 'under-gcm\n');
      // More than fits a packet, both ways: the count of packets under the keys goes on.
      final long = await said(client, 'head -c 300000 /dev/zero | tr "\\0" "x" | wc -c');
      expect(long.trim(), '300000');
      final echoed = await said(client, 'printf %s "${'y' * 4000}" | wc -c');
      expect(echoed.trim(), '4000');
    });

    test('the same server, and the proposal of before: nothing in common, with what the server offers', () async {
      final skip = await gcmOnly.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final client = await connect(gcmOnly, algorithms: asBefore);
      final failure = await client.authenticated.then<Object?>((_) => null, onError: (Object error) => error);
      expect(failure, isA<SSHAuthAbortError>());
      final reason = (failure! as SSHAuthAbortError).reason;
      expect(reason, isA<SSHHandshakeError>());
      final handshake = reason! as SSHHandshakeError;
      expect(handshake.offered, offeredBefore);
      expect(handshake.otherSideOffered, gcm);
    });

    test('the same server, and a client that has aes128-gcm alone: signed in under it', () async {
      final skip = await gcmOnly.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final client = await connect(gcmOnly, algorithms: const SSHAlgorithms(cipher: [SSHCipherType.aes128gcm]));
      await client.authenticated;
      expect(client.diagnostics.negotiatedCipher, 'aes128-gcm@openssh.com');
      expect(await said(client, 'echo under-gcm-128'), 'under-gcm-128\n');
    });

    test('a server that has what a current OpenSSH has: the cipher it was connected to under before, and with '
        'that one left out, AES-CTR before AES-GCM', () async {
      final skip = await plain.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final client = await connect(plain);
      await client.authenticated;
      expect(client.diagnostics.negotiatedCipher, 'chacha20-poly1305@openssh.com');
      expect(await said(client, 'echo as-before'), 'as-before\n');

      // The rest of the default list, in its order: the server has all four of them.
      final rest = const SSHAlgorithms().cipher.sublist(1);
      expect(names(rest), ['aes256-ctr', 'aes128-ctr', ...gcm]);
      final without = await connect(plain, algorithms: SSHAlgorithms(cipher: rest));
      await without.authenticated;
      expect(without.diagnostics.negotiatedCipher, 'aes256-ctr');
    });
  });
}
