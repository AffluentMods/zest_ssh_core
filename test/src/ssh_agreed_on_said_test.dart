// SPDX-License-Identifier: MIT
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/transport/ssh_events.dart';

import 'played_server.dart';

/// What a client says it agreed on with a server: a MAC only where one is
/// used.
///
/// A client says which algorithms a connection has, for whoever shows them
/// to a person or writes them to a log (`SSHClient.diagnostics`, and the
/// event of each key exchange). chacha20-poly1305 and AES-GCM check their
/// packets by themselves: there is no MAC beside them, whatever the two
/// proposals named for one, and they always name one. The transport said
/// the MAC that the proposals had in common all the same, so a connection
/// under chacha20-poly1305, which is what most have, was said to be under
/// that cipher and, for example, hmac-sha2-512-etm@openssh.com, which
/// protects nothing of it, or the word "none" where the proposals had none
/// in common. (OpenSSH says `MAC: <implicit>` there.)
void main() {
  /// A client that offers whatever a played server here proposes, and for
  /// the MAC what a played server names beside any cipher.
  SSHClient wide(SSHSocket socket, {List<SSHMacType> mac = const [SSHMacType.hmacSha256Etm, SSHMacType.hmacSha256]}) =>
      SSHClient(
        socket,
        username: 'deploy',
        algorithms: SSHAlgorithms(
          kex: const [SSHKexType.x25519],
          hostkey: const [SSHHostkeyType.ed25519],
          cipher: const [
            SSHCipherType.chacha20poly1305,
            SSHCipherType.aes256gcm,
            SSHCipherType.aes256ctr,
            SSHCipherType.aes256cbc,
          ],
          mac: mac,
        ),
        keepAliveInterval: null,
      );

  Future<PlayedServer> signedIn(PlayedSuite suite, {List<SSHMacType>? mac}) async {
    final server = await PlayedServer.signedIn(
        client: (socket, _) => mac == null ? wide(socket) : wide(socket, mac: mac), suite: suite);
    addTearDown(server.client.close);
    return server;
  }

  group('a cipher that checks its packets by itself: no MAC is said', () {
    for (final suite in [PlayedSuite.chacha, PlayedSuite.gcm]) {
      test('$suite, with a MAC named in both proposals', () async {
        final server = await signedIn(suite);
        expect(server.client.diagnostics.negotiatedCipher, suite.cipher.name);
        expect(server.client.diagnostics.negotiatedMac, '');
      });

      test('$suite, with no MAC that both proposals name', () async {
        // The played server names hmac-sha2-256 beside any cipher; this client has another.
        final server = await signedIn(suite, mac: const [SSHMacType.hmacSha512]);
        expect(server.client.diagnostics.negotiatedCipher, suite.cipher.name);
        expect(server.client.diagnostics.negotiatedMac, '');
      });
    }
  });

  group('a cipher with a MAC beside it: the MAC is said', () {
    for (final suite in [PlayedSuite.ctr, PlayedSuite.ctrEtm, PlayedSuite.cbc]) {
      test('$suite', () async {
        final server = await signedIn(suite);
        expect(server.client.diagnostics.negotiatedCipher, suite.cipher.name);
        expect(server.client.diagnostics.negotiatedMac, suite.mac!.name);
      });
    }
  });

  // One cipher and one MAC are said for a connection: those of what the
  // client sends.
  group('the two directions under different suites: what the client sends is what is said', () {
    Future<PlayedServer> signedInEachWay(PlayedSuite toServer, PlayedSuite toClient) async {
      final server = await PlayedServer.signedIn(
          client: (socket, _) => wide(socket), suite: toServer, toClient: toClient);
      addTearDown(server.client.close);
      return server;
    }

    test('chacha20-poly1305 out and aes256-ctr with a MAC in: the cipher, and no MAC', () async {
      final server = await signedInEachWay(PlayedSuite.chacha, PlayedSuite.ctr);
      expect(server.client.diagnostics.negotiatedCipher, PlayedSuite.chacha.cipher.name);
      expect(server.client.diagnostics.negotiatedMac, '');
    });

    test('aes256-ctr with a MAC out and chacha20-poly1305 in: the cipher and its MAC', () async {
      final server = await signedInEachWay(PlayedSuite.ctr, PlayedSuite.chacha);
      expect(server.client.diagnostics.negotiatedCipher, PlayedSuite.ctr.cipher.name);
      expect(server.client.diagnostics.negotiatedMac, PlayedSuite.ctr.mac!.name);
    });

    test('the same cipher with one kind of MAC out and another in: the one of what goes out', () async {
      final server = await signedInEachWay(PlayedSuite.ctrEtm, PlayedSuite.ctr);
      expect(server.client.diagnostics.negotiatedMac, PlayedSuite.ctrEtm.mac!.name);
    });
  });

  test('after new keys under another suite, what was agreed on then: a MAC goes and comes with its cipher', () async {
    final server = await signedIn(PlayedSuite.ctrEtm);
    expect(server.client.diagnostics.negotiatedMac, PlayedSuite.ctrEtm.mac!.name);
    await server.rekey(suite: PlayedSuite.chacha);
    expect(server.client.diagnostics.negotiatedCipher, PlayedSuite.chacha.cipher.name);
    expect(server.client.diagnostics.negotiatedMac, '');
    await server.rekey(suite: PlayedSuite.ctr);
    expect(server.client.diagnostics.negotiatedCipher, PlayedSuite.ctr.cipher.name);
    expect(server.client.diagnostics.negotiatedMac, PlayedSuite.ctr.mac!.name);
  });

  test('the event of each key exchange says the same', () async {
    final server = PlayedServer(suite: PlayedSuite.chacha);
    final client = wide(server.socket);
    addTearDown(client.close);
    final said = <SSHEventKexStarted>[];
    final listening = client.events.listen((event) {
      if (event is SSHEventKexStarted) said.add(event);
    });
    addTearDown(listening.cancel);
    await server.letIn();
    await client.authenticated.timeout(PlayedServer.patience);
    await server.rekey(suite: PlayedSuite.ctrEtm);
    await server.settle();
    expect(said.map((event) => (event.cipher, event.mac)), [
      (PlayedSuite.chacha.cipher.name, ''),
      (PlayedSuite.ctrEtm.cipher.name, PlayedSuite.ctrEtm.mac!.name),
    ]);
    expect(said.map((event) => event.kexAlgorithm).toSet(), {SSHKexType.x25519.name});
    expect(said.map((event) => event.hostKeyAlgorithm).toSet(), {SSHHostkeyType.ed25519.name});
  });
}
