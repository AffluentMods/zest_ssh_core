// SPDX-License-Identifier: MIT
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_ignore.dart';
import 'package:zest_ssh_core/src/message/msg_request.dart';

import 'played_server.dart';

/// New keys under other algorithms than the ones before.
///
/// A key exchange agrees on a cipher and a MAC for each direction, and each
/// side takes them into use with the new keys: for what it sends from its
/// own NEWKEYS on, and for what it reads from the other side's NEWKEYS on
/// (RFC 4253, 7.3). Until then everything goes as it did, the rest of that
/// exchange too. At the first exchange of a connection there is nothing
/// before, so it never mattered there that this transport put what was
/// agreed on to use the moment the proposals were compared. At a later
/// exchange it did: what the client sent for the rest of the exchange, its
/// own NEWKEYS with it, went out under the framing of the new algorithms
/// with the keys of the old ones, or with no keys at all, in the clear; and
/// what the server sent before its NEWKEYS was read as if it were under the
/// new ones. Nothing secret is in those packets, and only the server whose
/// host key was approved can propose other algorithms on a connection, but
/// no such exchange could end well, and a packet left the client in the
/// clear with keys in force.
///
/// The server is played (played_server.dart), and the played server is held
/// to the OpenSSH client (played_server_openssh_test.dart), which takes new
/// keys under every change of suites that is asked of this client here.
void main() {
  const suites = [PlayedSuite.ctr, PlayedSuite.ctrEtm, PlayedSuite.cbc, PlayedSuite.gcm, PlayedSuite.chacha];

  /// What a client here offers: whatever a played server may propose.
  const offered = SSHAlgorithms(
    kex: [SSHKexType.x25519],
    hostkey: [SSHHostkeyType.ed25519],
    cipher: [
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256gcm,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes256cbc,
    ],
    mac: [SSHMacType.hmacSha256Etm, SSHMacType.hmacSha256],
  );

  Future<PlayedServer> signedIn(PlayedSuite suite, {PlayedSuite? toClient, required bool strict}) async {
    final server = await PlayedServer.signedIn(
      client: (socket, _) => SSHClient(socket, username: 'deploy', algorithms: offered, keepAliveInterval: null),
      suite: suite,
      toClient: toClient,
      strict: strict,
    );
    addTearDown(server.client.close);
    return server;
  }

  /// Each side asks the other something and reads its answer, twice over.
  Future<void> bothWays(PlayedServer server) async {
    for (var i = 0; i < 2; i++) {
      server.send([SSH_Message_Global_Request(requestName: 'keepalive@openssh.com', wantReply: true).encode()]);
      await server.next(SSH_Message_Request_Failure.messageId);
      final answered = server.client.ping();
      await server.next(SSH_Message_Global_Request.messageId);
      server.send([SSH_Message_Request_Success(Uint8List(0)).encode()]);
      await answered.timeout(PlayedServer.patience);
    }
    expect(server.client.isClosed, isFalse);
  }

  group('the played server, where a test asks it for what cannot be', () {
    Matcher saying(String words) => throwsA(isA<StateError>().having((e) => e.message, 'what it says', contains(words)));

    test('new keys before the first exchange is over: it says so', () {
      expect(PlayedServer().beginRekey, saying('once the first exchange is over'));
    });

    test('the end of an exchange that is not under way, or that has ended: it says so', () async {
      final server = await signedIn(PlayedSuite.ctr, strict: true);
      await expectLater(server.finishRekey, saying('no exchange is under way'));
      await server.rekey();
      await expectLater(server.finishRekey, saying('no exchange is under way'));
      await bothWays(server);
    });
  });

  for (final strict in [true, false]) {
    final how = strict ? 'the strict exchange' : 'no strict exchange';

    group('new keys under another suite, $how', () {
      for (final from in suites) {
        for (final to in suites) {
          if (identical(from, to)) continue;
          test('$from, then $to: the exchange ends well and the session carries on', () async {
            final server = await signedIn(from, strict: strict);
            await bothWays(server);
            await server.rekey(suite: to);
            await bothWays(server);
          });
        }
      }

      test('new keys five times over, each time under another suite, and once more under the same', () async {
        const order = [PlayedSuite.chacha, PlayedSuite.ctrEtm, PlayedSuite.gcm, PlayedSuite.ctr, PlayedSuite.chacha, PlayedSuite.cbc];
        final server = await signedIn(order.first, strict: strict);
        for (final suite in order.skip(1)) {
          await server.rekey(suite: suite);
          await bothWays(server);
        }
        await server.rekey();
        await bothWays(server);
      });
    });

    group('one direction at a time, $how', () {
      test('only what the client sends changes its suite', () async {
        final server = await signedIn(PlayedSuite.chacha, strict: strict);
        await server.rekey(suite: PlayedSuite.ctrEtm, toClient: PlayedSuite.chacha);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.gcm, toClient: PlayedSuite.chacha);
        await bothWays(server);
      });

      test('only what the client is sent changes its suite', () async {
        final server = await signedIn(PlayedSuite.chacha, strict: strict);
        await server.rekey(suite: PlayedSuite.chacha, toClient: PlayedSuite.ctrEtm);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.chacha, toClient: PlayedSuite.gcm);
        await bothWays(server);
      });

      test('the two directions have a suite each, and exchange them', () async {
        final server = await signedIn(PlayedSuite.gcm, toClient: PlayedSuite.ctr, strict: strict);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.ctr, toClient: PlayedSuite.gcm);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.ctrEtm, toClient: PlayedSuite.chacha);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.chacha, toClient: PlayedSuite.ctrEtm);
        await bothWays(server);
      });

      test('only the MAC changes, one direction and then the other', () async {
        final server = await signedIn(PlayedSuite.ctr, strict: strict);
        await server.rekey(suite: PlayedSuite.ctrEtm, toClient: PlayedSuite.ctr);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.ctrEtm, toClient: PlayedSuite.ctrEtm);
        await bothWays(server);
        await server.rekey(suite: PlayedSuite.ctr, toClient: PlayedSuite.ctrEtm);
        await bothWays(server);
      });
    });

    // The transport by itself, for what a client never says and a transport
    // can: a message that may not wait for the exchange to end (RFC 4253,
    // 7.1 lets the first four kinds through), sent while it is under way.
    group('while the exchange is under way, $how', () {
      Uint8List note(String words) => SSH_Message_Ignore(Uint8List.fromList(utf8.encode(words))).encode();

      for (final (from, to) in [
        (PlayedSuite.chacha, PlayedSuite.ctrEtm),
        (PlayedSuite.ctrEtm, PlayedSuite.chacha),
        (PlayedSuite.gcm, PlayedSuite.ctr),
        (PlayedSuite.ctr, PlayedSuite.gcm),
        (PlayedSuite.ctr, PlayedSuite.ctrEtm),
        (PlayedSuite.chacha, PlayedSuite.gcm),
      ]) {
        test('$from, then $to: what is said before each side\'s NEWKEYS goes as before, and what is said after it '
            'under the new', () async {
          final server = PlayedServer(suite: from, strict: strict);
          final handedUp = <Uint8List>[];
          final transport = SSHTransport(
            server.socket,
            algorithms: offered,
            onVerifyHostKey: (type, key) => true,
            onPacket: handedUp.add,
          );
          addTearDown(transport.close);
          await server.exchangeKeys();

          await server.beginRekey(suite: to);
          // The proposals are compared by now, and the answer has not come.
          transport.sendPacket(note('the client, while the exchange is under way'));
          expect(await server.next(SSH_Message_Ignore.messageId), note('the client, while the exchange is under way'));
          server.send([note('the server, while the exchange is under way')]);
          await server.settle();
          expect(handedUp, [note('the server, while the exchange is under way')]);

          await server.finishRekey();
          transport.sendPacket(note('the client, under the new keys'));
          expect(await server.next(SSH_Message_Ignore.messageId), note('the client, under the new keys'));
          server.send([note('the server, under the new keys')]);
          await server.settle();
          expect(handedUp.last, note('the server, under the new keys'));
          expect(transport.isClosed, isFalse);
          expect(server.takeSent(), isEmpty, reason: 'nothing else was sent, in the clear or otherwise');
        });
      }
    });
  }
}
