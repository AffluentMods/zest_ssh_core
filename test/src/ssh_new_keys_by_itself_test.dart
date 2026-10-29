// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' show SHA256Digest;
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_ignore.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/transport/ssh_events.dart';

import 'played_server.dart';
import 'real_openssh_server.dart';

/// A client asks for new keys by itself, once enough has gone one way under
/// those in force.
///
/// It took new keys when the server asked, and never asked: nothing counted
/// what went out or came in under a set of keys, and the number of a packet
/// went from 2^32 - 1 back to nought without a word. RFC 4253 (9)
/// recommends new keys after each gigabyte, and RFC 4344 (3.1) says that a
/// side must not send more than 2^32 packets under one set. Under
/// chacha20-poly1305, which most sessions have, the number of the packet is
/// the nonce: with a server that never asks, the 2^32nd packet came under a
/// nonce used before with the same keys. An OpenSSH server asks after about
/// a gigabyte, so with one it did not come about.
///
/// Now a side asks after a gigabyte or 2^31 packets one way, as OpenSSH
/// does, and ends the connection where the new keys do not come and twice
/// that many packets, less one, have gone one way.
///
/// The limits of these tests are small ones, given to the client. The real
/// servers are those of tool/test_sshd.sh (2299, and 2289 for AES-GCM);
/// their tests skip themselves where the servers are not running.
void main() {
  test('where nothing is said: after a gigabyte, or 2^31 packets', () {
    expect(SSHTransport.defaultRekeyAfterBytes, 1024 * 1024 * 1024);
    expect(SSHTransport.defaultRekeyAfterPackets, 2147483648);
  });

  group('a server played by the test', () {
    late List<SSHEvent> events;

    int exchanges() => events.whereType<SSHEventKexCompleted>().length;

    /// A client with the limits it is given, signed in to a played server.
    Future<PlayedServer> signedIn({int? afterPackets, int? afterBytes}) async {
      events = [];
      final server = await PlayedServer.signedIn(
        client: (socket, algorithms) {
          final client = SSHClient(
            socket,
            username: 'deploy',
            algorithms: algorithms,
            keepAliveInterval: null,
            rekeyAfterPackets: afterPackets ?? SSHTransport.defaultRekeyAfterPackets,
            rekeyAfterBytes: afterBytes ?? SSHTransport.defaultRekeyAfterBytes,
          );
          final listening = client.events.listen(events.add);
          addTearDown(listening.cancel);
          return client;
        },
      );
      addTearDown(server.client.close);
      return server;
    }

    /// [count] packets from the server that ask nothing of the client, each
    /// carrying [bytes] bytes.
    Future<void> sends(PlayedServer server, int count, {int bytes = 0}) async {
      // One at a time: what the client does about each is done before the next.
      for (var i = 0; i < count; i++) {
        server.send([SSH_Message_Ignore(Uint8List(bytes)).encode()]);
      }
      await server.settle();
    }

    Future<bool> asked(PlayedServer server) => server.sent(SSH_Message_KexInit.messageId);

    test('enough packets have come in: new keys are asked for, once; the session goes on under them, and the '
        'count begins again', () async {
      final server = await signedIn(afterPackets: 60);
      expect(exchanges(), 1);
      await sends(server, 20);
      expect(await asked(server), isFalse, reason: 'not before its time');

      await sends(server, 60);
      expect(await asked(server), isTrue);
      // The server answers: its proposal, the exchange, new keys both ways.
      await server.rekey();
      await server.settle();
      expect(exchanges(), 2);
      expect(server.client.isClosed, isFalse);
      expect(await asked(server), isFalse, reason: 'asked once: the proposal the server has read');

      // Under the new keys the count began again: not asked before as many have come once more.
      await sends(server, 30);
      expect(await asked(server), isFalse);
      await sends(server, 40);
      expect(await asked(server), isTrue);
      await server.rekey();
      await server.settle();
      expect(exchanges(), 3);
      expect(server.client.isClosed, isFalse);
    });

    test('enough bytes have come in, in few packets: new keys are asked for', () async {
      final server = await signedIn(afterBytes: 8000);
      await sends(server, 3, bytes: 2000);
      expect(await asked(server), isFalse);
      await sends(server, 2, bytes: 2000);
      expect(await asked(server), isTrue);
      await server.rekey();
      await server.settle();
      expect(exchanges(), 2);
      // And again from nought.
      await sends(server, 3, bytes: 2000);
      expect(await asked(server), isFalse);
    });

    test('new keys the server asked for put the counts at nought as well', () async {
      final server = await signedIn(afterPackets: 60);
      await sends(server, 40);
      expect(await asked(server), isFalse);
      await server.rekey();
      await server.settle();
      expect(exchanges(), 2);
      // Forty before those keys and thirty under them: not sixty under one set.
      await sends(server, 30);
      expect(await asked(server), isFalse);
      await sends(server, 40);
      expect(await asked(server), isTrue);
    });

    test('with nothing said, a session of little traffic asks for none', () async {
      final server = await signedIn();
      await sends(server, 300, bytes: 500);
      expect(await asked(server), isFalse);
      expect(exchanges(), 1);
    });

    test('the new keys do not come and the server goes on sending: the connection is ended before a count of '
        'packets runs round, saying so', () async {
      final server = await signedIn(afterPackets: 60);
      Object? endedWith;
      unawaited(server.client.done.then((_) {}, onError: (Object error) {
        endedWith = error;
      }));
      await sends(server, 70);
      expect(await asked(server), isTrue);
      expect(server.client.isClosed, isFalse, reason: 'asked, and waiting');
      // Nothing is answered. Twice sixty, less one, is where it ends.
      await sends(server, 60);
      await server.settle();
      expect(server.client.isClosed, isTrue);
      expect(
        endedWith,
        isA<SSHHandshakeError>().having((e) => e.message, 'what it says',
            allOf(startsWith('New keys were asked for and have not come: '), contains(' packets have gone one way'))),
      );
    });
  });

  group('a real OpenSSH server', () {
    final plain = RealOpenSshServer.fromEnvironment();
    final gcmOnly = RealOpenSshServer.gcmOnly();
    const limit = 256 * 1024;

    Future<(SSHClient, List<SSHEvent>)> connect(
      RealOpenSshServer server, {
      SSHAlgorithms algorithms = const SSHAlgorithms(),
      int afterBytes = limit,
      int afterPackets = SSHTransport.defaultRekeyAfterPackets,
    }) async {
      final socket = await SSHSocket.connect(server.host, server.port);
      final client = SSHClient(
        socket,
        username: server.user,
        identities: SSHKeyPair.fromPem(File(server.keyPath).readAsStringSync()),
        keepAliveInterval: null,
        algorithms: algorithms,
        rekeyAfterBytes: afterBytes,
        rekeyAfterPackets: afterPackets,
      );
      final events = <SSHEvent>[];
      final listening = client.events.listen(events.add);
      addTearDown(listening.cancel);
      addTearDown(client.close);
      await client.authenticated;
      return (client, events);
    }

    int exchanges(List<SSHEvent> events) => events.whereType<SSHEventKexCompleted>().length;

    // Nearly seven megabytes of lines, each of which says where it belongs: a channel's window several times
    // over, so that the server waits for the client now and then, and an exchange has time.
    const count = 1000000;
    final lines = [for (var i = 1; i <= count; i++) '$i\n'].join();

    for (final (name, server, algorithms, cipher) in [
      ('chacha20-poly1305', plain, const SSHAlgorithms(), 'chacha20-poly1305@openssh.com'),
      (
        'aes256-ctr with a MAC',
        plain,
        const SSHAlgorithms(cipher: [SSHCipherType.aes256ctr], mac: [SSHMacType.hmacSha256Etm]),
        'aes256-ctr',
      ),
      ('AES-GCM', gcmOnly, const SSHAlgorithms(), 'aes256-gcm@openssh.com'),
    ]) {
      test('$name: megabytes come in whole while the client asks for new keys at each quarter of one', () async {
        final skip = await server.unavailable();
        if (skip != null) return markTestSkipped(skip);
        final (client, events) = await connect(server, algorithms: algorithms);
        expect(client.diagnostics.negotiatedCipher, cipher);
        expect(exchanges(events), 1);
        final got = String.fromCharCodes(await client.run('seq 1 $count'));
        expect(got.length, lines.length);
        expect(got == lines, isTrue, reason: 'every line, in its place');
        expect(client.isClosed, isFalse);
        // The session carries on: what is asked for during an exchange waits for the new keys.
        expect(String.fromCharCodes(await client.run('echo after')), 'after\n');
        // What a server sends before it has read the client's proposal still comes under the keys of before,
        // so not every quarter of a megabyte is an exchange. Several are, and nobody but the client asked.
        expect(exchanges(events), greaterThanOrEqualTo(3));
        // And no more than one for each quarter: new keys put the count at nought.
        expect(exchanges(events), lessThanOrEqualTo(1 + lines.length ~/ limit));
      });
    }

    test('a megabyte goes out whole while the client asks for new keys at each quarter of one', () async {
      final skip = await plain.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final (client, events) = await connect(plain);
      final sent = Uint8List(1024 * 1024);
      for (var i = 0; i < sent.length; i++) {
        sent[i] = (i * 31 + (i >> 8)) & 0xFF;
      }
      final session = await client.execute('sha256sum');
      final out = BytesBuilder(copy: false);
      final read = session.stdout.listen(out.add);
      // In pieces, as a program writes: each waits its turn at the channel's window.
      for (var at = 0; at < sent.length; at += 32 * 1024) {
        session.stdin.add(Uint8List.sublistView(sent, at, at + 32 * 1024));
      }
      await session.stdin.close();
      await session.done;
      await read.asFuture<void>().timeout(const Duration(seconds: 20), onTimeout: () {});
      final hex = [for (final b in SHA256Digest().process(sent)) b.toRadixString(16).padLeft(2, '0')].join();
      expect(String.fromCharCodes(out.takeBytes()).split(' ').first, hex);
      // A megabyte at a quarter of one for each set of keys: four exchanges after the first, or one fewer
      // or more by what else went out, and not one for every packet.
      expect(exchanges(events), inInclusiveRange(4, 7));
      expect(client.isClosed, isFalse);
    });

    test('many small writes go out whole while the client asks for new keys at every five hundred packets',
        () async {
      final skip = await plain.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final (client, events) =
          await connect(plain, afterBytes: SSHTransport.defaultRekeyAfterBytes, afterPackets: 500);
      final session = await client.execute('sha256sum');
      final out = BytesBuilder(copy: false);
      final read = session.stdout.listen(out.add);
      final all = BytesBuilder(copy: false);
      for (var i = 0; i < 2400; i++) {
        final line = Uint8List.fromList('line $i\n'.codeUnits);
        all.add(line);
        session.stdin.add(line);
        // A few at a time, as a program types: each is a packet of its own.
        if (i % 40 == 39) await Future<void>.delayed(const Duration(milliseconds: 2));
      }
      await session.stdin.close();
      await session.done;
      await read.asFuture<void>().timeout(const Duration(seconds: 20), onTimeout: () {});
      final hex = [for (final b in SHA256Digest().process(all.takeBytes())) b.toRadixString(16).padLeft(2, '0')].join();
      expect(String.fromCharCodes(out.takeBytes()).split(' ').first, hex);
      expect(exchanges(events), inInclusiveRange(3, 7));
      expect(client.isClosed, isFalse);
    });

    test('with nothing said, such a session asks for no new keys', () async {
      final skip = await plain.unavailable();
      if (skip != null) return markTestSkipped(skip);
      final (client, events) = await connect(plain, afterBytes: SSHTransport.defaultRekeyAfterBytes);
      final got = String.fromCharCodes(await client.run('seq 1 $count'));
      expect(got == lines, isTrue);
      expect(String.fromCharCodes(await client.run('echo after')), 'after\n');
      expect(exchanges(events), 1);
    });
  });
}
