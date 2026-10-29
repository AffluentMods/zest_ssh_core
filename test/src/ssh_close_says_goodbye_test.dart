// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_disconnect.dart';

import 'played_failing_socket.dart';
import 'played_server.dart';
import 'real_openssh_server.dart';

/// A client that closes its connection says so first.
///
/// The protocol has a message for it (SSH_MSG_DISCONNECT, RFC 4253, 11.1):
/// a side that ends a connection says that it does, and why, and then
/// closes. The client closed its socket and said nothing: a server wrote
/// "Connection closed by ..." into its log for every session that its
/// person had simply ended, which is what it writes when a connection
/// breaks, and never "Received disconnect from ...: disconnected by ...",
/// which is what it writes of a client that left in order.
///
/// With a played server, which reads what the client sends last; and with a
/// real OpenSSH server (the first one tool/test_sshd.sh starts, on
/// 127.0.0.1:2299), whose own log is read. The second is skipped where that
/// server is not running.
void main() {
  group('with a played server', () {
    /// What the client sent after [closing], as far as the server could read
    /// it, and whether the server saw the connection end.
    Future<({List<SSH_Message_Disconnect> goodbyes, List<int> others})> afterwards(
      PlayedServer server,
      void Function() closing,
    ) async {
      server.takeSent();
      closing();
      await server.settle();
      final sent = server.takeSent();
      return (
        goodbyes: [
          for (final packet in sent)
            if (packet[0] == SSH_Message_Disconnect.messageId) SSH_Message_Disconnect.decode(packet),
        ],
        others: [
          for (final packet in sent)
            if (packet[0] != SSH_Message_Disconnect.messageId) packet[0],
        ],
      );
    }

    test('a client that is signed in and closes says that it leaves, once, and its connection is over', () async {
      final server = await PlayedServer.signedIn();
      var over = false;
      unawaited(server.client.done.then<void>((_) {
        over = true;
      }));
      final sent = await afterwards(server, server.client.close);
      expect(sent.goodbyes, hasLength(1));
      // 11: by the application (SSH_DISCONNECT_BY_APPLICATION).
      expect(sent.goodbyes.single.reasonCode, 11);
      expect(sent.goodbyes.single.description, 'disconnected by application');
      expect(sent.others, isEmpty);
      expect(over, isTrue);
      expect(server.client.isClosed, isTrue);
      // Closed again, it says nothing more.
      expect((await afterwards(server, server.client.close)).goodbyes, isEmpty);
    });

    test('under each way of protecting packets the server can read it: it goes out as every packet before it',
        () async {
      for (final suite in [PlayedSuite.ctr, PlayedSuite.ctrEtm, PlayedSuite.cbc, PlayedSuite.gcm, PlayedSuite.chacha]) {
        final server = await PlayedServer.signedIn(
          client: (socket, algorithms) =>
              SSHClient(socket, username: 'deploy', algorithms: algorithms, keepAliveInterval: null),
          suite: suite,
        );
        final sent = await afterwards(server, server.client.close);
        expect(sent.goodbyes, hasLength(1), reason: '$suite');
      }
    });

    test('a connection that ends over an error says nothing: what was wrong with it is not told to the other side',
        () async {
      final server = await PlayedServer.signedIn();
      unawaited(server.client.done.then<void>((_) {}, onError: (Object _) {}));
      // A packet whose check value was changed on the way.
      server.takeSent();
      server.sendChanged([SSH_Message_Disconnect(reasonCode: 2, description: 'x').encode()], (packets) {
        packets.single[packets.single.length - 1] ^= 0x01;
      });
      await server.settle();
      expect(server.client.isClosed, isTrue);
      expect(server.takeSent(), isEmpty);
    });

    test('a client that closes before any keys are in force says nothing in the clear, and its socket is closed '
        'at once', () async {
      final server = PlayedServer();
      final socket = WatchedSocket(server.socket);
      final client = SSHTransport(socket, algorithms: PlayedServer.algorithms);
      await server.settle();
      final before = socket.did.length;
      client.close();
      // Nothing was written, nothing is waited for.
      expect(socket.did.skip(before), ['destroy']);
      await server.settle();
      // Its version line and its proposal went out, and nothing after them.
      expect(server.takeSent().map((packet) => packet[0]), isNot(contains(SSH_Message_Disconnect.messageId)));
      expect(client.isClosed, isTrue);
    });

    /// A client signed in on a watched socket.
    Future<({PlayedServer server, WatchedSocket socket})> watched() async {
      late WatchedSocket socket;
      final server = await PlayedServer.signedIn(
        client: (played, algorithms) => SSHClient(
          socket = WatchedSocket(played),
          username: 'deploy',
          algorithms: algorithms,
          keepAliveInterval: null,
        ),
      );
      return (server: server, socket: socket);
    }

    test('the socket is closed once the goodbye has left it, and not before', () async {
      final (:server, :socket) = await watched();
      socket.held = Completer<void>();
      final before = socket.did.length;
      server.client.close();
      await server.settle();
      // The goodbye was written, and is on its way out: the socket is still there.
      expect(socket.did.skip(before), ['write', 'flush']);
      socket.held!.complete();
      await server.settle();
      expect(socket.did.skip(before), ['write', 'flush', 'flushed', 'destroy']);
    });

    test('where the goodbye does not leave, the socket is closed on it after two seconds', () async {
      final (:server, :socket) = await watched();
      // A flush that never ends: the other side takes nothing more.
      socket.held = Completer<void>();
      server.client.close();
      await Future<void>.delayed(const Duration(milliseconds: 1500));
      expect(socket.destroyed, isFalse);
      await Future<void>.delayed(const Duration(milliseconds: 1000));
      expect(socket.destroyed, isTrue);
    });

    test('a socket that takes no goodbye, since it has gone: the client closes all the same, with nothing thrown '
        'and nothing waited for', () async {
      final (:server, :socket) = await watched();
      socket.writesFail = true;
      final before = socket.did.length;
      server.client.close();
      expect(socket.did.skip(before), ['destroy']);
      expect(server.client.isClosed, isTrue);
    });

    test('while what was sent before is still on its way out, nothing is added to it and the socket is closed '
        'at once', () async {
      final server = PlayedServer();
      final socket = WatchedSocket(server.socket);
      final client = SSHTransport(socket, algorithms: PlayedServer.algorithms, onVerifyHostKey: (type, key) => true);
      await server.exchangeKeys();
      await server.settle();
      // Whoever sends a lot waits for the socket to take it: that wait is under way.
      socket.held = Completer<void>();
      unawaited(client.drainSocket());
      await server.settle();
      final before = socket.did.length;
      client.close();
      expect(socket.did.skip(before), ['destroy']);
      socket.held!.complete();
    });
  });

  group('with a real OpenSSH server', () {
    final real = RealOpenSshServer.fromEnvironment();
    String? unavailable;

    setUpAll(() async => unavailable = await real.unavailable());

    test('the server writes that the client left in order, and not that the connection was closed on it', () async {
      if (unavailable != null) return markTestSkipped(unavailable!);
      final client = SSHClient(
        await SSHSocket.connect(real.host, real.port, timeout: const Duration(seconds: 5)),
        username: real.user,
        identities: SSHKeyPair.fromPem(File(real.keyPath).readAsStringSync()),
      );
      await client.authenticated.timeout(const Duration(seconds: 20));
      // The port the server sees this connection come from, which is what its log names it by.
      final seenFrom = int.parse(utf8.decode(await client.run(r'echo $SSH_CLIENT')).split(' ')[1]);
      client.close();
      final lines = await real.logged(seenFrom);
      expect(lines, contains(contains('Received disconnect from')), reason: lines.join('\n'));
      expect(lines, contains(contains(':11: disconnected by application')), reason: lines.join('\n'));
      expect(lines.where((line) => line.startsWith('Connection closed by')), isEmpty, reason: lines.join('\n'));
    }, timeout: const Timeout(Duration(seconds: 60)));
  });
}
