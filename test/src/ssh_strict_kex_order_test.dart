// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_debug.dart';
import 'package:zest_ssh_core/src/message/msg_ignore.dart';
import 'package:zest_ssh_core/src/message/msg_request.dart';
import 'package:zest_ssh_core/src/message/msg_service.dart';

import 'played_openssh_client.dart';
import 'played_server.dart';

/// The strict key exchange, held to its order.
///
/// Where both sides name the strict key exchange (OpenSSH's answer to the
/// Terrapin attack, CVE-2023-48795), the first exchange of a connection
/// carries the messages of that exchange and nothing else, and the server's
/// proposal is the first packet it sends: a packet that is put in before
/// the keys are in force shifts the count of packets, which is what the
/// attack is made of. The client kept the second half (after the proposal
/// it took the messages of an exchange and no other), and not the first: a
/// message that may come at any time (IGNORE, DEBUG, UNIMPLEMENTED) passed
/// when it came before the server's proposal, since nothing is known of a
/// strict exchange until that proposal is read. And what it took after the
/// proposal was any number an exchange may use, where an exchange has one
/// answer under one number.
///
/// What OpenSSH does with a packet before the proposal is asked of the
/// OpenSSH clients of the machine, with the same played server.
void main() {
  final ignore = SSH_Message_Ignore(Uint8List(4)).encode();
  final debug = SSH_Message_Debug(
    alwaysDisplay: false,
    message: Uint8List.fromList('hello'.codeUnits),
    language: Uint8List(0),
  ).encode();
  // SSH_MSG_UNIMPLEMENTED, of the packet numbered nought.
  final unimplemented = Uint8List.fromList([3, 0, 0, 0, 0]);
  // A number an exchange may use, and this one does not.
  final ofAnotherExchange = Uint8List.fromList([40, 0, 0, 0, 0]);

  /// A client on a played server that names the strict exchange, or does
  /// not ([strict]), and plays the first exchange with what the test puts
  /// into it: whether the connection is ready and open, what it ended with,
  /// and the numbers of the messages the client handed up.
  Future<({bool ready, Object? endedWith, List<int> handedUp})> exchanged({
    required bool strict,
    List<Uint8List> first = const [],
    List<Uint8List> beforeAnswer = const [],
    List<Uint8List> beforeNewKeys = const [],
  }) async {
    final server = PlayedServer(strict: strict);
    var ready = false;
    var ended = false;
    Object? endedWith;
    final handedUp = <int>[];
    final client = SSHTransport(
      server.socket,
      algorithms: PlayedServer.algorithms,
      onVerifyHostKey: (type, key) => true,
      onReady: () => ready = true,
      onPacket: (packet) => handedUp.add(packet[0]),
    );
    addTearDown(client.close);
    unawaited(client.done.then<void>((_) {
      ended = true;
    }, onError: (Object error) {
      ended = true;
      endedWith = error;
    }));
    // Where the client ends the connection, the played server waits for what does not come.
    await server
        .exchangeKeys(first: first, beforeAnswer: beforeAnswer, beforeNewKeys: beforeNewKeys)
        .then((_) {}, onError: (Object _) {});
    await server.settle();
    return (ready: ready && !ended, endedWith: endedWith, handedUp: handedUp);
  }

  const notFirst = 'Strict KEX violation: the server\'s key exchange proposal was not the first packet it sent '
      '(possible Terrapin attack).';
  String notOfTheExchange(int id) =>
      'Strict KEX violation: unexpected message id $id during the initial key exchange (possible Terrapin attack).';

  /// The connection was ended for what does not belong into a strict
  /// exchange, said as [said] and marked as that, and was never ready.
  void expectEndedForTheOrder(({bool ready, Object? endedWith, List<int> handedUp}) outcome, String said) {
    expect(outcome.ready, isFalse);
    expect(
      outcome.endedWith,
      isA<SSHHandshakeError>()
          .having((e) => e.message, 'what it says', said)
          .having((e) => e.strictOrderBroken, 'the strict order broken', isTrue),
    );
  }

  group('a server that names the strict exchange', () {
    test('and keeps to its order: the connection is ready', () async {
      final outcome = await exchanged(strict: true);
      expect((outcome.ready, outcome.endedWith), (true, null));
    });

    for (final (what, message) in [('IGNORE', ignore), ('DEBUG', debug), ('UNIMPLEMENTED', unimplemented)]) {
      test('$what before its proposal: the proposal is not its first packet, and the connection ends', () async {
        expectEndedForTheOrder(await exchanged(strict: true, first: [message]), notFirst);
      });

      test('$what between the proposals and its answer: the connection ends', () async {
        expectEndedForTheOrder(await exchanged(strict: true, beforeAnswer: [message]), notOfTheExchange(message[0]));
      });

      test('$what between its answer and its NEWKEYS: the connection ends', () async {
        expectEndedForTheOrder(
            await exchanged(strict: true, beforeNewKeys: [message]), notOfTheExchange(message[0]));
      });
    }

    test('a message under a number that an exchange may use and this one does not, once the key was looked at: '
        'the connection ends, and the message is handed to nobody', () async {
      final outcome = await exchanged(strict: true, beforeNewKeys: [ofAnotherExchange]);
      expectEndedForTheOrder(outcome, notOfTheExchange(40));
      expect(outcome.handedUp, isNot(contains(40)));
    });

    test('the same message before its answer: the connection ends', () async {
      final outcome = await exchanged(strict: true, beforeAnswer: [ofAnotherExchange]);
      expectEndedForTheOrder(outcome, notOfTheExchange(40));
      expect(outcome.handedUp, isNot(contains(40)));
    });

    test('each number a client may send in an exchange, sent by the server: no message of this exchange', () async {
      // 30, 32 and 34 are what a client sends (its start of an exchange, and the two of a group exchange).
      for (final id in [30, 32, 34]) {
        final outcome = await exchanged(strict: true, beforeNewKeys: [
          Uint8List.fromList([id, 0, 0, 0, 0])
        ]);
        expectEndedForTheOrder(outcome, notOfTheExchange(id));
      }
    });
  });

  test('an error of a key exchange is one of the strict order only where it says so', () {
    expect(SSHHandshakeError('No matching key exchange algorithm').strictOrderBroken, isFalse);
    expect(SSHHandshakeError('x', strictOrderBroken: true).strictOrderBroken, isTrue);
    expect('${SSHHandshakeError('x', strictOrderBroken: true)}', 'SSHHandshakeError(x)');
  });

  group('a server that does not name the strict exchange', () {
    test('and sends nothing else: the connection is ready', () async {
      final outcome = await exchanged(strict: false);
      expect((outcome.ready, outcome.endedWith), (true, null));
    });

    for (final (what, message) in [('IGNORE', ignore), ('DEBUG', debug), ('UNIMPLEMENTED', unimplemented)]) {
      test('$what before its proposal, and before its answer, and before its NEWKEYS: the connection is ready, as '
          'the protocol has it', () async {
        final outcome =
            await exchanged(strict: false, first: [message], beforeAnswer: [message], beforeNewKeys: [message]);
        expect((outcome.ready, outcome.endedWith), (true, null));
        expect(outcome.handedUp.where((id) => id == message[0]), hasLength(3), reason: 'each was handed up');
      });
    }
  });

  test('new keys on a connection that is open, under the strict exchange: a message that may come at any time '
      'comes in the middle of it, and the session carries on', () async {
    final server = await PlayedServer.signedIn();
    addTearDown(server.client.close);
    await server.beginRekey();
    server.send([ignore, debug]);
    await server.finishRekey();
    await server.settle();
    expect(server.client.isClosed, isFalse);
    // Each side reads the other under the new keys.
    server.send([SSH_Message_Global_Request(requestName: 'keepalive@openssh.com', wantReply: true).encode()]);
    await server.next(SSH_Message_Request_Failure.messageId);
  });

  group('what OpenSSH does with a packet before the proposal', () {
    final clients = OpenSshClient.found();
    if (clients.isEmpty) {
      test('asked of the OpenSSH client', () {}, skip: 'this machine has no OpenSSH client');
      return;
    }
    for (final client in clients) {
      test('$client, strict: IGNORE before the proposal ends the connection', () async {
        final run = await client.connect(offers: const [PlayedSuite.ctr], suite: PlayedSuite.ctr);
        addTearDown(run.end);
        await run.server.exchangeKeys(first: [ignore]).then((_) {}, onError: (Object _) {});
        expect(await run.exitCode, 255, reason: run.said.join('\n'));
        expect(run.said, contains(contains('KEXINIT was not the first packet')));
        expect(run.lookedAtOthersKeys, 0, reason: 'the client looked at a key that is not of the run');
      });

      test('$client, not strict: IGNORE before the proposal is passed over, and the client signs in', () async {
        final run = await client.connect(offers: const [PlayedSuite.ctr], suite: PlayedSuite.ctr, strict: false);
        addTearDown(run.end);
        await run.server.exchangeKeys(first: [ignore]);
        // It asks for the service it signs in with: the exchange was taken.
        await run.server.next(SSH_Message_Service_Request.messageId);
        expect(run.lookedAtOthersKeys, 0, reason: 'the client looked at a key that is not of the run');
      });
    }
  });
}
