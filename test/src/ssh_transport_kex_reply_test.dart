import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed25519;
import 'package:pointycastle/export.dart' show BlockCipher, SHA256Digest;
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';
import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
import 'package:zest_ssh_core/src/message/msg_disconnect.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/message/msg_kex_dh.dart';
import 'package:zest_ssh_core/src/message/msg_kex_ecdh.dart';
import 'package:zest_ssh_core/src/message/msg_service.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_kex_utils.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:zest_ssh_core/src/ssh_packet.dart';
import 'package:zest_ssh_core/src/utils/bigint.dart';

/// The answer to a key exchange is taken once.
///
/// A client asks the person (or its list of known hosts) about the host key
/// that came with the server's answer, and that takes time: a prompt, a
/// lookup. Whoever sits between the client and the server can use that time.
/// It lets the real server's answer through, signed by the key the client
/// trusts, and puts its own answer, signed by its own key, before and after
/// it. If every answer is taken, the trusted key is approved while the secret
/// in force is the one of the last answer, the attacker's: the session is
/// encrypted to the attacker under the approval of the real host's key, and
/// the password that follows goes to the attacker. The transport took every
/// answer until this was held.
///
/// So an exchange is one proposal, one answer (a group first, for a group
/// exchange) and one NEWKEYS, in that order, each taken once; whatever else
/// arrives for it ends the connection; and the keys put in force are those of
/// the answer whose host key was approved.
///
/// The other side is played here: [_Exchange] makes answers the way a server
/// does, signed by a host key of the test's, and [_Keys] speaks the encrypted
/// protocol that follows (aes256-ctr with hmac-sha2-256), so that the later
/// exchanges of a connection can be played too. Against a real OpenSSH see
/// test/kex/pq_kex_interop_test.dart and test/kex/rekey_interop_test.dart.
void main() {
  late _Wire wire;
  late SSHTransport client;
  late List<Uint8List> asked;
  late List<Uint8List> handedUp;
  late int ready;
  Object? closedWith;
  late bool closed;

  /// What the client is to say about a host key it is shown.
  late FutureOr<bool> Function(Uint8List hostKey) verdict;

  /// What is done the moment the client says the connection is ready.
  void Function()? whenReady;

  final trusted = _HostKey.generate();
  final attacker = _HostKey.generate();

  /// As the app answers: a key it knows is approved after a lookup, with
  /// nobody asked; a key it does not know waits for the person.
  FutureOr<bool> asTheAppDoes(Uint8List key) => _same(key, trusted.blob)
      ? Future<bool>.delayed(const Duration(milliseconds: 5), () => true)
      : Completer<bool>().future;

  /// A client that has sent its version, its proposal and its start of the
  /// exchange to a server that has sent its own version and proposal.
  /// [minDhGroupBits] is the shortest group it takes in a group exchange.
  Future<_Exchange> start({bool strict = true, bool group = false, int minDhGroupBits = 2048}) async {
    wire = _Wire();
    asked = [];
    handedUp = [];
    ready = 0;
    closedWith = null;
    closed = false;
    client = SSHTransport(
      wire,
      onPacket: handedUp.add,
      algorithms: SSHAlgorithms(
        kex: [group ? SSHKexType.dhGexSha256 : SSHKexType.x25519],
        hostkey: const [SSHHostkeyType.ed25519],
        cipher: const [SSHCipherType.aes256ctr],
        mac: const [SSHMacType.hmacSha256],
        minDhGroupBits: minDhGroupBits,
      ),
      onVerifyHostKey: (type, key) {
        asked.add(Uint8List.fromList(key));
        return verdict(key);
      },
      onReady: () {
        ready++;
        whenReady?.call();
      },
    );
    unawaited(client.done.then((_) => closed = true, onError: (Object e) {
      closed = true;
      closedWith = e;
    }));

    final serverKexInit = _proposal(strict: strict, group: group);
    wire.feed([...latin1.encode('$_serverVersion\r\n'), ..._plain(serverKexInit)]);
    await _settle();

    final sent = wire.clientOutput();
    return _Exchange(
      clientVersion: sent.version,
      clientKexInit: sent.packets.firstWhere((p) => p[0] == SSH_Message_KexInit.messageId),
      serverKexInit: serverKexInit,
      // The start of a plain exchange; a group exchange starts with a
      // request and names its public value only once it has the group.
      clientPublic: group
          ? Uint8List(0)
          : SSH_Message_KexECDH_Init.decode(
                  sent.packets.firstWhere((p) => p[0] == SSH_Message_KexECDH_Init.messageId))
              .ecdhPublicKey,
    );
  }

  /// A connection whose first exchange is over on both sides, with the keys
  /// both sides now use.
  Future<_Keys> established() async {
    verdict = (key) => true;
    final exchange = await start();
    final answer = exchange.answer(trusted);
    wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
    await _settle();
    expect(ready, 1);
    expect(closed, isFalse);
    expect(wire.clientOutput().packets.last, [SSH_Message_NewKeys.messageId]);
    wire.clearOutput();
    return _Keys(answer, sessionId: answer.hash);
  }

  setUp(() => whenReady = null);
  tearDown(() => client.close());

  group('the first exchange', () {
    test('one answer, the key approved: the keys in force are that answer\'s', () async {
      verdict = (key) => true;
      final exchange = await start();
      final answer = exchange.answer(trusted);
      wire.feed(_plain(answer.payload));
      await _settle();
      expect(asked, [trusted.blob]);
      expect(ready, 1);
      expect(closed, isFalse);

      wire.feed(_plain(SSH_Message_NewKeys().encode()));
      await _settle();
      final marker = Uint8List.fromList([2, 0, 0, 0, 4, 9, 8, 7, 6]);
      wire.clearOutput();
      client.sendPacket(marker);
      expect(_Keys(answer, sessionId: answer.hash).open(wire.rawOutput()), [marker],
          reason: 'whoever answered holds the keys');
    });

    test('a second answer while the first key is still being looked at ends the connection', () async {
      // The person has not answered the prompt for the first key yet.
      verdict = (key) => Completer<bool>().future;
      final exchange = await start();
      wire.feed(_plain(exchange.answer(attacker).payload));
      await _settle();
      expect(asked, hasLength(1));
      expect(closed, isFalse);

      wire.feed(_plain(exchange.answer(trusted).payload));
      await _settle();
      expect(closed, isTrue, reason: 'an exchange has one answer');
      expect(closedWith, isA<SSHHandshakeError>());
      expect('$closedWith', contains('one answer'));
      expect(asked, hasLength(1), reason: 'the second key is not even put to the person');
      expect(ready, 0);
    });

    // What it is all about. Two things stand in the way, and this test is
    // held by either of them alone: an exchange takes one answer, and the keys
    // put in force are the approved answer's or none (the fault check takes
    // the first away to see the second hold, and both to see this fail).
    for (final strict in [true, false]) {
      test(
          'the real answer between two of an attacker\'s: no session comes of it'
          '${strict ? '' : ' (nor without the strict key exchange, which is no defence here)'}', () async {
        verdict = asTheAppDoes;
        final exchange = await start(strict: strict);
        // All three in one read, as someone on the path would send them.
        wire.feed([
          ..._plain(exchange.answer(attacker).payload),
          ..._plain(exchange.answer(trusted).payload),
          ..._plain(exchange.answer(attacker).payload),
        ]);
        await _settle(const Duration(milliseconds: 60));

        expect(ready, 0, reason: 'the approval of the trusted key must not start a session on another answer');
        expect(closed, isTrue);

        // And the client sends nothing more, readable or not.
        wire.feed(_plain(SSH_Message_NewKeys().encode()));
        await _settle();
        wire.clearOutput();
        expect(() => client.sendPacket(Uint8List.fromList([2, 0, 0, 0, 1, 7])), throwsA(isA<SSHError>()));
        expect(wire.rawOutput(), isEmpty);
      });
    }

    test('it ends at the second answer, whose key is never shown', () async {
      verdict = asTheAppDoes;
      final exchange = await start();
      wire.feed([
        ..._plain(exchange.answer(attacker).payload),
        ..._plain(exchange.answer(trusted).payload),
        ..._plain(exchange.answer(attacker).payload),
      ]);
      await _settle(const Duration(milliseconds: 60));
      expect(closedWith, isA<SSHHandshakeError>());
      expect('$closedWith', contains('one answer'));
      expect(asked, [attacker.blob], reason: 'only the first key was ever shown');
    });

    test('the trusted key\'s own answer twice is one too many as well', () async {
      verdict = asTheAppDoes;
      final exchange = await start();
      final real = exchange.answer(trusted);
      wire.feed([..._plain(real.payload), ..._plain(real.payload)]);
      await _settle(const Duration(milliseconds: 60));
      expect(closed, isTrue);
      expect(ready, 0);
      expect(asked, hasLength(1));
    });

    test('a second proposal before the answer ends the connection', () async {
      verdict = (key) => true;
      final exchange = await start();
      wire.feed(_plain(exchange.serverKexInit));
      await _settle();
      expect(closed, isTrue, reason: 'one proposal to an exchange');
      expect(closedWith, isA<SSHHandshakeError>());
      expect('$closedWith', contains('proposal'));
    });

    test('a new proposal while the key is being looked at ends the connection, the server\'s NEWKEYS sent or not',
        () async {
      for (final newKeysFirst in [false, true]) {
        verdict = (key) => Completer<bool>().future;
        final exchange = await start();
        wire.feed([
          ..._plain(exchange.answer(trusted).payload),
          if (newKeysFirst) ..._plain(SSH_Message_NewKeys().encode()),
        ]);
        await _settle();
        expect(closed, isFalse, reason: 'so far a server\'s usual first exchange');
        if (newKeysFirst) {
          // From here the server speaks under the new keys, as it would.
          final keys = _Keys(exchange.lastAnswer, sessionId: exchange.lastAnswer.hash);
          wire.feed(keys.seal(_proposal()));
        } else {
          wire.feed(_plain(_proposal()));
        }
        await _settle();
        expect(closed, isTrue, reason: 'NEWKEYS first: $newKeysFirst');
        expect(closedWith, isA<SSHHandshakeError>());
        expect(asked, hasLength(1));
        expect(ready, 0);
        client.close();
      }
    });

    test('NEWKEYS with no answer before it ends the connection', () async {
      verdict = (key) => true;
      await start();
      wire.feed(_plain(SSH_Message_NewKeys().encode()));
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
      expect('$closedWith', contains('NEWKEYS'));
    });

    test('an answer before any proposal ends the connection', () async {
      wire = _Wire();
      asked = [];
      ready = 0;
      closed = false;
      closedWith = null;
      verdict = (key) => true;
      client = SSHTransport(wire, onVerifyHostKey: (type, key) => verdict(key), onReady: () => ready++);
      unawaited(client.done.then((_) => closed = true, onError: (Object e) {
        closed = true;
        closedWith = e;
      }));
      final writer = SSHMessageWriter()
        ..writeUint8(SSH_Message_KexECDH_Reply.messageId)
        ..writeString(trusted.blob)
        ..writeString(Uint8List(32))
        ..writeString(Uint8List(8));
      wire.feed([...latin1.encode('$_serverVersion\r\n'), ..._plain(writer.takeBytes())]);
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHError>());
      expect(ready, 0);
    });

    test('the keys in force are the approved answer\'s, however long the approval took', () async {
      final approve = Completer<bool>();
      verdict = (key) => approve.future;
      final exchange = await start();
      final answer = exchange.answer(trusted);
      // The server's NEWKEYS comes right behind its answer, as OpenSSH sends it.
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(ready, 0, reason: 'not before the person has answered');
      expect(wire.clientOutput().packets.where((p) => p[0] == SSH_Message_NewKeys.messageId), isEmpty,
          reason: 'our NEWKEYS waits for the approval');
      approve.complete(true);
      await _settle();
      expect(ready, 1);
      expect(wire.clientOutput().packets.last, [SSH_Message_NewKeys.messageId]);
      final marker = Uint8List.fromList([2, 0, 0, 0, 2, 5, 5]);
      wire.clearOutput();
      client.sendPacket(marker);
      expect(_Keys(answer, sessionId: answer.hash).open(wire.rawOutput()), [marker]);
    });

    test('by the time the connection is said to be ready, what is sent goes out under the new keys', () async {
      // A client asks for its first service the moment it is told so.
      final service = (SSHMessageWriter()
            ..writeUint8(5)
            ..writeUtf8('ssh-userauth'))
          .takeBytes();
      verdict = (key) => Future<bool>.delayed(const Duration(milliseconds: 5), () => true);
      final exchange = await start();
      whenReady = () {
        wire.clearOutput();
        client.sendPacket(service);
      };
      final answer = exchange.answer(trusted);
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle(const Duration(milliseconds: 60));
      expect(ready, 1);
      expect(closed, isFalse, reason: '$closedWith');
      expect(_Keys(answer, sessionId: answer.hash).open(wire.rawOutput()), [service]);
    });

    test('new keys asked for from this side while the key is being looked at: nothing goes out', () async {
      final approve = Completer<bool>();
      verdict = (key) => approve.future;
      final exchange = await start();
      final answer = exchange.answer(trusted);
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      final sentSoFar = wire.rawOutput().length;
      // The exchange is over for the server, and for us it is not: our
      // NEWKEYS waits for the approval, so nothing may be said before it.
      client.rekey();
      expect(wire.rawOutput().length, sentSoFar, reason: 'a proposal here would go out in the clear');
      approve.complete(true);
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      expect(ready, 1);
      expect(wire.clientOutput().packets.last, [SSH_Message_NewKeys.messageId],
          reason: 'our NEWKEYS, and nothing else, went out in the clear');
      // Once it is over on both sides, new keys can be asked for, and the
      // proposal goes out under the keys in force.
      wire.clearOutput();
      client.rekey();
      final proposal = _Keys(answer, sessionId: answer.hash).open(wire.rawOutput());
      expect(proposal.single[0], SSH_Message_KexInit.messageId);
    });

    test('a key the person refuses ends the connection, and nothing more is sent', () async {
      final answerLater = Completer<bool>();
      verdict = (key) => answerLater.future;
      final exchange = await start();
      wire.feed(_plain(exchange.answer(attacker).payload));
      await _settle();
      wire.clearOutput();
      answerLater.complete(false);
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHostkeyError>());
      expect(ready, 0);
      expect(wire.rawOutput(), isEmpty, reason: 'no NEWKEYS for a key that was refused');
    });

    test('a lookup that fails ends the connection, whatever it failed with', () async {
      final ours = SSHHostkeyError('the list of known hosts is closed');
      for (final failure in <Object>[ours, StateError('database is locked')]) {
        verdict = (key) => Future<bool>.error(failure);
        final exchange = await start();
        wire.feed(_plain(exchange.answer(trusted).payload));
        await _settle();
        expect(closed, isTrue, reason: '$failure');
        if (identical(failure, ours)) {
          expect(closedWith, same(ours), reason: 'an error of this library is passed on as it is');
        } else {
          // An error of any other kind was a type error thrown into nowhere,
          // with the connection left open.
          expect(closedWith, isA<SSHHostkeyError>());
          expect('$closedWith', contains('database is locked'), reason: 'what it failed with is kept');
        }
        expect(ready, 0);
        client.close();
      }
    });

    test('the connection ending while the person is asked: the answer that comes later does nothing', () async {
      final answerLater = Completer<bool>();
      verdict = (key) => answerLater.future;
      final exchange = await start();
      wire.feed(_plain(exchange.answer(trusted).payload));
      await _settle();
      // The server gives up waiting (its login grace time) and hangs up.
      await wire.close();
      await _settle();
      expect(closed, isTrue);
      wire.clearOutput();
      answerLater.complete(true);
      // An error thrown into nowhere would fail this test here.
      await _settle();
      expect(ready, 0);
      expect(wire.rawOutput(), isEmpty);
    });
  });

  group('a group exchange', () {
    test('the group, then the answer: the keys in force are that answer\'s', () async {
      verdict = (key) => true;
      final exchange = await start(group: true);
      final group = exchange.group();
      wire.feed(_plain(group.payload));
      await _settle();
      expect(closed, isFalse);
      final answer = group.answer(trusted, wire);
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(asked, [trusted.blob]);
      expect(ready, 1);
      final marker = Uint8List.fromList([2, 0, 0, 0, 1, 3]);
      wire.clearOutput();
      client.sendPacket(marker);
      expect(_Keys(answer, sessionId: answer.hash).open(wire.rawOutput()), [marker]);
    });

    test('the lengths the client asked for are the ones its exchange hash is made of: an answer signed over '
        'those is taken', () async {
      verdict = (key) => true;
      final exchange = await start(group: true);
      final group = exchange.group();
      final asked = group.asked(wire);
      expect((asked.minN, asked.preferredN, asked.maxN), (2048, 3072, 8192));
      wire.feed(_plain(group.payload));
      await _settle();
      // Signed over the hash of RFC 4419 as this test makes it, from what the client put on the wire: not
      // with the library's own function, which has those lengths from where the request has them.
      final answer = group.answer(trusted, wire, lengths: (asked.minN, asked.preferredN, asked.maxN));
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isFalse, reason: 'the client made its hash of other lengths than it asked for: $closedWith');
      expect(ready, 1);
      // And made the same way by both: the keys that follow from it open what the client sends.
      final marker = Uint8List.fromList([2, 0, 0, 0, 1, 3]);
      wire.clearOutput();
      client.sendPacket(marker);
      expect(_Keys(answer, sessionId: answer.hash).open(wire.rawOutput()), [marker]);
    });

    test('an answer signed over other lengths than the client asked for is no answer of this exchange', () async {
      for (final lengths in [(2048, 2048, 8192), (2048, 3072, 4096), (1024, 3072, 8192)]) {
        verdict = (key) => true;
        final exchange = await start(group: true);
        final group = exchange.group();
        wire.feed(_plain(group.payload));
        await _settle();
        final answer = group.answer(trusted, wire, lengths: lengths);
        wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
        await _settle();
        expect(closed, isTrue, reason: '$lengths');
        expect(closedWith, isA<SSHHostkeyError>(), reason: '$lengths');
        expect(ready, 0, reason: '$lengths');
      }
    });

    test('for an old server (groups of 1024 bits taken): the client asks for 1024 at the least, and its exchange '
        'hash is made of that; an answer signed over 2048 is no answer of this exchange', () async {
      verdict = (key) => true;
      final exchange = await start(group: true, minDhGroupBits: 1024);
      final group = exchange.group();
      final asked = group.asked(wire);
      expect((asked.minN, asked.preferredN, asked.maxN), (1024, 3072, 8192));
      wire.feed(_plain(group.payload));
      await _settle();
      final answer = group.answer(trusted, wire, lengths: (1024, 3072, 8192));
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isFalse, reason: 'the client made its hash of other lengths than it asked for: $closedWith');
      expect(ready, 1);

      final other = await start(group: true, minDhGroupBits: 1024);
      final otherGroup = other.group();
      wire.feed(_plain(otherGroup.payload));
      await _settle();
      final signedOver2048 = otherGroup.answer(trusted, wire, lengths: (2048, 3072, 8192));
      wire.feed([..._plain(signedOver2048.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHostkeyError>());
      expect(ready, 0);
    });

    test('a second group ends the connection', () async {
      verdict = (key) => true;
      final exchange = await start(group: true);
      wire.feed(_plain(exchange.group().payload));
      await _settle();
      wire.feed(_plain(exchange.group().payload));
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
    });

    test('the answer before the group ends the connection', () async {
      verdict = (key) => true;
      final exchange = await start(group: true);
      final writer = SSHMessageWriter()
        ..writeUint8(SSH_Message_KexDH_GexReply.messageId)
        ..writeString(trusted.blob)
        ..writeMpint(BigInt.from(5))
        ..writeString(Uint8List(8));
      wire.feed(_plain(writer.takeBytes()));
      await _settle();
      expect(exchange.clientKexInit, isNotEmpty);
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
      expect(asked, isEmpty);
    });

    test('two answers to a group exchange are one too many', () async {
      verdict = asTheAppDoes;
      final exchange = await start(group: true);
      final group = exchange.group();
      wire.feed(_plain(group.payload));
      await _settle();
      final theirs = group.answer(attacker, wire);
      final real = group.answer(trusted, wire);
      wire.feed([..._plain(theirs.payload), ..._plain(real.payload), ..._plain(theirs.payload)]);
      await _settle(const Duration(milliseconds: 60));
      expect(closed, isTrue);
      expect(ready, 0);
      expect(asked, [attacker.blob]);
    });
  });

  group('an answer under another exchange\'s number', () {
    test('a plain exchange is not answered under the group exchange\'s number', () async {
      verdict = (key) => true;
      final exchange = await start();
      final answer = exchange.answer(trusted);
      final renumbered = Uint8List.fromList(answer.payload)..[0] = SSH_Message_KexDH_GexReply.messageId;
      wire.feed(_plain(renumbered));
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
      expect(asked, isEmpty, reason: 'its key is not looked at');
    });
  });

  group('a later exchange on the same connection', () {
    /// The server asks for new keys; the client's side of the exchange comes
    /// back under the keys in force.
    Future<_Exchange> serverAsks(_Keys keys) async {
      final proposal = _proposal(strict: false);
      wire.feed(keys.seal(proposal));
      await _settle();
      final sent = keys.open(wire.rawOutput());
      wire.clearOutput();
      return _Exchange(
        clientVersion: keys.answer.exchange.clientVersion,
        clientKexInit: sent.firstWhere((p) => p[0] == SSH_Message_KexInit.messageId),
        serverKexInit: proposal,
        clientPublic: SSH_Message_KexECDH_Init.decode(
                sent.firstWhere((p) => p[0] == SSH_Message_KexECDH_Init.messageId))
            .ecdhPublicKey,
      );
    }

    test('with the same host key: nobody is asked again, and the session carries on under the new keys',
        () async {
      final keys = await established();
      final again = await serverAsks(keys);
      final answer = again.answer(trusted);
      wire.feed([...keys.seal(answer.payload), ...keys.seal(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      expect(asked, hasLength(1), reason: 'the key is the one already approved');
      expect(ready, 1);
      // Our NEWKEYS went out under the old keys.
      expect(keys.open(wire.rawOutput()), [
        [SSH_Message_NewKeys.messageId]
      ]);
      wire.clearOutput();

      final marker = Uint8List.fromList([2, 0, 0, 0, 3, 1, 2, 3]);
      client.sendPacket(marker);
      final raw = wire.rawOutput();
      // The session's id stays the first exchange's.
      expect(_Keys(answer, sessionId: keys.sessionId).open(raw), [marker]);
      expect(() => keys.open(raw), throwsA(anything), reason: 'the old keys read nothing any more');
    });

    test('with another host key the connection ends', () async {
      final keys = await established();
      final again = await serverAsks(keys);
      wire.feed([...keys.seal(again.answer(attacker).payload), ...keys.seal(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHostkeyError>());
      expect('$closedWith', contains('changed'));
      expect(asked, hasLength(1), reason: 'the other key is not put to the person as if it were new');
    });

    test('a second proposal during it ends the connection', () async {
      final keys = await established();
      await serverAsks(keys);
      wire.feed(keys.seal(_proposal(strict: false)));
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
    });

    test('two answers to it are one too many', () async {
      final keys = await established();
      final again = await serverAsks(keys);
      final answer = again.answer(trusted);
      wire.feed([...keys.seal(answer.payload), ...keys.seal(answer.payload)]);
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
    });

    test('an answer when no exchange is in progress ends the connection', () async {
      final keys = await established();
      final stray = keys.answer.exchange.answer(trusted);
      wire.feed(keys.seal(stray.payload));
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
    });

    test('NEWKEYS when no exchange is in progress ends the connection', () async {
      final keys = await established();
      wire.feed(keys.seal(SSH_Message_NewKeys().encode()));
      await _settle();
      expect(closed, isTrue);
      expect(closedWith, isA<SSHHandshakeError>());
    });

    test('the harness itself: what the server seals the client reads, in order', () async {
      // Without this the tests above could pass for the wrong reason (a
      // client that drops everything sealed would also "end the connection").
      final keys = await established();
      wire.feed([...keys.seal(Uint8List.fromList([2, 0, 0, 0, 1, 1])), ...keys.seal(Uint8List.fromList([4, 0, 0, 0, 0, 0, 0, 0, 0, 0]))]);
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      expect(handedUp.map((p) => p[0]), [2, 4]);
    });
  });

  // A server may say that it ends the connection at any time, before any
  // keys as well, and why, in words that are shown to the person. They are
  // the server's own only where they came under keys whose host key was
  // approved: until then anybody on the way can have written them, and the
  // error says which it is (SSHDisconnectError.authentic).
  // Until the server's NEWKEYS, what arrives comes in the clear: anybody on
  // the way can have written it, and the approval of the host key changes
  // nothing about that. Where no strict key exchange was agreed, the
  // transport handed such a message up once the key was approved, so whoever
  // sits between could answer the client's request for a service and its
  // sign-in in the clear, and play it a session it took for the server's
  // (what the client sent went under the new keys: that could not be read).
  group('in the clear after the host key was approved, before the server\'s NEWKEYS', () {
    for (final strict in [true, false]) {
      test(
          'a service\'s acceptance and a sign-in\'s success are not taken'
          '${strict ? '' : ', nor where no strict key exchange was agreed'}', () async {
        verdict = (key) => true;
        final exchange = await start(strict: strict);
        wire.feed(_plain(exchange.answer(trusted).payload));
        await _settle();
        expect(asked, hasLength(1));
        expect(closed, isFalse, reason: '$closedWith');
        wire.feed([
          ..._plain(SSH_Message_Service_Accept('ssh-userauth').encode()),
          ..._plain(SSH_Message_Userauth_Success().encode()),
        ]);
        await _settle();
        expect(handedUp, isEmpty, reason: 'nothing written in the clear reaches the client');
        expect(closed, isTrue);
        expect(closedWith, isA<SSHError>());
      });
    }

    test('a message of any time still is: the server\'s DEBUG ends nothing', () async {
      verdict = (key) => true;
      final exchange = await start(strict: false);
      wire.feed(_plain(exchange.answer(trusted).payload));
      await _settle();
      // SSH_MSG_DEBUG: always_display false, a message, a language tag.
      wire.feed(_plain(Uint8List.fromList([4, 0, 0, 0, 0, 2, 104, 105, 0, 0, 0, 0])));
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      expect(handedUp, hasLength(1));
    });

    test('nor under keys whose host key is still being looked at', () async {
      final approve = Completer<bool>();
      verdict = (key) => approve.future;
      final exchange = await start();
      final answer = exchange.answer(trusted);
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      wire.feed(_Keys(answer, sessionId: answer.hash).seal(SSH_Message_Service_Accept('ssh-userauth').encode()));
      await _settle();
      expect(handedUp, isEmpty);
      expect(closedWith, isA<SSHStateError>());
      expect('$closedWith', contains('message id 6 before host-key verification'));
      approve.complete(true);
      await _settle();
      expect(ready, 0);
    });

    test('under the keys of the approved host key, after the server\'s NEWKEYS, they are', () async {
      final keys = await established();
      wire.feed(keys.seal(SSH_Message_Service_Accept('ssh-userauth').encode()));
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      expect(handedUp.map((m) => m.first), [SSH_Message_Service_Accept.messageId]);
    });
  });

  group('a message that ends the connection, and whose words it carries', () {
    Uint8List ending(String words) => SSH_Message_Disconnect(reasonCode: 11, description: words).encode();

    Matcher endedSaying(String words, {required bool itsOwn}) => isA<SSHDisconnectError>()
        .having((e) => e.reasonCode, 'reason code', 11)
        .having((e) => e.description, 'the words', words)
        .having((e) => e.authentic, 'the server\'s own', itsOwn);

    test('in the clear, before any answer: anybody\'s', () async {
      verdict = (key) => true;
      await start();
      wire.feed(_plain(ending('Go away')));
      await _settle();
      expect(closedWith, endedSaying('Go away', itsOwn: false));
      expect(asked, isEmpty);
    });

    test('the same where no strict exchange was agreed', () async {
      verdict = (key) => true;
      await start(strict: false);
      wire.feed(_plain(ending('Go away')));
      await _settle();
      expect(closedWith, endedSaying('Go away', itsOwn: false));
    });

    test('under the keys of a host key that is still being looked at: not the server\'s own yet, and the '
        'approval that comes later does nothing', () async {
      final approve = Completer<bool>();
      verdict = (key) => approve.future;
      final exchange = await start();
      final answer = exchange.answer(trusted);
      // The server's NEWKEYS comes right behind its answer: what it sends from here is under keys.
      wire.feed([..._plain(answer.payload), ..._plain(SSH_Message_NewKeys().encode())]);
      await _settle();
      expect(closed, isFalse, reason: '$closedWith');
      wire.feed(_Keys(answer, sessionId: answer.hash).seal(ending('Too slow')));
      await _settle();
      expect(closedWith, endedSaying('Too slow', itsOwn: false));
      approve.complete(true);
      await _settle();
      expect(ready, 0);
    });

    test('in the clear after the key was approved, the server\'s NEWKEYS not come yet: anybody\'s',
        () async {
      verdict = (key) => true;
      final exchange = await start();
      wire.feed(_plain(exchange.answer(trusted).payload));
      await _settle();
      expect(ready, 1);
      expect(closed, isFalse, reason: '$closedWith');
      wire.feed(_plain(ending('Go away')));
      await _settle();
      expect(closedWith, endedSaying('Go away', itsOwn: false));
    });

    test('under keys whose host key was approved: the server\'s own', () async {
      final keys = await established();
      wire.feed(keys.seal(ending('Idle for too long')));
      await _settle();
      expect(closedWith, endedSaying('Idle for too long', itsOwn: true));
      expect(handedUp, isEmpty, reason: 'taken here, not handed on');
    });
  });
}

const _serverVersion = 'SSH-2.0-OpenSSH_9.6';

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Future<void> _settle([Duration time = const Duration(milliseconds: 20)]) => Future<void>.delayed(time);

/// [payload] as a packet before any keys are in force.
Uint8List _plain(Uint8List payload) => SSHPacket.pack(payload, align: 8);

/// A server's proposal: curve25519 (or a group exchange) with an Ed25519
/// host key, aes256-ctr and hmac-sha2-256.
Uint8List _proposal({bool strict = true, bool group = false}) => SSH_Message_KexInit(
      kexAlgorithms: [
        group ? 'diffie-hellman-group-exchange-sha256' : 'curve25519-sha256@libssh.org',
        if (strict) 'kex-strict-s-v00@openssh.com',
      ],
      serverHostKeyAlgorithms: const ['ssh-ed25519'],
      encryptionClientToServer: const ['aes256-ctr'],
      encryptionServerToClient: const ['aes256-ctr'],
      macClientToServer: const ['hmac-sha2-256'],
      macServerToClient: const ['hmac-sha2-256'],
      compressionClientToServer: const ['none'],
      compressionServerToClient: const ['none'],
      firstKexPacketFollows: false,
    ).encode();

/// An Ed25519 host key and what it signs with.
class _HostKey {
  _HostKey(this._pair);

  factory _HostKey.generate() {
    final signing = ed25519.SigningKey.generate();
    return _HostKey(OpenSSHEd25519KeyPair(
      Uint8List.fromList(signing.verifyKey.asTypedList),
      Uint8List.fromList(signing.asTypedList),
      'test',
    ));
  }

  final OpenSSHEd25519KeyPair _pair;

  /// The key as a server sends it.
  Uint8List get blob => _pair.toPublicKey().encode();

  Uint8List sign(Uint8List data) => _pair.sign(data).encode();
}

/// What both sides have said before the answer, so that an answer can be
/// made for the client's own start of the exchange.
class _Exchange {
  _Exchange({
    required this.clientVersion,
    required this.clientKexInit,
    required this.serverKexInit,
    required this.clientPublic,
  });

  final String clientVersion;
  final Uint8List clientKexInit;
  final Uint8List serverKexInit;
  final Uint8List clientPublic;

  /// The answer made last, for a test that needs its keys afterwards.
  late _Answer lastAnswer;

  /// An answer signed by [hostKey], with a secret of its own.
  _Answer answer(_HostKey hostKey) {
    final mine = SSHKexX25519();
    final secret = SSHKexUtils.encodeSharedSecretMpint(mine.computeSecret(clientPublic));
    final hash = SSHKexUtils.computeExchangeHash(
      digest: SHA256Digest(),
      clientVersion: clientVersion,
      serverVersion: _serverVersion,
      clientKexInit: clientKexInit,
      serverKexInit: serverKexInit,
      hostKey: hostKey.blob,
      clientPublicKey: clientPublic,
      serverPublicKey: mine.publicKey,
      sharedSecret: secret,
    );
    final writer = SSHMessageWriter()
      ..writeUint8(SSH_Message_KexECDH_Reply.messageId)
      ..writeString(hostKey.blob)
      ..writeString(mine.publicKey)
      ..writeString(hostKey.sign(hash));
    return lastAnswer = _Answer(this, writer.takeBytes(), secret, hash);
  }

  /// The group a server names in a group exchange.
  _Group group() => _Group(this);
}

/// The group of a group exchange (RFC 3526's 2048-bit one), and the answers
/// that can follow it.
class _Group {
  _Group(this.exchange);

  final _Exchange exchange;
  final _dh = SSHKexDH.group14();

  Uint8List get payload => SSH_Message_KexDH_GexGroup(p: _dh.p, g: _dh.g).encode();

  /// What the client asked for: its request, as it stands on [wire].
  SSH_Message_KexDH_GexRequest asked(_Wire wire) => SSH_Message_KexDH_GexRequest.decode(
      wire.clientOutput().packets.lastWhere((p) => p[0] == SSH_Message_KexDH_GexRequest.messageId));

  /// The exchange hash of a group exchange (RFC 4419, 3), made here field
  /// by field, with [lengths] for the shortest group the client takes,
  /// the one it would like and the longest.
  Uint8List _hashByTheBook(_HostKey hostKey, BigInt e, BigInt f, Uint8List secret, (int, int, int) lengths) {
    final writer = SSHMessageWriter()
      ..writeUtf8(exchange.clientVersion)
      ..writeUtf8(_serverVersion)
      ..writeString(exchange.clientKexInit)
      ..writeString(exchange.serverKexInit)
      ..writeString(hostKey.blob)
      ..writeUint32(lengths.$1)
      ..writeUint32(lengths.$2)
      ..writeUint32(lengths.$3)
      ..writeMpint(_dh.p)
      ..writeMpint(_dh.g)
      ..writeMpint(e)
      ..writeMpint(f)
      ..writeBytes(secret);
    final all = writer.takeBytes();
    final digest = SHA256Digest()..update(all, 0, all.length);
    final hash = Uint8List(digest.digestSize);
    digest.doFinal(hash, 0);
    return hash;
  }

  /// An answer signed by [hostKey] to the public value the client sent
  /// after it was given the group (read from [wire]). With [lengths] the
  /// hash it is signed over is made by this test with those lengths
  /// ([_hashByTheBook]), and not by the library.
  _Answer answer(_HostKey hostKey, _Wire wire, {(int, int, int)? lengths}) {
    final init = wire.clientOutput().packets.lastWhere((p) => p[0] == SSH_Message_KexDH_GexInit.messageId);
    final e = SSH_Message_KexDH_GexInit.decode(init).e;
    final mine = SSHKexDH(p: _dh.p, g: _dh.g, secretBits: 256);
    final secret = SSHKexUtils.encodeSharedSecretMpint(mine.computeSecret(e));
    if (lengths != null) {
      final byTheBook = _hashByTheBook(hostKey, e, mine.e, secret, lengths);
      final payload = SSH_Message_KexDH_GexReply(
        hostPublicKey: hostKey.blob,
        f: mine.e,
        signature: hostKey.sign(byTheBook),
      ).encode();
      return exchange.lastAnswer = _Answer(exchange, payload, secret, byTheBook);
    }
    final hash = SSHKexUtils.computeExchangeHash(
      digest: SHA256Digest(),
      groupExchange: mine,
      clientVersion: exchange.clientVersion,
      serverVersion: _serverVersion,
      clientKexInit: exchange.clientKexInit,
      serverKexInit: exchange.serverKexInit,
      hostKey: hostKey.blob,
      clientPublicKey: encodeBigInt(e),
      serverPublicKey: encodeBigInt(mine.e),
      sharedSecret: secret,
    );
    final payload = SSH_Message_KexDH_GexReply(
      hostPublicKey: hostKey.blob,
      f: mine.e,
      signature: hostKey.sign(hash),
    ).encode();
    return exchange.lastAnswer = _Answer(exchange, payload, secret, hash);
  }
}

/// One answer to an exchange: what is sent, and the secret and the hash the
/// keys follow from.
class _Answer {
  _Answer(this.exchange, this.payload, this.secret, this.hash);

  final _Exchange exchange;
  final Uint8List payload;
  final Uint8List secret;
  final Uint8List hash;
}

/// The keys that follow from an answer, for whoever made it, and the
/// encrypted protocol under them: aes256-ctr with hmac-sha2-256, strict key
/// exchange (packet numbers start again at every NEWKEYS).
class _Keys {
  _Keys(this.answer, {required this.sessionId});

  final _Answer answer;

  /// The first exchange's hash, which a connection keeps for all its keys.
  final Uint8List sessionId;

  Uint8List _key(SSHDeriveKeyType type, int size) => SSHKexUtils.deriveKey(
        digest: SHA256Digest(),
        sharedSecret: answer.secret,
        exchangeHash: answer.hash,
        keyType: type,
        sessionId: sessionId,
        keySize: size,
      );

  late final BlockCipher _toClient = SSHCipherType.aes256ctr.createCipher(
      _key(SSHDeriveKeyType.serverKey, 32), _key(SSHDeriveKeyType.serverIV, 16),
      forEncryption: true);
  late final BlockCipher _fromClient = SSHCipherType.aes256ctr.createCipher(
      _key(SSHDeriveKeyType.clientKey, 32), _key(SSHDeriveKeyType.clientIV, 16),
      forEncryption: false);
  late final Uint8List _macToClient = _key(SSHDeriveKeyType.serverMacKey, 32);
  late final Uint8List _macFromClient = _key(SSHDeriveKeyType.clientMacKey, 32);
  var _sent = 0;
  var _opened = 0;

  Uint8List _tag(Uint8List macKey, int number, Uint8List clear) {
    final count = ByteData(4)..setUint32(0, number);
    final mac = SSHMacType.hmacSha256.createMac(macKey)
      ..update(count.buffer.asUint8List(), 0, 4)
      ..update(clear, 0, clear.length);
    final tag = Uint8List(32);
    mac.doFinal(tag, 0);
    return tag;
  }

  /// [payload] as the server sends it under these keys.
  Uint8List seal(Uint8List payload) {
    final clear = SSHPacket.pack(payload, align: 16);
    final tag = _tag(_macToClient, _sent++, clear);
    final sealed = Uint8List(clear.length);
    for (var i = 0; i < clear.length; i += 16) {
      _toClient.processBlock(clear, i, sealed, i);
    }
    return Uint8List.fromList([...sealed, ...tag]);
  }

  /// The payloads of what the client sent under these keys, in order.
  /// Throws when [raw] is not that: when it does not read as packets, or
  /// when a packet's check value is not the one these keys give it.
  List<Uint8List> open(Uint8List raw) {
    final out = <Uint8List>[];
    var at = 0;
    while (at < raw.length) {
      if (raw.length - at < 16 + 32) throw const FormatException('not a packet under these keys');
      final first = Uint8List(16);
      _fromClient.processBlock(raw, at, first, 0);
      final length = ByteData.sublistView(first).getUint32(0);
      final body = 4 + length;
      if (length < 12 || length > 35000 || body % 16 != 0 || at + body + 32 > raw.length) {
        throw const FormatException('not a packet under these keys');
      }
      final clear = Uint8List(body)..setRange(0, 16, first);
      for (var i = 16; i < body; i += 16) {
        _fromClient.processBlock(raw, at + i, clear, i);
      }
      final padding = clear[4];
      if (padding < 4 || padding > length - 1) throw const FormatException('not a packet under these keys');
      if (!_same(_tag(_macFromClient, _opened++, clear), Uint8List.sublistView(raw, at + body, at + body + 32))) {
        throw const FormatException('a packet whose check value these keys do not give it');
      }
      out.add(Uint8List.sublistView(clear, 5, body - padding));
      at += body + 32;
    }
    return out;
  }
}

/// The connection as the test holds it: what the client wrote, and a way to
/// hand it bytes.
class _Wire implements SSHSocket {
  final _incoming = StreamController<Uint8List>();
  final _done = Completer<void>();
  final _written = BytesBuilder(copy: true);

  /// Bytes from the other side. Once the client has ended the connection
  /// they go nowhere, as they would.
  void feed(List<int> bytes) {
    if (!_incoming.isClosed) _incoming.add(Uint8List.fromList(bytes));
  }

  Uint8List rawOutput() => _written.toBytes();

  void clearOutput() => _written.clear();

  /// The client's version line and the packets it sent in the clear.
  ({String version, List<Uint8List> packets}) clientOutput() {
    final bytes = _written.toBytes();
    final end = latin1.decode(bytes).indexOf('\r\n');
    final version = latin1.decode(bytes.sublist(0, end));
    final packets = <Uint8List>[];
    var at = end + 2;
    while (at + 5 <= bytes.length) {
      final length = ByteData.sublistView(bytes, at).getUint32(0);
      final padding = bytes[at + 4];
      packets.add(Uint8List.sublistView(bytes, at + 5, at + 4 + length - padding));
      at += 4 + length;
    }
    return (version: version, packets: packets);
  }

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _Sink(_written);

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> flush() async {}

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _incoming.close();
  }

  @override
  void destroy() {
    if (!_done.isCompleted) _done.complete();
    unawaited(_incoming.close());
  }
}

class _Sink implements StreamSink<List<int>> {
  _Sink(this._into);

  final BytesBuilder _into;

  @override
  void add(List<int> data) => _into.add(data);

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      _into.add(chunk);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done => Future.value();
}
