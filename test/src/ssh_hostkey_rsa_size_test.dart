// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';

import 'played_server.dart';

/// An RSA host key of a size no key has is refused before anything is
/// computed with it.
///
/// A server shows its host key with its answer to the key exchange, and the
/// client checks the signature that comes with it before it asks anybody
/// whether they trust the key. For an RSA key that check raises a number
/// to a power, and how long that takes is for the server to choose: with
/// the size of the key, and with its public exponent, which is 65537 in any
/// key that anybody makes and can be as long as the key in one that is made
/// up. The transport checked a key of any size with any exponent. That is
/// before the sign-in and before any question, so whoever stands between a
/// client and its server can send such a key in the server's place: more
/// than a second of a busy processor for a key of 16384 bits with an
/// exponent as long (measured on the machine this was written on), ten
/// seconds for 32768 bits, eighty for 65536, and a key in one packet can be
/// twice as long again: more than ten minutes. The program does nothing
/// else in that time.
///
/// A key is taken as far as OpenSSH takes one: 16384 bits, and an exponent
/// that is odd, at least 3 and no longer than 64 bits. Anything else ends
/// the connection, saying what was wrong with the key, before the check and
/// before anybody is asked.
///
/// And no shorter than 2048 bits where nothing is said (NIST's floor until
/// 2030; OpenSSH takes 1024): a key of 512 bits can be worked out in hours, and whoever has done so answers in
/// the server's place with the server's own key. Such a key was checked as
/// any other and put to whoever verifies host keys. It ends the connection
/// now, said as too short with both lengths, unless whoever connects has
/// said that a shorter one will do (`SSHAlgorithms.minRsaHostKeyBits`).
void main() {
  const offered = SSHAlgorithms(
    kex: [SSHKexType.x25519],
    hostkey: [SSHHostkeyType.rsaSha512, SSHHostkeyType.rsaSha256, SSHHostkeyType.ed25519],
    cipher: [SSHCipherType.aes256ctr],
    mac: [SSHMacType.hmacSha256],
  );

  /// An odd number of exactly [bits] bits, the same every time.
  BigInt odd(int bits) => (BigInt.one << (bits - 1)) | (BigInt.one << (bits ~/ 2)) | BigInt.one;

  /// Bytes for a signature that signs nothing. Not noughts: nought to any
  /// power is nought, and takes no time to work out.
  Uint8List signsNothing(int length) => Uint8List(length)..fillRange(length == 0 ? 0 : 1, length, 0x5A);

  /// A host key that is the numbers a test gives it, under the name of an
  /// RSA key, with a signature that signs nothing: as long as the key, or
  /// of [signatureLength] bytes where the two would not go into one packet.
  PlayedHostKey madeUp(BigInt n, BigInt e, {int? signatureLength}) => PlayedHostKey(
        'rsa-sha2-256',
        SSHRsaPublicKey(e, n).encode(),
        (hash) => SSHRsaSignature(
          SSHRsaSignatureType.sha256,
          signsNothing(signatureLength ?? (n.bitLength + 7) ~/ 8),
        ).encode(),
      );

  /// A transport that is shown [hostKey] by a played server: how its
  /// connection ended, whether anybody was asked about the key, whether it
  /// said the connection was ready, and what it sent after its proposal and
  /// its start of the exchange.
  Future<({Object? endedWith, int asked, int ready, List<int> sentAfter, Duration took})> shown(
      PlayedHostKey hostKey, {SSHAlgorithms algorithms = offered}) async {
    final server = PlayedServer(hostKey: hostKey);
    var asked = 0;
    var ready = 0;
    final transport = SSHTransport(
      server.socket,
      algorithms: algorithms,
      onVerifyHostKey: (type, key) {
        asked++;
        return true;
      },
      onReady: () => ready++,
    );
    addTearDown(transport.close);
    Object? endedWith;
    final ended = transport.done.then((_) {}, onError: (Object e) {
      endedWith = e;
    });
    final watch = Stopwatch()..start();
    // The played server waits for the client's NEWKEYS, which does not come
    // where the key is refused: the client's end of the connection is what
    // is waited for then.
    final exchanged = server.exchangeKeys().then((_) => true, onError: (Object _) => false);
    final accepted = await Future.any([exchanged, ended.then((_) => false)]);
    watch.stop();
    if (accepted) {
      await server.settle();
    } else {
      await ended.timeout(PlayedServer.patience);
    }
    return (
      endedWith: endedWith,
      asked: asked,
      ready: ready,
      sentAfter: [
        for (final payload in server.takeSent())
          if (payload[0] != SSH_Message_KexInit.messageId) payload[0],
      ],
      took: watch.elapsed,
    );
  }

  Matcher refusedFor(String what) => isA<SSHHostkeyError>().having((e) => e.message, 'what it says', contains(what));

  group('an RSA key that a server has', () {
    test('2048 bits, from a key file: taken, its person asked once, and the connection is ready', () async {
      final pair = SSHKeyPair.fromPem(await File('test/fixtures/ssh-rsa/ssh_host_rsa_key').readAsString()).single;
      final key = SSHRsaPublicKey.decode(pair.toPublicKey().encode());
      expect(key.n.bitLength, 2048);
      final outcome = await shown(PlayedHostKey.of(pair, algorithm: 'rsa-sha2-256'));
      expect(outcome.endedWith, isNull);
      expect(outcome.asked, 1);
      expect(outcome.ready, 1);
    });
  });

  group('a key of a size no key has is refused for that, and nobody is asked', () {
    for (final (bits, exponentBits, what) in [
      (16385, 17, 'a modulus one bit longer than any key has'),
      (32768, 17, 'a modulus twice as long'),
      (16384, 65, 'the longest modulus with an exponent one bit too long'),
      (16384, 16384, 'the longest modulus with an exponent as long'),
      (4096, 4096, 'a usual modulus with an exponent as long'),
    ]) {
      test('$what ($bits bits, an exponent of $exponentBits)', () async {
        final outcome = await shown(madeUp(odd(bits), odd(exponentBits)));
        expect(outcome.endedWith,
            refusedFor(bits > 16384 ? 'modulus of $bits bits' : 'exponent of $exponentBits bits'));
        expect(outcome.asked, 0, reason: 'a key that is refused is not put to anybody');
        expect(outcome.ready, 0);
        expect(outcome.sentAfter, isEmpty, reason: 'no NEWKEYS for a key that was refused');
      });
    }

    test('the longest key a packet holds, with an exponent as long', () async {
      // About 16 KB each: what a server can put into the one packet of its answer.
      final outcome = await shown(madeUp(odd(131072), odd(131072), signatureLength: 256));
      expect(outcome.endedWith, refusedFor('modulus of 131072 bits'));
      expect(outcome.asked, 0);
      expect(outcome.sentAfter, isEmpty);
    });

    test('nothing is computed with a key that is refused: 65536 bits with an exponent as long is refused at once',
        () async {
      // The check of this key's signature takes the machine this was written on eighty seconds.
      final outcome = await shown(madeUp(odd(65536), odd(65536), signatureLength: 256));
      expect(outcome.endedWith, refusedFor('modulus of 65536 bits'));
      expect(outcome.took, lessThan(const Duration(seconds: 10)));
    });
  });

  group('an exponent that is none', () {
    for (final (e, what) in [
      (BigInt.one, 'one, with which every signature is its own check'),
      (BigInt.zero, 'nought'),
      (BigInt.two, 'two'),
      (BigInt.from(65536), 'an even number'),
    ]) {
      test('$what: refused for that, and nobody is asked', () async {
        final outcome = await shown(madeUp(odd(2048), e));
        expect(outcome.endedWith, refusedFor('exponent'));
        expect(outcome.asked, 0);
        expect(outcome.ready, 0);
      });
    }
  });

  group('a modulus that is none', () {
    for (final (n, what) in [
      (BigInt.zero, 'nought'),
      (odd(2048) + BigInt.one, 'an even number'),
      (BigInt.two, 'two'),
    ]) {
      test('$what: refused for that, and nobody is asked', () async {
        final outcome = await shown(madeUp(n, BigInt.from(65537)));
        expect(outcome.endedWith, refusedFor('modulus'));
        expect(outcome.asked, 0);
        expect(outcome.ready, 0);
      });
    }
  });

  // Within what a key can be, the key is checked as it was: a made-up key
  // signs nothing, and the connection ends for its signature and not for
  // its size.
  group('a key of a size a key can have is checked', () {
    for (final (bits, e, what) in [
      (16384, BigInt.from(65537), 'the longest modulus, the usual exponent'),
      (2048, BigInt.from(3), 'the smallest exponent'),
      (2048, BigInt.from(35), 'an exponent of old keys'),
      (2048, (BigInt.one << 63) | BigInt.one, 'an exponent of 64 bits'),
      (2048, BigInt.from(65537), 'the shortest key that is taken'),
    ]) {
      test('$what ($bits bits): not refused for its size', () async {
        final outcome = await shown(madeUp(odd(bits), e));
        expect(outcome.endedWith, refusedFor('Signature verification failed'));
        expect(outcome.asked, 0);
        expect(outcome.ready, 0);
      });
    }
  });

  group('an RSA key shorter than is taken', () {
    /// What [offered] offers, with [bits] as the shortest RSA host key that is taken.
    SSHAlgorithms atLeast(int bits) => SSHAlgorithms(
          kex: offered.kex,
          hostkey: offered.hostkey,
          cipher: offered.cipher,
          mac: offered.mac,
          minRsaHostKeyBits: bits,
        );

    test('where nothing is said of a shortest, it is 2048 bits', () {
      expect(const SSHAlgorithms().minRsaHostKeyBits, 2048);
      expect(offered.minRsaHostKeyBits, 2048);
    });

    for (final bits in [2047, 1536, 1024, 768, 512, 17]) {
      test('$bits bits: refused for its length, with both lengths, before its signature is looked at, and nobody is '
          'asked', () async {
        final outcome = await shown(madeUp(odd(bits), BigInt.from(65537)));
        expect(
          outcome.endedWith,
          isA<SSHHostkeyError>()
              .having((e) => e.fault, 'what was wrong', SSHHostkeyFault.tooShort)
              .having((e) => e.bits, 'how long it is', bits)
              .having((e) => e.shortestTaken, 'the shortest taken', 2048)
              .having((e) => e.message, 'what it says',
                  'The RSA host key has a modulus of $bits bits, and none of less than 2048 is taken'),
        );
        expect(outcome.asked, 0, reason: 'a key that is refused is not put to anybody');
        expect(outcome.ready, 0);
        expect(outcome.sentAfter, isEmpty, reason: 'no NEWKEYS for a key that was refused');
      });
    }

    test('a key of 2048 bits is refused for nothing of its length, and what it ends with names no lengths', () async {
      final outcome = await shown(madeUp(odd(2048), BigInt.from(65537)));
      expect(
        outcome.endedWith,
        isA<SSHHostkeyError>()
            .having((e) => e.fault, 'what was wrong', isNot(SSHHostkeyFault.tooShort))
            .having((e) => e.bits, 'how long it is', isNull)
            .having((e) => e.shortestTaken, 'the shortest taken', isNull),
      );
    });

    test('a key of 768 bits that signs as a key does: refused where nothing is said, and taken, its person asked '
        'once, where whoever connects has said that any length will do', () async {
      final pair = SSHKeyPair.fromPem(await File('test/fixtures/ssh-rsa/short_rsa_768_key').readAsString()).single;
      expect(SSHRsaPublicKey.decode(pair.toPublicKey().encode()).n.bitLength, 768);

      final refused = await shown(PlayedHostKey.of(pair, algorithm: 'rsa-sha2-256'));
      expect(
        refused.endedWith,
        isA<SSHHostkeyError>()
            .having((e) => e.fault, 'what was wrong', SSHHostkeyFault.tooShort)
            .having((e) => e.bits, 'how long it is', 768),
      );
      expect(refused.asked, 0);
      expect(refused.ready, 0);

      final taken = await shown(PlayedHostKey.of(pair, algorithm: 'rsa-sha2-256'), algorithms: atLeast(0));
      expect(taken.endedWith, isNull);
      expect(taken.asked, 1);
      expect(taken.ready, 1);
    });

    test('the shortest taken is what the algorithms say, to the bit, and is of RSA keys only', () async {
      final pair = SSHKeyPair.fromPem(await File('test/fixtures/ssh-rsa/ssh_host_rsa_key').readAsString()).single;
      expect(SSHRsaPublicKey.decode(pair.toPublicKey().encode()).n.bitLength, 2048);

      final exact = await shown(PlayedHostKey.of(pair, algorithm: 'rsa-sha2-256'), algorithms: atLeast(2048));
      expect(exact.endedWith, isNull);
      expect(exact.asked, 1);

      final oneMore = await shown(PlayedHostKey.of(pair, algorithm: 'rsa-sha2-256'), algorithms: atLeast(2049));
      expect(
        oneMore.endedWith,
        isA<SSHHostkeyError>()
            .having((e) => e.fault, 'what was wrong', SSHHostkeyFault.tooShort)
            .having((e) => e.bits, 'how long it is', 2048)
            .having((e) => e.shortestTaken, 'the shortest taken', 2049),
      );
      expect(oneMore.asked, 0);

      // A key of another kind has no such length: it is taken as before.
      final ed25519 = await shown(PlayedHostKey.ed25519(), algorithms: atLeast(4096));
      expect(ed25519.endedWith, isNull);
      expect(ed25519.asked, 1);
    });
  });
}
