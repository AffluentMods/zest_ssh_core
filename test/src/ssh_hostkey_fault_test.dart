import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ecdsa.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';

import 'played_server.dart';

/// What the library found wrong with a host key that it refused by itself
/// is told with the error ([SSHHostkeyError.fault]), and so is when: at the
/// start of a connection, or when new keys were taken on one that was open
/// ([SSHHostkeyError.duringRekey]).
///
/// A host key is refused for three things that are nothing alike to
/// whoever uses the program: the key did not sign the exchange it came
/// with, which is what somebody who answers in a host's place cannot do;
/// what came is no key a server has; or the server showed another key when
/// new keys were taken than the connection began with. Each was an
/// [SSHHostkeyError] with words of its own and nothing else, so an
/// application could say them apart only by reading the words. And a host
/// key that whoever verifies host keys did not accept is an error of the
/// same type: it has no fault, since the library found none.
///
/// When it was refused is as much to its person: a connection that is
/// refused at its start was sent nothing, and one that was open had gone on
/// under a key that was accepted, with whatever was sent over it.
///
/// With a server played by the test.
void main() {
  const offered = SSHAlgorithms(
    kex: [SSHKexType.x25519],
    hostkey: [
      SSHHostkeyType.ed25519,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256,
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256,
    ],
    cipher: [SSHCipherType.aes256ctr],
    mac: [SSHMacType.hmacSha256],
  );

  SSHKeyPair fromFile(String path) => SSHKeyPair.fromPem(File('test/fixtures/$path').readAsStringSync()).single;

  final ed25519 = fromFile('ssh-ed25519/ssh_host_ed25519_key');
  final rsa = fromFile('ssh-rsa/ssh_host_rsa_key');
  final ecdsa = {
    for (final curve in ['nistp256', 'nistp384', 'nistp521'])
      'ecdsa-sha2-$curve': fromFile('ecdsa-sha2-$curve/ssh_host_ecdsa_key'),
  };

  /// The key of [pair] under the name [agreed], with the key's signature of
  /// something else than the exchange: what whoever has only the public
  /// half of a host's key can show.
  PlayedHostKey cannotSign(SSHKeyPair pair, String agreed) => PlayedHostKey(
        agreed,
        pair.toPublicKey().encode(),
        (hash) => pair.sign(Uint8List.fromList(hash.reversed.toList())).encode(),
      );

  /// An odd number of exactly [bits] bits.
  BigInt odd(int bits) => (BigInt.one << (bits - 1)) | (BigInt.one << (bits ~/ 2)) | BigInt.one;

  /// The numbers [n] and [e] under the name of an RSA key, with a signature
  /// that signs nothing.
  PlayedHostKey madeUpRsa(BigInt n, BigInt e) => PlayedHostKey(
        'rsa-sha2-256',
        SSHRsaPublicKey(e, n).encode(),
        (hash) => SSHRsaSignature(SSHRsaSignatureType.sha256, Uint8List(256)..fillRange(1, 256, 0x5A)).encode(),
      );

  /// A transport on a played server that shows [first] at the start of the
  /// connection and, where [newKeys] is given, asks for new keys once the
  /// connection is ready and shows what [newKeys] makes then (null: the key
  /// it showed before). How the connection ended, how often whoever
  /// verifies host keys was asked (who answers with [verify]: yes where
  /// none is given), and how often it was ready.
  Future<({Object? endedWith, int asked, int ready, bool newKeysTaken})> shown(
    PlayedHostKey first, {
    PlayedHostKey? Function()? newKeys,
    FutureOr<bool> Function()? verify,
  }) async {
    final server = PlayedServer(hostKey: first);
    var asked = 0;
    var ready = 0;
    final transport = SSHTransport(
      server.socket,
      algorithms: offered,
      onVerifyHostKey: (type, key) {
        asked++;
        return verify == null ? true : verify();
      },
      onReady: () => ready++,
    );
    addTearDown(transport.close);
    Object? endedWith;
    final ended = transport.done.then((_) {}, onError: (Object e) {
      endedWith = e;
    });

    /// Whether [exchange] came to its end; where the client ended the
    /// connection over it, that is waited for.
    Future<bool> played(Future<void> exchange) async {
      final over = exchange.then((_) => true, onError: (Object _) => false);
      if (await Future.any([over, ended.then((_) => false)])) {
        await server.settle();
        return true;
      }
      await ended.timeout(PlayedServer.patience);
      return false;
    }

    var newKeysTaken = false;
    if (await played(server.exchangeKeys()) && newKeys != null) {
      newKeysTaken = await played(server.rekey(hostKey: newKeys()));
    }
    return (endedWith: endedWith, asked: asked, ready: ready, newKeysTaken: newKeysTaken);
  }

  /// Refused at the start of a connection, or with [duringRekey] when new
  /// keys were taken on one that was open.
  Matcher refusedAs(SSHHostkeyFault? fault, {String? saying, bool duringRekey = false}) => isA<SSHHostkeyError>()
      .having((e) => e.fault, 'what was wrong with the key', fault)
      .having((e) => e.duringRekey, 'whether it was during a re-key', duringRekey)
      .having((e) => e.message, 'what it says', saying == null ? anything : contains(saying));

  group('a key that did not sign the exchange it came with: not signed', () {
    for (final (pair, agreed) in [
      (ed25519, 'ssh-ed25519'),
      (rsa, 'rsa-sha2-256'),
      for (final entry in ecdsa.entries) (entry.value, entry.key),
    ]) {
      test(agreed, () async {
        final outcome = await shown(cannotSign(pair, agreed));
        expect(outcome.endedWith, refusedAs(SSHHostkeyFault.notSigned, saying: 'Signature verification failed'));
        expect(outcome.asked, 0);
        expect(outcome.ready, 0);
      });
    }
  });

  group('what is no key a server has: no key', () {
    final cases = <(String, PlayedHostKey Function(), String)>[
      (
        'a key of another curve than the one agreed on',
        () => PlayedHostKey.of(ecdsa['ecdsa-sha2-nistp256']!, algorithm: 'ecdsa-sha2-nistp384'),
        'was agreed on',
      ),
      (
        'a key of another kind altogether',
        () => PlayedHostKey.of(rsa, algorithm: 'ssh-ed25519'),
        'was agreed on',
      ),
      (
        'an ECDSA signature under another curve\'s name than its key\'s',
        () {
          final pair = ecdsa['ecdsa-sha2-nistp256']!;
          return PlayedHostKey('ecdsa-sha2-nistp256', pair.toPublicKey().encode(), (hash) {
            final own = SSHEcdsaSignature.decode(pair.sign(hash).encode());
            return SSHEcdsaSignature('ecdsa-sha2-nistp384', own.r, own.s).encode();
          });
        },
        'its key is of the kind',
      ),
      (
        'an RSA signature under another of its names than the one agreed on',
        // (The key pair signs under rsa-sha2-256.)
        () => PlayedHostKey('rsa-sha2-512', rsa.toPublicKey().encode(), (hash) => rsa.sign(hash).encode()),
        'The signature of the host key is of the kind',
      ),
      (
        'an RSA key with a modulus that is an even number',
        () => madeUpRsa(odd(2048) + BigInt.one, BigInt.from(65537)),
        'a modulus that is none',
      ),
      (
        'an RSA key with a modulus longer than any key has',
        () => madeUpRsa(odd(16385), BigInt.from(65537)),
        'a modulus of 16385 bits',
      ),
      (
        'an RSA key with a public exponent longer than any key has',
        () => madeUpRsa(odd(2048), odd(65)),
        'a public exponent of 65 bits',
      ),
      (
        'an RSA key with a public exponent of one',
        () => madeUpRsa(odd(2048), BigInt.one),
        'a public exponent that is none',
      ),
      (
        'bytes that are no key',
        () => PlayedHostKey(
              'ssh-ed25519',
              Uint8List.fromList([0, 0, 0, 200, 1, 2, 3]),
              (hash) => ed25519.sign(hash).encode(),
            ),
        'could not be read',
      ),
    ];
    for (final (what, hostKey, words) in cases) {
      test(what, () async {
        final outcome = await shown(hostKey());
        expect(outcome.endedWith, refusedAs(SSHHostkeyFault.noKey, saying: words));
        expect(outcome.asked, 0);
        expect(outcome.ready, 0);
      });
    }
  });

  group('a key that whoever verifies host keys did not accept: no fault of the library\'s finding', () {
    test('they say no', () async {
      final outcome = await shown(PlayedHostKey.of(ed25519, algorithm: 'ssh-ed25519'), verify: () => false);
      expect(outcome.endedWith, refusedAs(null, saying: 'Hostkey verification failed'));
      expect(outcome.asked, 1);
      expect(outcome.ready, 0);
    });

    test('they could not say: what they failed with is no error of this library\'s', () async {
      final outcome = await shown(
        PlayedHostKey.of(ed25519, algorithm: 'ssh-ed25519'),
        verify: () async => throw StateError('the list of known hosts could not be read'),
      );
      expect(outcome.endedWith, refusedAs(null, saying: 'The host key could not be verified'));
      expect(outcome.asked, 1);
    });

    test('they refuse with an error of their own: the connection ends with that very error', () async {
      final theirs = SSHHostkeyError('not the key that was pinned for this host');
      final outcome = await shown(
        PlayedHostKey.of(ed25519, algorithm: 'ssh-ed25519'),
        verify: () async => throw theirs,
      );
      expect(outcome.endedWith, same(theirs));
      expect(theirs.fault, isNull);
    });
  });

  group('when new keys are taken on a connection that is open', () {
    final first = PlayedHostKey.of(ed25519, algorithm: 'ssh-ed25519');

    test('the key the connection began with, signed: the connection goes on, and nobody is asked again', () async {
      final outcome = await shown(first, newKeys: () => null);
      expect(outcome.endedWith, isNull);
      expect(outcome.newKeysTaken, isTrue);
      expect(outcome.asked, 1);
      expect(outcome.ready, 1);
    });

    test('another key of the same kind, which signs: changed', () async {
      final outcome = await shown(first, newKeys: PlayedHostKey.ed25519);
      expect(outcome.endedWith,
          refusedAs(SSHHostkeyFault.changed, saying: 'Host key changed during re-key', duringRekey: true));
      expect(outcome.newKeysTaken, isFalse);
      expect(outcome.asked, 1, reason: 'a key that is shown at new keys is put to nobody');
      expect(outcome.ready, 1);
    });

    test('a key of another kind, which the server has agreed on then and which signs: changed', () async {
      final outcome = await shown(first, newKeys: () => PlayedHostKey.of(rsa, algorithm: 'rsa-sha2-256'));
      expect(outcome.endedWith, refusedAs(SSHHostkeyFault.changed, duringRekey: true));
      expect(outcome.asked, 1);
    });

    test('the key the connection began with, and a signature that is not its own of this exchange: not signed',
        () async {
      final outcome = await shown(first, newKeys: () => cannotSign(ed25519, 'ssh-ed25519'));
      expect(outcome.endedWith,
          refusedAs(SSHHostkeyFault.notSigned, saying: 'Signature verification failed', duringRekey: true));
      expect(outcome.newKeysTaken, isFalse);
      expect(outcome.asked, 1);
    });

    test('another key that did not sign either: not signed, which is found first', () async {
      final other = fromFile('ecdsa-sha2-nistp256/ssh_host_ecdsa_key');
      final outcome = await shown(first, newKeys: () => cannotSign(other, 'ecdsa-sha2-nistp256'));
      expect(outcome.endedWith, refusedAs(SSHHostkeyFault.notSigned, duringRekey: true));
    });

    test('a key of another kind than the server has agreed on then: no key, with the words it has at the start',
        () async {
      final outcome = await shown(first, newKeys: () => PlayedHostKey.of(rsa, algorithm: 'ssh-ed25519'));
      expect(
        outcome.endedWith,
        refusedAs(
          SSHHostkeyFault.noKey,
          saying: 'The server showed a host key of the kind "ssh-rsa", and "ssh-ed25519" was agreed on',
          duringRekey: true,
        ),
      );
      expect(outcome.asked, 1);
    });

    test('something that is no key: no key', () async {
      final outcome = await shown(
        first,
        newKeys: () => PlayedHostKey(
          'ssh-ed25519',
          Uint8List.fromList([0, 0, 0, 200, 1, 2, 3]),
          (hash) => ed25519.sign(hash).encode(),
        ),
      );
      expect(outcome.endedWith, refusedAs(SSHHostkeyFault.noKey, saying: 'could not be read', duringRekey: true));
      expect(outcome.asked, 1);
    });
  });

  test('an error reads as it did, whatever its fault and whenever it was, and has neither unless it is given them',
      () {
    final plain = SSHHostkeyError('Hostkey verification failed');
    expect(plain.fault, isNull);
    expect(plain.duringRekey, isFalse);
    expect(plain.bits, isNull);
    expect(plain.shortestTaken, isNull);
    for (final fault in SSHHostkeyFault.values) {
      for (final duringRekey in [false, true]) {
        final error = SSHHostkeyError('Signature verification failed', fault: fault, duringRekey: duringRekey);
        expect(error.fault, fault);
        expect(error.duringRekey, duringRekey);
        expect(error.bits, isNull);
        expect(error.shortestTaken, isNull);
        expect('$error', 'SSHHostkeyError(Signature verification failed)');
      }
    }
    // A key that is too short says how long it is and what the shortest taken is, beside what it reads as.
    final short = SSHHostkeyError('too short', fault: SSHHostkeyFault.tooShort, bits: 768, shortestTaken: 1024);
    expect((short.bits, short.shortestTaken), (768, 1024));
    expect('$short', 'SSHHostkeyError(too short)');
    expect(SSHHostkeyFault.values, hasLength(4));
  });
}
