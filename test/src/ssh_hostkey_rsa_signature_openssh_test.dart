import 'dart:async';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' show Digest;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';

import 'played_openssh_client.dart';
import 'played_server.dart';

/// Which signatures of an RSA host key are taken: by this package's client,
/// and by the OpenSSH client of the machine, side by side.
///
/// The check of an RSA signature is the package's own
/// (hostkey/hostkey_rsa_verify_test.dart). It takes fewer signatures than
/// the library that checked before: none that is longer than the key, and
/// none that names its hash without the empty part that goes with the
/// name. Whether that is what a server may expect of a client is asked of
/// OpenSSH here: a played server shows each client an RSA host key, and
/// signs the exchange with it as the test says. Whatever OpenSSH takes this
/// client takes, and whatever OpenSSH refuses it refuses.
///
/// The key is made here, with a modulus just above a power of 256, so that
/// every signature it makes begins with a nought: a server may send such a
/// signature with the nought left out, and some do.
///
/// The OpenSSH client looks at no key and no file of whoever runs the
/// tests, and its own account of what it did is checked for that. Where a
/// machine has no OpenSSH client its half of these tests is skipped.
void main() {
  /// [base] to the power of [exponent], modulo [modulus].
  BigInt byHand(BigInt base, BigInt exponent, BigInt modulus) {
    var result = BigInt.one % modulus;
    var square = base % modulus;
    for (var left = exponent; left > BigInt.zero; left = left >> 1) {
      if (left.isOdd) result = (result * square) % modulus;
      square = (square * square) % modulus;
    }
    return result;
  }

  BigInt asNumber(List<int> bytes) => bytes.fold(BigInt.zero, (sum, byte) => (sum << 8) | BigInt.from(byte));

  Uint8List asBytes(BigInt number, int length) {
    final out = Uint8List(length);
    var left = number;
    for (var i = length - 1; i >= 0; i--) {
      out[i] = (left & BigInt.from(0xff)).toInt();
      left = left >> 8;
    }
    expect(left, BigInt.zero, reason: 'the number is longer than $length bytes');
    return out;
  }

  /// The first prime from [from] on (a number that passes for one with
  /// every base tried).
  BigInt primeFrom(BigInt from) {
    const small = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];
    var candidate = from | BigInt.one;
    while (true) {
      if (small.every((p) => candidate % BigInt.from(p) != BigInt.zero) &&
          [2, 3, 5, 7].every((base) => byHand(BigInt.from(base), candidate - BigInt.one, candidate) == BigInt.one)) {
        return candidate;
      }
      candidate += BigInt.two;
    }
  }

  // A key of 2041 bits whose modulus is just above 2^2040.
  final e = BigInt.from(65537);
  final p = primeFrom((BigInt.one << 1020) + BigInt.from(20261010));
  var q = primeFrom(p + BigInt.from(1000000));
  while (((p - BigInt.one) * (q - BigInt.one)).gcd(e) != BigInt.one) {
    q = primeFrom(q + BigInt.two);
  }
  final n = p * q;
  final d = e.modInverse((p - BigInt.one) * (q - BigInt.one));
  const length = 256;
  final blob = SSHRsaPublicKey(e, n).encode();

  const names = {
    'rsa-sha2-256': [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
    'rsa-sha2-512': [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
  };
  // The same names without the empty part that goes with them.
  const namesWithoutIt = {
    'rsa-sha2-256': [0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20],
    'rsa-sha2-512': [0x30, 0x4f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40],
  };

  Digest digestOf(String kind) => kind == 'rsa-sha2-256' ? SHA256Digest() : SHA512Digest();

  /// The key's signature of what comes back to a nought, a one, [padding]
  /// bytes of 0xff (as many as fill the length where none is given), a
  /// nought, [name], the hash of [signed] and [after].
  BigInt signature(String kind, Uint8List signed, {List<int>? name, int? padding, List<int> after = const []}) {
    final tail = [...(name ?? names[kind]!), ...digestOf(kind).process(signed), ...after];
    final encoded = [0, 1, ...List.filled(padding ?? length - 3 - tail.length, 0xff), 0, ...tail];
    expect(encoded, hasLength(length));
    return byHand(asNumber(encoded), d, n);
  }

  /// The signatures a played server sends, by what they are, and whether a
  /// client is to take them.
  final cases = <(String, bool, Uint8List Function(String kind, Uint8List hash))>[
    ('as it should be', true, (kind, hash) => asBytes(signature(kind, hash), length)),
    (
      'with the nought it begins with left out',
      true,
      (kind, hash) => Uint8List.sublistView(asBytes(signature(kind, hash), length), 1),
    ),
    (
      'with one more nought before it, which makes it longer than the key',
      false,
      (kind, hash) => Uint8List.fromList([0, ...asBytes(signature(kind, hash), length)]),
    ),
    (
      'that names its hash without the empty part of the name',
      false,
      (kind, hash) => asBytes(signature(kind, hash, name: namesWithoutIt[kind]), length),
    ),
    (
      'with eight bytes of padding and something after the hash',
      false,
      (kind, hash) {
        final hashLength = digestOf(kind).digestSize;
        final after = List.filled(length - 3 - 8 - names[kind]!.length - hashLength, 0x5a);
        return asBytes(signature(kind, hash, padding: 8, after: after), length);
      },
    ),
    (
      'of something else',
      false,
      (kind, hash) => asBytes(signature(kind, Uint8List.fromList(hash.reversed.toList())), length),
    ),
  ];

  PlayedHostKey showing(String kind, Uint8List Function(String kind, Uint8List hash) signed) =>
      PlayedHostKey(kind, blob, (hash) => SSHRsaSignature(kind, signed(kind, hash)).encode());

  test('the key made here: 2041 bits, and every signature it makes begins with a nought', () {
    expect(n.bitLength, 2041);
    expect((e * d) % ((p - BigInt.one) * (q - BigInt.one)), BigInt.one);
    final hash = Uint8List.fromList(List.generate(32, (i) => i));
    for (final kind in names.keys) {
      final made = asBytes(signature(kind, hash), length);
      expect(made[0], 0);
      expect(SSHRsaPublicKey(e, n).verify(hash, SSHRsaSignature(kind, made)), isTrue);
    }
  });

  group('this package\'s client', () {
    for (final kind in names.keys) {
      for (final (what, taken, signed) in cases) {
        test('$kind, a signature $what: ${taken ? 'taken' : 'refused'}', () async {
          final server = PlayedServer(hostKey: showing(kind, signed));
          var asked = 0;
          var ready = 0;
          final transport = SSHTransport(
            server.socket,
            algorithms: SSHAlgorithms(
              kex: const [SSHKexType.x25519],
              hostkey: [kind == 'rsa-sha2-256' ? SSHHostkeyType.rsaSha256 : SSHHostkeyType.rsaSha512],
              cipher: const [SSHCipherType.aes256ctr],
              mac: const [SSHMacType.hmacSha256],
              // The key is 2041 bits on purpose (its signatures begin with
              // a nought); what is held here is the signature, not the
              // length, which 2048 bits where nothing is said would refuse.
              minRsaHostKeyBits: 1024,
            ),
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
          final exchanged = server.exchangeKeys().then((_) => true, onError: (Object _) => false);
          final went = await Future.any([exchanged, ended.then((_) => false)]);
          if (went) {
            await server.settle();
          } else {
            await ended.timeout(PlayedServer.patience);
          }
          if (taken) {
            expect(endedWith, isNull);
            expect(asked, 1);
            expect(ready, 1);
          } else {
            expect(
              endedWith,
              isA<SSHHostkeyError>()
                  .having((e) => e.fault, 'what was wrong', SSHHostkeyFault.notSigned)
                  .having((e) => e.message, 'what it says', 'Signature verification failed'),
            );
            expect(asked, 0);
            expect(ready, 0);
          }
        });
      }
    }
  });

  final clients = OpenSshClient.found();
  if (clients.isEmpty) {
    test('what OpenSSH takes for the signature of an RSA host key', () {}, skip: 'this machine has no OpenSSH client');
    return;
  }

  for (final client in clients) {
    group('the OpenSSH client $client', () {
      for (final kind in names.keys) {
        for (final (what, taken, signed) in cases) {
          test('$kind, a signature $what: ${taken ? 'taken' : 'refused'}', () async {
            final run = await client.connect(
              offers: const [PlayedSuite.ctr],
              suite: PlayedSuite.ctr,
              hostKey: showing(kind, signed),
            );
            addTearDown(run.end);
            // The client sends its new keys once it has taken the server's key and signature.
            final went = await run.server.exchangeKeys().then((_) => true, onError: (Object _) => false);
            expect(went, taken, reason: run.said.join('\n'));
            if (!taken) expect(await run.exitCode, 255, reason: run.said.join('\n'));
            expect(run.lookedAtOthersKeys, 0, reason: 'the client looked at a key that is not of the run');
          });
        }
      }
    });
  }
}
