// SPDX-License-Identifier: MIT
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' show Digest, PrivateKeyParameter;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/signers/rsa_signer.dart';
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';

/// The check of an RSA signature takes the key's own signatures and no
/// others.
///
/// The check ran in a library, on `BigInt.modPow` of the Dart SDK, which
/// answers wrong for numbers that are picked for it, and a signature is the
/// other side's to pick (utils/mod_pow_exact_test.dart). It is the
/// package's own now: what a signature comes back to under the key is
/// compared, byte for byte, with the one thing it has to come back to
/// (RFC 8017, 8.2.2). These tests hold it to signatures another program
/// made (OpenSSL), to the ones this package makes, and to what is no
/// signature of the key in each way that is known to have been taken for
/// one somewhere.
void main() {
  final pair = SSHKeyPair.fromPem(File('test/fixtures/ssh-rsa/ssh_host_rsa_key').readAsStringSync()).single
      as OpenSSHRsaKeyPair;
  final key = pair.toPublicKey() as SSHRsaPublicKey;
  final length = (key.n.bitLength + 7) ~/ 8;

  Uint8List bytesOf(String hex) =>
      Uint8List.fromList([for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)]);

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

  const kinds = {
    SSHRsaSignatureType.sha1: ('06052b0e03021a', [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
    SSHRsaSignatureType.sha256: (
      '0609608648016503040201',
      [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
    ),
    SSHRsaSignatureType.sha512: (
      '0609608648016503040203',
      [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
    ),
  };

  Digest digestOf(String kind) => switch (kind) {
        SSHRsaSignatureType.sha1 => SHA1Digest(),
        SSHRsaSignatureType.sha256 => SHA256Digest(),
        _ => SHA512Digest(),
      };

  /// The key's signature of [message] under [kind], as the library that
  /// signs here makes it.
  Uint8List signed(Uint8List message, String kind) {
    final signer = RSASigner(digestOf(kind), kinds[kind]!.$1)
      ..init(true, PrivateKeyParameter<asymmetric.RSAPrivateKey>(asymmetric.RSAPrivateKey(pair.n, pair.d, pair.p, pair.q)));
    return signer.generateSignature(message).bytes;
  }

  /// A signature that comes back to [encoded] under the key: made with the
  /// key's secret, as whoever has the key could make it.
  Uint8List comingBackTo(List<int> encoded) => asBytes(byHand(asNumber(encoded), pair.d, pair.n), length);

  /// What a signature of [message] has to come back to, with [padding]
  /// bytes of 0xff where it is not as many as fill the length, and with
  /// [after] behind the hash.
  List<int> encodedFor(Uint8List message, String kind, {List<int>? name, int? padding, List<int> after = const []}) {
    final hash = digestOf(kind).process(message);
    final tail = [...(name ?? kinds[kind]!.$2), ...hash, ...after];
    return [0, 1, ...List.filled(padding ?? length - 3 - tail.length, 0xff), 0, ...tail];
  }

  final message = Uint8List.fromList('what a server signs'.codeUnits);

  // Made with OpenSSL 3.2.2 from the same key file (written out in the PEM
  // form): openssl dgst -sha1|-sha256|-sha512 -sign key message.
  final byOpenSsl = {
    SSHRsaSignatureType.sha1: bytesOf(
      '3ea449daec592db05ac70f3bf1be5d102364a5de16fdc3ab43ded21e0296152853a23eb3469db3e5baf0e0fe82fa4a4d'
      '57eebebe8aba2b37e4ccfb27a9a747c0ac8b1263e4b89c02844ee20b1b4e6af8e29cdedae69be5e49890267e587dab35'
      'e91e3989f7118b73c0e3f7ac7055c8ca9c58b8c98b9181587377d9203db398c3a4ee21266e72f726c338c85aac9d82d8'
      'ef6923edb6e92816263c264701aa9651ee1976571871777c162f16c6fd1a2db5a1c968a8df2641887b561cfbbffb9672'
      'f8cede7d7dca5b2b24ceccb5407eb971f2ddd817801cb66ed17ed6a4f0611969472f197bb15e3dfced597e24f8d6675a'
      'c597f85caa99291f65e4fac290dba9f8',
    ),
    SSHRsaSignatureType.sha256: bytesOf(
      'aefa5e603636739de338e0075038815498d6743b1d9bc1ddd10a1c42ff65e8424eb455ffd54d41c28638fb498ec93a17'
      'a340a30572913c273bd64432839a3ccec5818a531829e04aaabd25f6a98d5b23e8c3d7e96d9322ef367b81db8100072b'
      '92e3732ec4e8efa193b1dbffd4b8ec7677995ee28f837b2256ab61c54b56e80a79d771c07e06595fe3bc4eb9facd61e5'
      'acfc6301b7904920cf13e21576bc366101f00da5616b1abbe9b87bb85be8371c611d78199918b0430e4753a7ce82aaee'
      '1e9c8eee0a1840942f157409809f375060a7fac69ddbb361eea8c35cf6bf3420f44ea528b397f6a1cf21f9bd3fe762b0'
      '3a7cde067c35cfcc1afacec52bfb9ed3',
    ),
    SSHRsaSignatureType.sha512: bytesOf(
      '3c6c17c7cbf814543b83a1dc791cb391de51904ff1ac7ea7e61c39243e5607ad4a909a3777467699010394e047d58412'
      'e83bbe37422a8bb08739f8949b7efef138fd6919b38b2ee8548f46030d58a46a7d6088e437e2626c7a269c264ba42f9d'
      '85e9bf3e4f6a129b72645bdca17b851967d91d9f3938f61aa93cbd807463c5a35079e076a521185678e2d3547b1db7cf'
      '6610d9ebe80b25d587993e576fcbfea2904f758a02649e4cdf6766af8be8e93eb975fd3c60836a80c2cd9950edbe47b4'
      '00e54ef96b43d07becca1d070fac7812e1a20e49f131f68e27f8572ff21cf45e3c8cec1da9aa79a19837a27ba3208707'
      'aea4d2fadffa6b98b5a3c92a39cf8089',
    ),
  };

  group('the key\'s own signatures are taken', () {
    for (final kind in kinds.keys) {
      test('$kind: the one OpenSSL made, and the one made here, which are the same', () {
        expect(key.verify(message, SSHRsaSignature(kind, byOpenSsl[kind]!)), isTrue);
        expect(signed(message, kind), byOpenSsl[kind], reason: 'a signature of this kind has no chance in it');
        expect(key.verify(message, SSHRsaSignature(kind, signed(message, kind))), isTrue);
      });
    }

    test('what the key pair of this package signs, and the same key in the PEM form', () {
      expect(key.verify(message, pair.sign(message)), isTrue);
      final other = Uint8List.fromList('something else'.codeUnits);
      expect(key.verify(other, pair.sign(other)), isTrue);
    });

    test('a signature with its noughts in front left out, as some servers send it, is read as OpenSSH reads it', () {
      // One signature in 256 begins with a nought.
      for (var i = 0; i < 4000; i++) {
        final text = Uint8List.fromList('message $i'.codeUnits);
        final signature = signed(text, SSHRsaSignatureType.sha256);
        if (signature[0] != 0) continue;
        final shorter = Uint8List.sublistView(signature, 1);
        expect(key.verify(text, SSHRsaSignature(SSHRsaSignatureType.sha256, shorter)), isTrue);
        return;
      }
      fail('no signature that begins with a nought among four thousand');
    });
  });

  group('what is no signature of the key is refused', () {
    test('a signature of something else, and of the same under another kind of hash', () {
      final other = Uint8List.fromList('what a server did not sign'.codeUnits);
      for (final kind in kinds.keys) {
        expect(key.verify(other, SSHRsaSignature(kind, byOpenSsl[kind]!)), isFalse, reason: kind);
        for (final named in kinds.keys.where((k) => k != kind)) {
          expect(key.verify(message, SSHRsaSignature(named, byOpenSsl[kind]!)), isFalse, reason: '$kind as $named');
        }
      }
    });

    test('a signature with one bit of it changed, wherever the bit is', () {
      final signature = byOpenSsl[SSHRsaSignatureType.sha256]!;
      for (var bit = 0; bit < signature.length * 8; bit += 13) {
        final changed = Uint8List.fromList(signature)..[bit ~/ 8] ^= 1 << (bit % 8);
        expect(key.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, changed)), isFalse, reason: 'bit $bit');
      }
    });

    test('a signature that is longer than the key, with a nought before it or a byte after it', () {
      final signature = byOpenSsl[SSHRsaSignatureType.sha256]!;
      for (final longer in [
        [0, ...signature],
        [...signature, 0],
      ]) {
        expect(key.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, Uint8List.fromList(longer))), isFalse);
      }
    });

    test('the same signature with the modulus added to it, which comes back to the same', () {
      // It fits into the key's length for a signature that is small enough: one in a few is.
      for (var i = 0; i < 400; i++) {
        final text = Uint8List.fromList('message $i'.codeUnits);
        final more = asNumber(signed(text, SSHRsaSignatureType.sha256)) + key.n;
        if (more.bitLength > length * 8) continue;
        expect(byHand(more, key.e, key.n), asNumber(encodedFor(text, SSHRsaSignatureType.sha256)));
        expect(key.verify(text, SSHRsaSignature(SSHRsaSignatureType.sha256, asBytes(more, length))), isFalse);
        return;
      }
      fail('no signature small enough among four hundred');
    });

    test('nothing, a nought, a one, and the modulus less one', () {
      for (final bytes in [
        Uint8List(0),
        Uint8List(1),
        Uint8List(length),
        asBytes(BigInt.one, length),
        asBytes(key.n - BigInt.one, length),
      ]) {
        for (final kind in kinds.keys) {
          expect(key.verify(message, SSHRsaSignature(kind, bytes)), isFalse);
        }
      }
    });

    test('a signature that comes back to the right hash with too little before it and something after it: the '
        'forgery of 2006', () {
      // (For a key with an exponent of three such a number can be made without the key's secret.)
      final forged = comingBackTo(encodedFor(message, SSHRsaSignatureType.sha256,
          padding: 8, after: List.filled(length - 3 - 8 - 19 - 32, 0x5a)));
      expect(key.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, forged)), isFalse);
    });

    test('one whose padding is not all of 0xff, or has seven bytes, or begins with a two', () {
      final good = encodedFor(message, SSHRsaSignatureType.sha256);
      expect(key.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, comingBackTo(good))), isTrue,
          reason: 'what is made here is a signature when nothing is changed');
      final notAllOnes = [...good]..[10] = 0xfe;
      final aTwo = [...good]..[1] = 2;
      final aNoughtInIt = [...good]..[20] = 0;
      for (final encoded in [notAllOnes, aTwo, aNoughtInIt]) {
        expect(key.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, comingBackTo(encoded))), isFalse);
      }
    });

    test('one that names its hash without the empty part a name has: refused, as OpenSSH refuses it', () {
      // (The library that checked before took this one.)
      const withoutIt = [0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20];
      final signature = comingBackTo(encodedFor(message, SSHRsaSignatureType.sha256, name: withoutIt));
      expect(key.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, signature)), isFalse);
    });

    test('a number picked for the key, for which the SDK\'s arithmetic is wrong: no signature, and no error', () {
      final picked = (((BigInt.one << (length * 8 - 1)) - BigInt.one) * (BigInt.one << (length * 8)).modInverse(key.n)) %
          key.n;
      for (final kind in kinds.keys) {
        expect(key.verify(message, SSHRsaSignature(kind, asBytes(picked, length))), isFalse);
      }
    });
  });

  group('a key that is none', () {
    BigInt odd(int bits) => (BigInt.one << (bits - 1)) | BigInt.from(1234567) | BigInt.one;

    test('a modulus too short to hold a signature of the kind asked for, of nought, of one: said as that', () {
      Matcher tooShort(int bits) => throwsA(isA<FormatException>()
          .having((e) => e.message, 'what it says', 'The RSA key is too short to hold a signature of this kind: $bits bits'));
      Uint8List anything(int length) => Uint8List(length)..[length - 1] = 2;
      // (It was a range error out of the library that checked.)
      for (final (n, bits) in [(BigInt.zero, 0), (BigInt.one, 1), (BigInt.two, 2), (odd(360), 360)]) {
        final key = SSHRsaPublicKey(BigInt.from(65537), n);
        for (final kind in kinds.keys) {
          expect(() => key.verify(message, SSHRsaSignature(kind, anything(8))), tooShort(bits), reason: '$kind, $bits');
        }
      }
      // 512 bits hold a signature with SHA-1 or SHA-256, and none with SHA-512.
      final of512 = SSHRsaPublicKey(BigInt.from(65537), odd(512));
      expect(of512.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha1, anything(64))), isFalse);
      expect(of512.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, anything(64))), isFalse);
      expect(() => of512.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha512, anything(64))), tooShort(512));
    });

    test('the shortest key that holds a signature of each kind, to the bit', () {
      // A nought, a one, eight bytes of 0xff, a nought, the name of the hash and the hash.
      for (final (kind, bytes) in [
        (SSHRsaSignatureType.sha1, 11 + 15 + 20),
        (SSHRsaSignatureType.sha256, 11 + 19 + 32),
        (SSHRsaSignatureType.sha512, 11 + 19 + 64),
      ]) {
        final holds = SSHRsaPublicKey(BigInt.from(65537), odd(bytes * 8 - 7));
        expect(holds.verify(message, SSHRsaSignature(kind, Uint8List(bytes)..[bytes - 1] = 2)), isFalse, reason: kind);
        final tooShort = SSHRsaPublicKey(BigInt.from(65537), odd(bytes * 8 - 8));
        expect(() => tooShort.verify(message, SSHRsaSignature(kind, Uint8List(bytes - 1)..[bytes - 2] = 2)),
            throwsFormatException, reason: kind);
      }
    });

    test('an exponent of nought or one', () {
      for (final e in [BigInt.zero, BigInt.one]) {
        final odd = SSHRsaPublicKey(e, key.n);
        expect(odd.verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, byOpenSsl[SSHRsaSignatureType.sha256]!)),
            isFalse);
      }
      // With an exponent of one a signature is what it comes back to, as for every key with that exponent.
      final itself = Uint8List.fromList(encodedFor(message, SSHRsaSignatureType.sha256));
      expect(SSHRsaPublicKey(BigInt.one, key.n).verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, itself)),
          isTrue);
      // And nothing that is only the end of it: the whole of it is compared, the noughts in front as well.
      for (final atTheEnd in [1, 32, 51, itself.length - 2]) {
        final end = Uint8List.sublistView(itself, itself.length - atTheEnd);
        expect(SSHRsaPublicKey(BigInt.one, key.n).verify(message, SSHRsaSignature(SSHRsaSignatureType.sha256, end)),
            isFalse, reason: 'the last $atTheEnd bytes');
      }
    });
  });

  test('a kind of signature that is none is said to be none', () {
    expect(() => key.verify(message, SSHRsaSignature('rsa-sha2-384', Uint8List(length))), throwsFormatException);
  });

  test('a key of 1024 bits and one of 4096, made up of primes found here: their signatures are taken under each '
      'kind of hash', () {
    final r = Random(11);
    BigInt randomOdd(int bits) {
      var out = BigInt.one << (bits - 1);
      for (var i = 0; i < bits - 2; i += 16) {
        out |= BigInt.from(r.nextInt(1 << 16)) << i;
      }
      return (out | BigInt.one | (BigInt.one << (bits - 2))).toUnsigned(bits);
    }

    bool probablyPrime(BigInt n) {
      for (final small in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]) {
        if (n % BigInt.from(small) == BigInt.zero) return false;
      }
      for (final witness in [2, 3, 5, 7, 11]) {
        if (byHand(BigInt.from(witness), n - BigInt.one, n) != BigInt.one) return false;
      }
      return true;
    }

    BigInt prime(int bits) {
      while (true) {
        final candidate = randomOdd(bits);
        if (probablyPrime(candidate)) return candidate;
      }
    }

    final e = BigInt.from(65537);
    for (final bits in [1024, 4096]) {
      final p = prime(bits ~/ 2);
      final q = prime(bits ~/ 2);
      final n = p * q;
      final d = e.modInverse((p - BigInt.one) * (q - BigInt.one));
      final made = SSHRsaPublicKey(e, n);
      final bytes = (n.bitLength + 7) ~/ 8;
      for (final kind in kinds.keys) {
        final hash = digestOf(kind).process(message);
        final tail = [...kinds[kind]!.$2, ...hash];
        final encoded = [0, 1, ...List.filled(bytes - 3 - tail.length, 0xff), 0, ...tail];
        final signature = asBytes(byHand(asNumber(encoded), d, n), bytes);
        expect(made.verify(message, SSHRsaSignature(kind, signature)), isTrue, reason: '$bits bits, $kind');
        final changed = Uint8List.fromList(signature)..[bytes - 1] ^= 1;
        expect(made.verify(message, SSHRsaSignature(kind, changed)), isFalse, reason: '$bits bits, $kind');
      }
    }
  }, timeout: const Timeout(Duration(minutes: 3)));
}
