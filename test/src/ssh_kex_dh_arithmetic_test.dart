// SPDX-License-Identifier: MIT
import 'dart:math';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';

/// What a Diffie-Hellman exchange computes is right, whatever numbers it is
/// given.
///
/// Both numbers of the exchange are powers modulo the group's modulus: the
/// public value a side sends (the generator to the power of its secret) and
/// the secret both arrive at (the other side's public value to that power).
/// They were computed with `BigInt.modPow` of the Dart SDK, which answers
/// wrong for some numbers (Dart 3.10.8 on x64, as a script and compiled):
/// not for numbers picked at random, and for any odd modulus of 192 bits or
/// more for a base that is computed from the modulus. The other side picks
/// its public value, and in a group exchange the modulus and the generator
/// as well.
///
/// The right answers here are computed by squaring and multiplying with
/// nothing but `*` and `%`, and for the smallest case they are the numbers
/// another program says (Python's `pow`).
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

  BigInt random(Random r, int bits) {
    var out = BigInt.zero;
    for (var i = 0; i < bits; i += 16) {
      out = (out << 16) | BigInt.from(r.nextInt(1 << 16));
    }
    return out >> ((16 - bits % 16) % 16);
  }

  /// A number below the odd modulus [m] of [bits] bits (a multiple of 64)
  /// that `BigInt.modPow` raises to a power wrongly: one whose form inside
  /// that computation (the number times 2^bits, modulo [m]) is all ones.
  BigInt pickedFor(BigInt m, int bits, {int less = 1}) {
    final allOnes = (BigInt.one << (bits - 1)) - BigInt.from(less);
    return (allOnes * (BigInt.one << bits).modInverse(m)) % m;
  }

  final group14 = SSHKexDH.group14();
  final group1 = SSHKexDH.group1();

  test('the smallest case found, against what another program says', () {
    final m = BigInt.parse('aa9ac7cc8b50a995a97721d14f6ec73e851424ae9183cafb', radix: 16);
    final f = BigInt.parse('a08421e1df1118dae27e84ec688d029565581fb3bd61e397', radix: 16);
    expect(f, pickedFor(m, 192), reason: 'the number is the one picked for this modulus');
    final dh = SSHKexDH(p: m, g: BigInt.two, secretBits: 160);
    expect(dh.computeSecret(f), byHand(f, dh.x, m));
    // With the exponent an RSA key has, which Python computed too.
    expect(byHand(f, BigInt.from(65537), m),
        BigInt.parse('a51c75c8f28bbd641ad703fb658c367e336549f5f6d3d01f', radix: 16));
  });

  group('the secret, from a public value the other side picked for the group', () {
    for (final (name, group) in [('the group of RFC 3526 (2048 bits)', group14), ('the group of RFC 2409 (1024 bits)', group1)]) {
      test(name, () {
        final p = group.p;
        for (var less = 1; less <= 3; less++) {
          final f = pickedFor(p, p.bitLength, less: less);
          expect(f > BigInt.one && f < p - BigInt.one, isTrue, reason: 'a public value a server may send');
          final dh = SSHKexDH(p: p, g: BigInt.two, secretBits: 256);
          expect(dh.computeSecret(f), byHand(f, dh.x, p), reason: 'picked with $less');
        }
      });
    }

    test('a group a server named in a group exchange, of any odd modulus', () {
      final r = Random(20261010);
      for (final bits in [2048, 3072, 4096]) {
        final p = random(r, bits) | (BigInt.one << (bits - 1)) | BigInt.one;
        final f = pickedFor(p, bits);
        final dh = SSHKexDH(p: p, g: BigInt.two, secretBits: 256);
        expect(dh.computeSecret(f), byHand(f, dh.x, p), reason: '$bits bits');
      }
    });
  });

  group('the public value, from a generator the other side picked for the group', () {
    test('a generator picked for the modulus', () {
      final r = Random(20261011);
      for (final bits in [2048, 4096]) {
        final p = random(r, bits) | (BigInt.one << (bits - 1)) | BigInt.one;
        final g = pickedFor(p, bits);
        final dh = SSHKexDH(p: p, g: g, secretBits: 256);
        expect(dh.e, byHand(g, dh.x, p), reason: '$bits bits');
      }
    });

    test('the generator 2 with a modulus that is mostly noughts', () {
      final p = (BigInt.one << 2047) | (BigInt.one << 1024) | BigInt.one;
      final dh = SSHKexDH(p: p, g: BigInt.two, secretBits: 256);
      expect(dh.e, byHand(BigInt.two, dh.x, p));
    });
  });

  test('numbers picked at random, as an honest exchange has them: right, as they were', () {
    final r = Random(20261012);
    for (final group in [group14, group1]) {
      for (var i = 0; i < 20; i++) {
        final f = random(r, group.p.bitLength - 1) + BigInt.two;
        final dh = SSHKexDH(p: group.p, g: group.g, secretBits: 256);
        expect(dh.e, byHand(group.g, dh.x, group.p));
        expect(dh.computeSecret(f), byHand(f, dh.x, group.p));
      }
    }
  });

  test('two sides of an exchange arrive at the same secret', () {
    for (final group in [group14, group1]) {
      final client = SSHKexDH(p: group.p, g: group.g, secretBits: 256);
      final server = SSHKexDH(p: group.p, g: group.g, secretBits: 256);
      expect(client.computeSecret(server.e), server.computeSecret(client.e));
    }
  });
}
