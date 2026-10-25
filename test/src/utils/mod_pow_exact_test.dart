import 'dart:io';
import 'dart:math';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';
import 'package:zest_ssh_core/src/utils/bigint.dart';

/// The package's own power of a number modulo another is right.
///
/// It is there because `BigInt.modPow` of the Dart SDK is not, for some
/// numbers (see [modPowExact]). What is right is known here without
/// computing it, or from another program (Python's `pow`), or from
/// `BigInt.modPow` itself for numbers picked at random, where it is right.
/// Nothing here says what `BigInt.modPow` answers where it is wrong: that
/// is the SDK's to mend, and these tests are to hold when it has.
void main() {
  BigInt hex(String digits) => BigInt.parse(digits, radix: 16);

  BigInt random(Random r, int bits) {
    var out = BigInt.zero;
    for (var i = 0; i < bits; i += 16) {
      out = (out << 16) | BigInt.from(r.nextInt(1 << 16));
    }
    return out >> ((16 - bits % 16) % 16);
  }

  test('the smallest case found in which the SDK is wrong, as another program computes it', () {
    final m = hex('aa9ac7cc8b50a995a97721d14f6ec73e851424ae9183cafb');
    final base = hex('a08421e1df1118dae27e84ec688d029565581fb3bd61e397');
    expect(modPowExact(base, BigInt.from(65537), m), hex('a51c75c8f28bbd641ad703fb658c367e336549f5f6d3d01f'));
    expect(modPowExact(base, BigInt.from(128), m), hex('8a561e3312aa03d3ba2a0d14318e9bdcbf3b4de330c43048'));
  });

  group('what is known without computing it', () {
    final moduli = {
      'the group of RFC 3526': SSHKexDH.group14().p,
      'the group of RFC 2409': SSHKexDH.group1().p,
      '2^255 - 19': (BigInt.one << 255) - BigInt.from(19),
      '2^521 - 1': (BigInt.one << 521) - BigInt.one,
      '2^2048 - 12345': (BigInt.one << 2048) - BigInt.from(12345),
      'a modulus that is mostly noughts': (BigInt.one << 2047) | (BigInt.one << 1024) | BigInt.one,
    };
    for (final entry in moduli.entries) {
      test('${entry.key}: the modulus less one to an even power is one, and to an odd power itself', () {
        final m = entry.value;
        final lessOne = m - BigInt.one;
        for (final exponent in [BigInt.two, BigInt.from(128), BigInt.from(1000), (BigInt.one << 255) + BigInt.two]) {
          expect(modPowExact(lessOne, exponent, m), BigInt.one, reason: 'to the power of $exponent');
          expect(modPowExact(lessOne, exponent + BigInt.one, m), lessOne, reason: 'to the power of $exponent and one');
        }
      });
    }

    test('a power that is less than the modulus is that power', () {
      final m = (BigInt.one << 2047) | (BigInt.one << 1024) | BigInt.one;
      expect(modPowExact(BigInt.two, BigInt.from(1000), m), BigInt.one << 1000);
      expect(modPowExact(BigInt.from(3), BigInt.from(100), m), BigInt.from(3).pow(100));
    });

    test('the limits: a power of nought, of one, a base of nought and of one, a modulus of one', () {
      final m = BigInt.from(1000003);
      expect(modPowExact(BigInt.from(12345), BigInt.zero, m), BigInt.one);
      expect(modPowExact(BigInt.from(12345), BigInt.one, m), BigInt.from(12345));
      expect(modPowExact(BigInt.zero, BigInt.from(5), m), BigInt.zero);
      expect(modPowExact(BigInt.zero, BigInt.zero, m), BigInt.one);
      expect(modPowExact(BigInt.one, BigInt.from(1) << 200, m), BigInt.one);
      expect(modPowExact(BigInt.from(12345), BigInt.from(77), BigInt.one), BigInt.zero);
      expect(modPowExact(BigInt.from(12345), BigInt.zero, BigInt.one), BigInt.zero);
      // A base that is not below the modulus, and one below nought, count as what they are modulo it.
      expect(modPowExact(m + BigInt.two, BigInt.from(10), m), BigInt.from(1024));
      expect(modPowExact(BigInt.from(-2), BigInt.from(3), BigInt.from(7)), BigInt.from(6));
      // A modulus that is an even number.
      expect(modPowExact(BigInt.from(7), BigInt.from(4), BigInt.from(100)), BigInt.one);
      expect(modPowExact(BigInt.from(3), BigInt.from(200), BigInt.one << 64), BigInt.from(3).pow(200) % (BigInt.one << 64));
    });

    test('what is no power or no modulus is refused, as BigInt.modPow refuses it', () {
      expect(() => modPowExact(BigInt.two, BigInt.from(-1), BigInt.from(7)), throwsArgumentError);
      expect(() => modPowExact(BigInt.two, BigInt.two, BigInt.zero), throwsArgumentError);
      expect(() => modPowExact(BigInt.two, BigInt.two, BigInt.from(-7)), throwsArgumentError);
    });
  });

  test('numbers picked at random: as BigInt.modPow says, which is right for those', () {
    final r = Random(20261010);
    for (var i = 0; i < 300; i++) {
      final bits = [64, 127, 255, 256, 521, 1024, 2048][i % 7];
      final m = random(r, bits) | (BigInt.one << (bits - 1)) | (i.isEven ? BigInt.one : BigInt.zero);
      final base = random(r, bits + 8);
      final exponent = random(r, [1, 2, 7, 8, 17, 64, 160, 256][i % 8]);
      expect(modPowExact(base, exponent, m), base.modPow(exponent, m), reason: 'case $i');
    }
  });

  test('nothing of the package computes a power with BigInt.modPow', () {
    // (A library the package signs with still does, with a key's own numbers: what it makes is checked before it
    // is given out, see ssh_rsa_sign_checked_test.dart.)
    final calls = <String>[];
    for (final file in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!file.path.endsWith('.dart')) continue;
      final lines = file.readAsLinesSync();
      for (var i = 0; i < lines.length; i++) {
        final line = lines[i].trimLeft();
        if (line.startsWith('//')) continue;
        if (line.contains('.modPow(')) calls.add('${file.path}:${i + 1}');
      }
    }
    expect(calls, isEmpty);
    // The search finds what it looks for.
    expect('    e = g.modPow(x, p);'.contains('.modPow('), isTrue);
  });

  test('a group of 8192 bits to a power of 256 bits takes no time that anybody would notice', () {
    final r = Random(7);
    final m = random(r, 8192) | (BigInt.one << 8191) | BigInt.one;
    final clock = Stopwatch()..start();
    modPowExact(random(r, 8191), random(r, 256), m);
    expect(clock.elapsed, lessThan(const Duration(seconds: 5)));
  });
}
