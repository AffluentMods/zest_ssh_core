import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/kex/mlkem768.dart';

Uint8List hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

// NIST publishes uppercase hex; compare in lowercase.
String toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

String lower(dynamic s) => (s as String).toLowerCase();

void main() {
  // NIST ACVP ML-KEM FIPS 203 vectors (ML-KEM-768 subset), from
  // usnistgov/ACVP-Server gen-val/json-files.
  final kat = jsonDecode(
    File('test/kex/fixtures/mlkem768_kat.json').readAsStringSync(),
  ) as Map<String, dynamic>;

  group('ML-KEM-768 FIPS 203 vectors', () {
    test('KeyGen_internal(d, z) matches ek and dk', () {
      final cases = kat['keyGen'] as List;
      expect(cases, isNotEmpty);
      for (final c in cases) {
        final r = MlKem768.keyGenInternal(hex(c['d']), hex(c['z']));
        expect(toHex(r.ek), lower(c['ek']));
        expect(toHex(r.dk), lower(c['dk']));
      }
    });

    test('Encaps_internal(ek, m) matches c and K', () {
      final cases = kat['encaps'] as List;
      expect(cases, isNotEmpty);
      for (final c in cases) {
        final r = MlKem768.encapsInternal(hex(c['ek']), hex(c['m']));
        expect(toHex(r.ciphertext), lower(c['c']));
        expect(toHex(r.sharedSecret), lower(c['k']));
      }
    });

    test('Decaps(dk, c) matches K, including implicit rejection', () {
      final cases = kat['decaps'] as List;
      expect(cases, isNotEmpty);
      var rejected = 0;
      for (final c in cases) {
        final k = MlKem768.decaps(hex(c['dk']), hex(c['c']));
        expect(toHex(k), lower(c['k']), reason: c['reason']);
        if ((c['reason'] as String).contains('modified')) rejected++;
      }
      expect(rejected, greaterThan(0));
    });
  });

  group('ML-KEM-768 round trip', () {
    final rng = Random.secure();
    Uint8List random(int n) =>
        Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));

    test('encaps then decaps agree on the shared secret', () {
      for (var i = 0; i < 5; i++) {
        final kp = MlKem768.keyGen(random);
        expect(kp.ek.length, MlKem768.encapsulationKeySize);
        expect(kp.dk.length, MlKem768.decapsulationKeySize);
        final e = MlKem768.encaps(kp.ek, random);
        expect(e.ciphertext.length, MlKem768.ciphertextSize);
        expect(MlKem768.decaps(kp.dk, e.ciphertext), e.sharedSecret);
      }
    });

    test('a tampered ciphertext yields a different secret, never an error',
        () {
      final kp = MlKem768.keyGen(random);
      final e = MlKem768.encaps(kp.ek, random);
      final bad = Uint8List.fromList(e.ciphertext);
      bad[7] ^= 0x01;
      final k = MlKem768.decaps(kp.dk, bad);
      expect(k, isNot(e.sharedSecret));
      expect(k.length, 32);
    });

    test('rejects a malformed encapsulation key', () {
      final kp = MlKem768.keyGen(random);
      expect(() => MlKem768.encaps(Uint8List(10), random), throwsArgumentError);
      // Force a coefficient >= q: 0xfff in the first 12-bit slot.
      final unreduced = Uint8List.fromList(kp.ek);
      unreduced[0] = 0xff;
      unreduced[1] |= 0x0f;
      expect(() => MlKem768.encaps(unreduced, random), throwsArgumentError);
    });

    test('rejects wrong-size ciphertexts and keys', () {
      final kp = MlKem768.keyGen(random);
      expect(() => MlKem768.decaps(kp.dk, Uint8List(1087)), throwsArgumentError);
      expect(() => MlKem768.decaps(Uint8List(2399), Uint8List(1088)),
          throwsArgumentError);
    });
  });
}
