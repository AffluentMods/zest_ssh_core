import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/kex/sntrup761.dart';

/// Deterministic byte source for reproducible key material in tests.
Uint8List Function(int) seeded(int seed) {
  final rng = Random(seed);
  return (n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
}

void main() {
  final rng = Random.secure();
  Uint8List random(int n) =>
      Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));

  group('sntrup761', () {
    test('sizes match the reference constants', () {
      expect(Sntrup761.publicKeySize, 1158);
      expect(Sntrup761.secretKeySize, 1763);
      expect(Sntrup761.ciphertextSize, 1039);
      expect(Sntrup761.sharedSecretSize, 32);
      final kp = Sntrup761.keyPair(random);
      expect(kp.pk.length, 1158);
      expect(kp.sk.length, 1763);
      // The secret key embeds the public key after the two small polys.
      expect(kp.sk.sublist(382, 382 + 1158), kp.pk);
    });

    test('encaps then decaps agree on the shared secret', () {
      for (var i = 0; i < 3; i++) {
        final kp = Sntrup761.keyPair(random);
        final e = Sntrup761.encaps(kp.pk, random);
        expect(e.ciphertext.length, 1039);
        expect(e.sharedSecret.length, 32);
        expect(Sntrup761.decaps(kp.sk, e.ciphertext), e.sharedSecret);
      }
    });

    test('is deterministic for a fixed byte source', () {
      final a = Sntrup761.keyPair(seeded(7));
      final b = Sntrup761.keyPair(seeded(7));
      expect(a.pk, b.pk);
      expect(a.sk, b.sk);
      final ea = Sntrup761.encaps(a.pk, seeded(11));
      final eb = Sntrup761.encaps(a.pk, seeded(11));
      expect(ea.ciphertext, eb.ciphertext);
      expect(ea.sharedSecret, eb.sharedSecret);
      expect(Sntrup761.encaps(a.pk, seeded(12)).ciphertext,
          isNot(ea.ciphertext));
    });

    test('a tampered ciphertext yields the implicit-rejection secret', () {
      final kp = Sntrup761.keyPair(random);
      final e = Sntrup761.encaps(kp.pk, random);
      for (final at in [0, 500, 1006, 1007, 1038]) {
        final bad = Uint8List.fromList(e.ciphertext);
        bad[at] ^= 0x01;
        final k = Sntrup761.decaps(kp.sk, bad);
        expect(k, isNot(e.sharedSecret), reason: 'byte $at');
        expect(k.length, 32);
        // Rejection is deterministic in (sk, c).
        expect(Sntrup761.decaps(kp.sk, bad), k);
      }
    });

    test('rejects wrong-size inputs', () {
      final kp = Sntrup761.keyPair(random);
      expect(() => Sntrup761.encaps(Uint8List(1157), random), throwsArgumentError);
      expect(() => Sntrup761.decaps(kp.sk, Uint8List(1038)), throwsArgumentError);
      expect(() => Sntrup761.decaps(Uint8List(1762), Uint8List(1039)),
          throwsArgumentError);
    });
  });
}
