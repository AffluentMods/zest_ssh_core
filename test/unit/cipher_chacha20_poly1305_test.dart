import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_cipher_chacha20_poly1305.dart';
import 'package:zest_ssh_core/src/exceptions/ssh_exceptions.dart';

void main() {
  /// Helper: generates a deterministic key of [length] bytes seeded from
  /// [seed].
  Uint8List makeKey(int seed, [int length = 64]) {
    final key = Uint8List(length);
    for (var i = 0; i < length; i++) {
      key[i] = (seed + i * 7 + 3) & 0xff;
    }
    return key;
  }

  /// Helper: builds a fake SSH packet payload with padding.
  /// Returns (packetLength, fullPayload) where fullPayload is
  /// padding_length || payload || padding.
  (int, Uint8List) buildPacketPayload(Uint8List payload) {
    const blockSize = 8;
    var paddingLength = blockSize - ((payload.length + 1) % blockSize);
    if (paddingLength < 4) paddingLength += blockSize;
    final packetLength = 1 + payload.length + paddingLength;
    final fullPayload = Uint8List(packetLength);
    fullPayload[0] = paddingLength;
    fullPayload.setRange(1, 1 + payload.length, payload);
    // Leave padding as zeros
    return (packetLength, fullPayload);
  }

  group('SSHCipherChaCha20Poly1305', () {
    test('roundtrip encrypt/decrypt preserves data', () {
      final key = makeKey(42);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      final payload = Uint8List.fromList(
        [10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
      );
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const sequenceNumber = 0;

      // Encrypt
      final encrypted = cipher.encrypt(fullPayload, packetLength, sequenceNumber);

      // encrypted = enc_length(4) + enc_payload(packetLength) + tag(16)
      expect(encrypted.length, 4 + packetLength + 16);

      // Decrypt
      final encLength = Uint8List.sublistView(encrypted, 0, 4);
      final encPayload = Uint8List.sublistView(encrypted, 4, 4 + packetLength);
      final tag = Uint8List.sublistView(encrypted, 4 + packetLength);

      final decrypted = cipher.decrypt(
        encLength,
        encPayload,
        tag,
        sequenceNumber,
      );

      expect(decrypted, fullPayload);

      // Extract the actual payload from the decrypted packet
      final paddingLen = decrypted[0];
      final actualPayload = Uint8List.sublistView(
        decrypted,
        1,
        decrypted.length - paddingLen,
      );
      expect(actualPayload, payload);
    });

    test('roundtrip works at multiple sequence numbers', () {
      final key = makeKey(99);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      for (var seq = 0; seq < 10; seq++) {
        final payload = Uint8List.fromList(
          List.generate(20, (i) => (i + seq) & 0xff),
        );
        final (packetLength, fullPayload) = buildPacketPayload(payload);

        final encrypted = cipher.encrypt(fullPayload, packetLength, seq);
        final encLength = Uint8List.sublistView(encrypted, 0, 4);
        final encPayload = Uint8List.sublistView(encrypted, 4, 4 + packetLength);
        final tag = Uint8List.sublistView(encrypted, 4 + packetLength);

        final decrypted = cipher.decrypt(encLength, encPayload, tag, seq);
        expect(decrypted, fullPayload);
      }
    });

    test('tampered ciphertext fails MAC check', () {
      final key = makeKey(55);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      final payload = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const sequenceNumber = 7;

      final encrypted = cipher.encrypt(fullPayload, packetLength, sequenceNumber);

      // Tamper with the encrypted payload (flip a bit in the payload area)
      final tampered = Uint8List.fromList(encrypted);
      tampered[6] ^= 0x01;

      final encLength = Uint8List.sublistView(tampered, 0, 4);
      final encPayload = Uint8List.sublistView(tampered, 4, 4 + packetLength);
      final tag = Uint8List.sublistView(tampered, 4 + packetLength);

      expect(
        () => cipher.decrypt(encLength, encPayload, tag, sequenceNumber),
        throwsA(isA<SSHMacMismatchException>()),
      );
    });

    test('tampered tag fails MAC check', () {
      final key = makeKey(66);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      final payload = Uint8List.fromList([11, 22, 33, 44, 55]);
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const sequenceNumber = 3;

      final encrypted = cipher.encrypt(fullPayload, packetLength, sequenceNumber);

      // Tamper with the tag (last byte)
      final tampered = Uint8List.fromList(encrypted);
      tampered[tampered.length - 1] ^= 0x01;

      final encLength = Uint8List.sublistView(tampered, 0, 4);
      final encPayload = Uint8List.sublistView(tampered, 4, 4 + packetLength);
      final tag = Uint8List.sublistView(tampered, 4 + packetLength);

      expect(
        () => cipher.decrypt(encLength, encPayload, tag, sequenceNumber),
        throwsA(isA<SSHMacMismatchException>()),
      );
    });

    test('wrong sequence number fails MAC check', () {
      final key = makeKey(77);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      final payload = Uint8List.fromList([100, 200, 150, 50]);
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const encryptSeq = 5;
      const decryptSeq = 6; // Wrong sequence number

      final encrypted = cipher.encrypt(fullPayload, packetLength, encryptSeq);

      final encLength = Uint8List.sublistView(encrypted, 0, 4);
      final encPayload = Uint8List.sublistView(encrypted, 4, 4 + packetLength);
      final tag = Uint8List.sublistView(encrypted, 4 + packetLength);

      expect(
        () => cipher.decrypt(encLength, encPayload, tag, decryptSeq),
        throwsA(isA<SSHMacMismatchException>()),
      );
    });

    test('different key produces different ciphertext', () {
      final key1 = makeKey(10);
      final key2 = makeKey(20);
      final cipher1 = SSHCipherChaCha20Poly1305(key: key1);
      final cipher2 = SSHCipherChaCha20Poly1305(key: key2);

      final payload = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const sequenceNumber = 0;

      final encrypted1 = cipher1.encrypt(fullPayload, packetLength, sequenceNumber);
      final encrypted2 = cipher2.encrypt(fullPayload, packetLength, sequenceNumber);

      // The encrypted outputs should differ
      expect(encrypted1, isNot(equals(encrypted2)));
    });

    test('key length validation rejects wrong sizes', () {
      expect(
        () => SSHCipherChaCha20Poly1305(key: Uint8List(32)),
        throwsA(isA<ArgumentError>()),
      );

      expect(
        () => SSHCipherChaCha20Poly1305(key: Uint8List(63)),
        throwsA(isA<ArgumentError>()),
      );

      expect(
        () => SSHCipherChaCha20Poly1305(key: Uint8List(65)),
        throwsA(isA<ArgumentError>()),
      );

      expect(
        () => SSHCipherChaCha20Poly1305(key: Uint8List(0)),
        throwsA(isA<ArgumentError>()),
      );

      // 64 bytes should work
      expect(
        () => SSHCipherChaCha20Poly1305(key: Uint8List(64)),
        returnsNormally,
      );
    });

    test('encrypt/decrypt with empty payload works', () {
      final key = makeKey(88);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      // Empty payload -- just padding
      final payload = Uint8List(0);
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const sequenceNumber = 0;

      final encrypted = cipher.encrypt(fullPayload, packetLength, sequenceNumber);
      final encLength = Uint8List.sublistView(encrypted, 0, 4);
      final encPayload = Uint8List.sublistView(encrypted, 4, 4 + packetLength);
      final tag = Uint8List.sublistView(encrypted, 4 + packetLength);

      final decrypted = cipher.decrypt(encLength, encPayload, tag, sequenceNumber);
      expect(decrypted, fullPayload);
    });

    test('encryptLength/decryptLength roundtrip', () {
      final key = makeKey(33);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      const packetLength = 1234;
      const sequenceNumber = 42;

      final encrypted = cipher.encryptLength(packetLength, sequenceNumber);
      expect(encrypted.length, 4);

      final decrypted = cipher.decryptLength(encrypted, sequenceNumber);
      expect(decrypted, packetLength);
    });

    test('encrypted length differs from plaintext length', () {
      final key = makeKey(44);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      const packetLength = 256;
      const sequenceNumber = 0;

      final encrypted = cipher.encryptLength(packetLength, sequenceNumber);
      final plaintextBytes = Uint8List(4);
      ByteData.sublistView(plaintextBytes).setUint32(0, packetLength);

      // The encrypted form should not be the same as plaintext
      expect(encrypted, isNot(equals(plaintextBytes)));
    });

    test('large payload roundtrip', () {
      final key = makeKey(11);
      final cipher = SSHCipherChaCha20Poly1305(key: key);

      // 4096 byte payload
      final payload = Uint8List.fromList(
        List.generate(4096, (i) => i & 0xff),
      );
      final (packetLength, fullPayload) = buildPacketPayload(payload);
      const sequenceNumber = 999;

      final encrypted = cipher.encrypt(fullPayload, packetLength, sequenceNumber);
      final encLength = Uint8List.sublistView(encrypted, 0, 4);
      final encPayload = Uint8List.sublistView(encrypted, 4, 4 + packetLength);
      final tag = Uint8List.sublistView(encrypted, 4 + packetLength);

      final decrypted = cipher.decrypt(encLength, encPayload, tag, sequenceNumber);
      expect(decrypted, fullPayload);
    });
  });
}
