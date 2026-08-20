import 'dart:typed_data';

import 'package:zest_ssh_core/zest_ssh_core.dart';

void main() {
  final sizes = [1024 * 1024, 10 * 1024 * 1024]; // 1MB, 10MB

  // Only benchmark non-AEAD ciphers that expose BlockCipher via createCipher.
  // AEAD ciphers (AES-GCM) are packet-level and cannot be benchmarked this way.
  final ciphers = <String, SSHCipherType>{
    'aes128-ctr': SSHCipherType.aes128ctr,
    'aes192-ctr': SSHCipherType.aes192ctr,
    'aes256-ctr': SSHCipherType.aes256ctr,
    'aes128-cbc': SSHCipherType.aes128cbc,
    'aes192-cbc': SSHCipherType.aes192cbc,
    'aes256-cbc': SSHCipherType.aes256cbc,
  };

  for (final entry in ciphers.entries) {
    final cipherName = entry.key;
    final cipherType = entry.value;

    print('=== $cipherName (keySize: ${cipherType.keySize}) ===');

    final key = Uint8List(cipherType.keySize);
    final iv = Uint8List(cipherType.ivSize);

    // Fill key and IV with deterministic data
    for (var i = 0; i < key.length; i++) {
      key[i] = i & 0xFF;
    }
    for (var i = 0; i < iv.length; i++) {
      iv[i] = (i * 7) & 0xFF;
    }

    for (final size in sizes) {
      final sizeMB = size / (1024 * 1024);
      final data = Uint8List(size);

      // Fill with deterministic data
      for (var i = 0; i < size; i++) {
        data[i] = i & 0xFF;
      }

      // Benchmark encryption
      final encCipher = cipherType.createCipher(
        key,
        Uint8List.fromList(iv),
        forEncryption: true,
      );
      final encSw = Stopwatch()..start();
      final blockSize = encCipher.blockSize;
      for (var offset = 0; offset + blockSize <= size; offset += blockSize) {
        encCipher.processBlock(data, offset, data, offset);
      }
      encSw.stop();

      final encMs = encSw.elapsedMilliseconds;
      final encMbps =
          encMs > 0 ? sizeMB / (encMs / 1000) : double.infinity;
      print(
        '  Encrypt ${sizeMB.toStringAsFixed(0)}MB: '
        '${encMbps.toStringAsFixed(1)} MB/s '
        '(${encMs}ms)',
      );

      // Benchmark decryption
      final decCipher = cipherType.createCipher(
        key,
        Uint8List.fromList(iv),
        forEncryption: false,
      );
      final decSw = Stopwatch()..start();
      for (var offset = 0; offset + blockSize <= size; offset += blockSize) {
        decCipher.processBlock(data, offset, data, offset);
      }
      decSw.stop();

      final decMs = decSw.elapsedMilliseconds;
      final decMbps =
          decMs > 0 ? sizeMB / (decMs / 1000) : double.infinity;
      print(
        '  Decrypt ${sizeMB.toStringAsFixed(0)}MB: '
        '${decMbps.toStringAsFixed(1)} MB/s '
        '(${decMs}ms)',
      );
    }

    print('');
  }
}
