import 'dart:math';

import 'dart:typed_data';

Uint8List randomBytes(int length) {
  final random = Random.secure();
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = random.nextInt(256);
  }
  return bytes;
}

extension ListX on List<int> {
  /// Constant-time comparison to prevent timing side-channel attacks during
  /// MAC verification. Every byte is always compared regardless of mismatches.
  bool equals(List<int> other) {
    if (length != other.length) return false;
    int result = 0;
    for (int i = 0; i < length; i++) {
      result |= this[i] ^ other[i];
    }
    return result == 0;
  }
}
