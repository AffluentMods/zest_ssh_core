import 'dart:math';

import 'dart:typed_data';

/// One OS-CSPRNG instance for the isolate. Reused across calls: a fresh
/// `Random.secure()` per call re-opens the platform entropy source each time,
/// and this is called once per packet for padding during a bulk transfer.
/// Each draw still pulls fresh OS entropy, and each isolate gets its own
/// instance (top-level finals are per-isolate), so sharing it is safe.
final _secureRandom = Random.secure();

/// Cryptographically-secure random bytes from the OS CSPRNG.
///
/// Fills two bytes per `nextInt` call instead of one, so N bytes cost about
/// N/2 calls. The chunk is 16 bits, not 32, on purpose: `1 << 32` wraps to `1`
/// under dart2js (bitwise ops are 32-bit there), which would silently zero the
/// output on web, whereas `1 << 16` is well within range on every target.
/// This is the single OS-backed source for both key material (KEX cookie,
/// ECDH private keys, key-file salts) and RFC 4253 packet padding.
Uint8List randomBytes(int length) {
  final bytes = Uint8List(length);
  final view = ByteData.sublistView(bytes);
  var i = 0;
  for (; i + 2 <= length; i += 2) {
    view.setUint16(i, _secureRandom.nextInt(1 << 16));
  }
  if (i < length) {
    bytes[i] = _secureRandom.nextInt(256);
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
