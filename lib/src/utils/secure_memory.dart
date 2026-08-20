import 'dart:typed_data';

/// Overwrites every byte in [bytes] with zero.
///
/// Use this to scrub sensitive material (passwords, keys) from memory as soon
/// as it is no longer needed. This is a best-effort measure -- the Dart GC may
/// have already copied the data elsewhere.
void zeroBytes(Uint8List bytes) {
  var check = 0;
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = 0;
    check |= bytes[i];
  }
  if (check != 0) throw StateError('zeroBytes failed');
}

/// A wrapper around [Uint8List] that tracks whether its contents have been
/// cleared and prevents accidental use-after-clear.
///
/// ```dart
/// final secret = SecureBytes(Uint8List.fromList([0x01, 0x02, 0x03]));
/// doSomething(secret.bytes);
/// secret.clear(); // zeros the underlying buffer
/// ```
class SecureBytes {
  final Uint8List _data;
  bool _cleared = false;

  SecureBytes(this._data);

  /// The underlying bytes. Throws [StateError] if [clear] has been called.
  Uint8List get bytes {
    if (_cleared) throw StateError('SecureBytes already cleared');
    return _data;
  }

  /// Whether the contents have been zeroed.
  bool get isCleared => _cleared;

  /// The length of the underlying buffer.
  int get length => _data.length;

  /// Zeros the buffer. Subsequent access to [bytes] will throw.
  ///
  /// Calling [clear] multiple times is safe (it is a no-op after the first).
  void clear() {
    if (!_cleared) {
      zeroBytes(_data);
      _cleared = true;
    }
  }
}
