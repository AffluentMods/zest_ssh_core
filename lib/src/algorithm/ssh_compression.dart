import 'dart:io' show ZLibCodec, ZLibOption;
import 'dart:typed_data';

/// Identifies an SSH compression algorithm by its protocol name.
///
/// See RFC 4253 Section 6.2 for the algorithm registry.
class SSHCompressionType {
  /// The SSH protocol name (e.g. `"zlib"`, `"none"`).
  final String name;

  const SSHCompressionType._(this.name);

  /// No compression.
  static const none = SSHCompressionType._('none');

  /// Standard zlib compression (starts immediately after KEX).
  static const zlib = SSHCompressionType._('zlib');

  /// Delayed zlib compression -- starts only after user authentication.
  ///
  /// This is the variant used by OpenSSH to avoid compressing data before the
  /// session is authenticated (which could leak plaintext via compression
  /// oracles).
  static const zlibOpenssh = SSHCompressionType._('zlib@openssh.com');

  /// All known compression types.
  static const values = [none, zlib, zlibOpenssh];

  /// Look up a compression type by its SSH protocol name. Returns `null` if
  /// the name is not recognised.
  static SSHCompressionType? fromName(String name) {
    for (final value in values) {
      if (value.name == name) {
        return value;
      }
    }
    return null;
  }

  @override
  String toString() => 'SSHCompressionType($name)';
}

// ---------------------------------------------------------------------------
// Compressor / decompressor interface
// ---------------------------------------------------------------------------

/// Exception thrown when decompressed data exceeds the safety limit.
class SSHDecompressionBombException implements Exception {
  final int size;
  final int limit;

  const SSHDecompressionBombException(this.size, this.limit);

  @override
  String toString() =>
      'SSHDecompressionBombException: decompressed size $size exceeds '
      'limit of $limit bytes';
}

/// A paired compressor and decompressor for SSH transport-layer compression.
///
/// Implementations must be safe to call repeatedly and must support [reset]
/// to reinitialise internal state after a re-key.
abstract class SSHCompressor {
  /// Maximum allowed decompressed output size (256 MB).
  static const maxDecompressedSize = 256 * 1024 * 1024;

  /// Compress [data] and return the compressed bytes.
  List<int> compress(List<int> data);

  /// Decompress [data] and return the original bytes.
  List<int> decompress(List<int> data);

  /// Reset internal compressor/decompressor state (e.g. after re-key).
  void reset();
}

// ---------------------------------------------------------------------------
// No-op compressor
// ---------------------------------------------------------------------------

/// Pass-through compressor that performs no transformation.
class SSHNoCompression implements SSHCompressor {
  @override
  List<int> compress(List<int> data) => data;

  @override
  List<int> decompress(List<int> data) => data;

  @override
  void reset() {}
}

// ---------------------------------------------------------------------------
// Zlib compressor
// ---------------------------------------------------------------------------

/// Zlib-based compressor for `zlib` and `zlib@openssh.com`.
///
/// When [delayed] is `true` the compressor starts in pass-through mode and
/// must be activated explicitly by calling [activate] after authentication
/// completes. This implements the `zlib@openssh.com` semantics.
class SSHZlibCompressor implements SSHCompressor {
  /// Whether this instance uses delayed activation (`zlib@openssh.com`).
  final bool delayed;

  bool _active;

  ZLibCodec _deflater;
  ZLibCodec _inflater;

  SSHZlibCompressor({this.delayed = false})
      : _active = !delayed,
        _deflater = ZLibCodec(
          level: ZLibOption.defaultLevel,
          raw: false,
        ),
        _inflater = ZLibCodec(
          level: ZLibOption.defaultLevel,
          raw: false,
        );

  /// Whether compression is currently active. Always `true` for plain `zlib`;
  /// for `zlib@openssh.com` this becomes `true` after [activate] is called.
  bool get isActive => _active;

  /// Activate compression. Only meaningful for delayed mode.
  void activate() {
    _active = true;
  }

  @override
  List<int> compress(List<int> data) {
    if (!_active) return data;
    return Uint8List.fromList(_deflater.encode(data));
  }

  @override
  List<int> decompress(List<int> data) {
    if (!_active) return data;
    final result = Uint8List.fromList(_inflater.decode(data));
    if (result.length > SSHCompressor.maxDecompressedSize) {
      throw SSHDecompressionBombException(
        result.length,
        SSHCompressor.maxDecompressedSize,
      );
    }
    return result;
  }

  @override
  void reset() {
    _deflater = ZLibCodec(
      level: ZLibOption.defaultLevel,
      raw: false,
    );
    _inflater = ZLibCodec(
      level: ZLibOption.defaultLevel,
      raw: false,
    );
  }
}

/// Create an [SSHCompressor] for the given [type].
///
/// Returns [SSHNoCompression] for [SSHCompressionType.none].
SSHCompressor createCompressor(SSHCompressionType type) {
  switch (type) {
    case SSHCompressionType.zlib:
      return SSHZlibCompressor();
    case SSHCompressionType.zlibOpenssh:
      return SSHZlibCompressor(delayed: true);
    case SSHCompressionType.none:
    default:
      return SSHNoCompression();
  }
}
