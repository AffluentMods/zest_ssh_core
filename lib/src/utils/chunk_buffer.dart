import 'dart:typed_data';

/// A buffer that can queue chunks of data and consume parts or all of them as
/// needed. Primarily used for reading data from a socket.
///
/// Internally this uses a **read-offset** design instead of reallocating on
/// every append. The backing [_buffer] may be larger than the logical data it
/// holds; the live region is the half-open range `[_start, _end)`:
///
///   * [add] appends into free space at the tail in place (amortised O(1)).
///     When the tail is full it allocates a *fresh, larger* array and copies
///     only the unread region - dropping the already-consumed prefix
///     (compaction) and growing capacity in one step.
///   * [consume]/[data]/[view] read from `[_start, _end)` and [consume] simply
///     advances `_start` rather than reallocating.
///
/// The previous implementation reallocated and recopied the entire buffer on
/// every [add], which is O(n^2) when a receive backlog builds up (e.g. while
/// the isolate is busy decrypting a large SFTP transfer and the socket keeps
/// delivering data). The offset design keeps a burst of appends amortised O(1).
///
/// A subtlety this preserves from the old behaviour: a [Uint8List] previously
/// returned by [consume] (or [data]) is a VIEW onto the backing store and must
/// stay valid after later operations. This holds because a tail append only
/// writes bytes at or after `_end` (never inside an already-returned region),
/// and compaction/growth allocates a brand-new array and leaves the old one
/// untouched - so outstanding views are never mutated.
class ChunkBuffer {
  /// Backing store. Its length is the *capacity*, which may exceed the logical
  /// length `_end - _start`.
  var _buffer = Uint8List(0);

  /// Start of the unread region (inclusive).
  var _start = 0;

  /// End of the unread region (exclusive). Logical length is `_end - _start`.
  var _end = 0;

  void add(Uint8List data) {
    if (data.isEmpty) return;
    final incoming = data.length;

    // Fast path: free space remains at the tail - append in place. This writes
    // only at `[_end, _end + incoming)`, so it can never touch a region a prior
    // consume()/data view aliases, and it never reallocates.
    if (_buffer.length - _end >= incoming) {
      _buffer.setRange(_end, _end + incoming, data);
      _end += incoming;
      return;
    }

    // Not enough room at the tail. Allocate a FRESH array (never mutate the old
    // one, so any views previously returned stay valid), copying only the
    // unread region - this both compacts (drops the consumed prefix) and grows.
    // Geometric growth keeps a burst of appends amortised O(1) instead of the
    // old recopy-everything-per-add O(n^2).
    final used = _end - _start;
    final required = used + incoming;
    var newCapacity = required * 2;
    if (newCapacity < required) newCapacity = required; // overflow guard
    final newBuffer = Uint8List(newCapacity);
    newBuffer.setRange(0, used, _buffer, _start);
    newBuffer.setRange(used, required, data);
    _buffer = newBuffer;
    _start = 0;
    _end = required;
  }

  Uint8List consume([int? length]) {
    if (length == null) {
      final result = Uint8List.sublistView(_buffer, _start, _end);
      _buffer = Uint8List(0);
      _start = 0;
      _end = 0;
      return result;
    }
    final end = _start + length;
    if (length < 0 || end > _end) {
      throw RangeError.range(length, 0, _end - _start, 'length');
    }
    final result = Uint8List.sublistView(_buffer, _start, end);
    _start = end;
    return result;
  }

  void clear() {
    _buffer = Uint8List(0);
    _start = 0;
    _end = 0;
  }

  Uint8List get data {
    return Uint8List.sublistView(_buffer, _start, _end);
  }

  Uint8List view(int start, int length) {
    final from = _start + start;
    final to = from + length;
    if (start < 0 || length < 0 || to > _end) {
      throw RangeError('view($start, $length) out of range '
          '(available ${_end - _start})');
    }
    return _buffer.sublist(from, to);
  }

  int get length {
    return _end - _start;
  }

  bool get isEmpty {
    return _start == _end;
  }

  bool get isNotEmpty {
    return _start != _end;
  }

  ByteData get byteData {
    return ByteData.sublistView(data);
  }

  @override
  String toString() {
    return 'SSHChunkBuffer(length: $length)';
  }
}
