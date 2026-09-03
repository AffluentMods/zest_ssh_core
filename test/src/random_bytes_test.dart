import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/utils/list.dart';

/// randomBytes fills two bytes per CSPRNG draw. These pin the properties the
/// batching must not break: exact length for even AND odd sizes (the tail
/// byte), and that the output is actually random, not the all-zero buffer a
/// broken shift (`1 << 32` under dart2js) would produce.
void main() {
  test('returns exactly the requested length, even and odd', () {
    for (final n in [0, 1, 2, 3, 4, 15, 16, 17, 32, 255]) {
      expect(randomBytes(n).length, n, reason: 'length $n');
    }
  });

  test('is not the all-zero buffer (guards a dead RNG / bad shift)', () {
    // Odd length exercises both the 2-byte loop and the tail byte.
    final b = randomBytes(33);
    expect(b.any((x) => x != 0), isTrue);
  });

  test('every byte position varies across the buffer (no stuck 16-bit lane)',
      () {
    // Draw a large buffer; both the low and high byte of each 16-bit word
    // must take more than one value across the buffer.
    final b = randomBytes(4096);
    final evenBytes = <int>{};
    final oddBytes = <int>{};
    for (var i = 0; i + 1 < b.length; i += 2) {
      evenBytes.add(b[i]);
      oddBytes.add(b[i + 1]);
    }
    expect(evenBytes.length, greaterThan(1));
    expect(oddBytes.length, greaterThan(1));
  });

  test('successive calls differ (shared instance still draws fresh entropy)',
      () {
    expect(randomBytes(32), isNot(equals(randomBytes(32))));
  });

  test('returns a Uint8List', () {
    expect(randomBytes(8), isA<Uint8List>());
  });
}
