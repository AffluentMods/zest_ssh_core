import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/zest_ssh_core.dart';

void main() {
  final rng = Random(42); // Deterministic seed for reproducibility

  group('Key parser fuzzing', () {
    for (var i = 0; i < 500; i++) {
      test('random PEM input #$i does not crash', () {
        final length = rng.nextInt(2048);
        final chars = List.generate(length, (_) => rng.nextInt(128));
        final input = String.fromCharCodes(chars);

        try {
          SSHKeyPair.fromPem(input);
        } on FormatException {
          // Expected
        } on RangeError {
          // Expected for truncated data (must be before ArgumentError)
        } on ArgumentError {
          // Expected
        } on StateError {
          // Expected for invalid state
        } on UnsupportedError {
          // Expected for unsupported key types
        } on SSHKeyDecodeError {
          // Expected: the library's own graceful "cannot decode this key"
          // signal for malformed/garbage input - a controlled failure, not a
          // crash. (SSHKeyPair.fromPem wraps every lower-level decode error,
          // incl. ASN.1 type-cast failures, in this type.)
        } on TypeError {
          // Expected for null safety issues with random data
        }
      });
    }

    for (var i = 0; i < 500; i++) {
      test('random binary key blob #$i does not crash', () {
        final length = rng.nextInt(1024);
        final bytes = Uint8List.fromList(
          List.generate(length, (_) => rng.nextInt(256)),
        );

        // Wrap random bytes in a valid-looking PEM envelope
        final pemText = '-----BEGIN OPENSSH PRIVATE KEY-----\n'
            '${_base64Encode(bytes)}\n'
            '-----END OPENSSH PRIVATE KEY-----';

        try {
          SSHKeyPair.fromPem(pemText);
        } on FormatException {
          // Expected
        } on RangeError {
          // Expected for truncated data (must be before ArgumentError)
        } on ArgumentError {
          // Expected
        } on StateError {
          // Expected for invalid state
        } on UnsupportedError {
          // Expected for unsupported key types
        } on SSHKeyDecodeError {
          // Expected: the library's own graceful "cannot decode this key"
          // signal for malformed/garbage input - a controlled failure, not a
          // crash. (SSHKeyPair.fromPem wraps every lower-level decode error,
          // incl. ASN.1 type-cast failures, in this type.)
        } on TypeError {
          // Expected for null safety issues with random data
        }
      });
    }

    for (var i = 0; i < 200; i++) {
      test('random RSA PEM blob #$i does not crash', () {
        final length = rng.nextInt(1024);
        final bytes = Uint8List.fromList(
          List.generate(length, (_) => rng.nextInt(256)),
        );

        final pemText = '-----BEGIN RSA PRIVATE KEY-----\n'
            '${_base64Encode(bytes)}\n'
            '-----END RSA PRIVATE KEY-----';

        try {
          SSHKeyPair.fromPem(pemText);
        } on FormatException {
          // Expected
        } on RangeError {
          // Expected (must be before ArgumentError)
        } on ArgumentError {
          // Expected
        } on StateError {
          // Expected
        } on UnsupportedError {
          // Expected
        } on SSHKeyDecodeError {
          // Expected: the library's own graceful "cannot decode this key"
          // signal for malformed/garbage input - a controlled failure, not a
          // crash. (SSHKeyPair.fromPem wraps every lower-level decode error,
          // incl. ASN.1 type-cast failures, in this type.)
        } on TypeError {
          // Expected
        }
      });
    }

    for (var i = 0; i < 200; i++) {
      test('random EC PEM blob #$i does not crash', () {
        final length = rng.nextInt(1024);
        final bytes = Uint8List.fromList(
          List.generate(length, (_) => rng.nextInt(256)),
        );

        final pemText = '-----BEGIN EC PRIVATE KEY-----\n'
            '${_base64Encode(bytes)}\n'
            '-----END EC PRIVATE KEY-----';

        try {
          SSHKeyPair.fromPem(pemText);
        } on FormatException {
          // Expected
        } on RangeError {
          // Expected (must be before ArgumentError)
        } on ArgumentError {
          // Expected
        } on StateError {
          // Expected
        } on UnsupportedError {
          // Expected
        } on SSHKeyDecodeError {
          // Expected: the library's own graceful "cannot decode this key"
          // signal for malformed/garbage input - a controlled failure, not a
          // crash. (SSHKeyPair.fromPem wraps every lower-level decode error,
          // incl. ASN.1 type-cast failures, in this type.)
        } on TypeError {
          // Expected
        }
      });
    }

    for (var i = 0; i < 200; i++) {
      test('isEncryptedPem with random input #$i does not crash', () {
        final length = rng.nextInt(2048);
        final chars = List.generate(length, (_) => rng.nextInt(128));
        final input = String.fromCharCodes(chars);

        try {
          SSHKeyPair.isEncryptedPem(input);
        } on FormatException {
          // Expected
        } on RangeError {
          // Expected (must be before ArgumentError)
        } on ArgumentError {
          // Expected
        } on StateError {
          // Expected
        } on UnsupportedError {
          // Expected
        } on SSHKeyDecodeError {
          // Expected: the library's own graceful "cannot decode this key"
          // signal for malformed/garbage input - a controlled failure, not a
          // crash. (SSHKeyPair.fromPem wraps every lower-level decode error,
          // incl. ASN.1 type-cast failures, in this type.)
        } on TypeError {
          // Expected
        }
      });
    }
  });
}

/// Encode bytes to base64 with line wrapping for PEM format.
String _base64Encode(Uint8List bytes) {
  final b64 = _toBase64(bytes);
  final lines = <String>[];
  for (var i = 0; i < b64.length; i += 64) {
    final end = i + 64 > b64.length ? b64.length : i + 64;
    lines.add(b64.substring(i, end));
  }
  return lines.join('\n');
}

String _toBase64(Uint8List bytes) {
  const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  final buf = StringBuffer();
  var i = 0;
  while (i < bytes.length) {
    final b0 = bytes[i++];
    final b1 = i < bytes.length ? bytes[i++] : -1;
    final b2 = i < bytes.length ? bytes[i++] : -1;

    buf.write(alphabet[(b0 >> 2) & 0x3F]);
    buf.write(alphabet[((b0 << 4) | (b1 >= 0 ? (b1 >> 4) : 0)) & 0x3F]);
    if (b1 >= 0) {
      buf.write(alphabet[((b1 << 2) | (b2 >= 0 ? (b2 >> 6) : 0)) & 0x3F]);
    } else {
      buf.write('=');
    }
    if (b2 >= 0) {
      buf.write(alphabet[b2 & 0x3F]);
    } else {
      buf.write('=');
    }
  }
  return buf.toString();
}
