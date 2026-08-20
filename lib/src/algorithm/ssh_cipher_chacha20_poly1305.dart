import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../exceptions/ssh_exceptions.dart';
import '../utils/secure_memory.dart';

/// OpenSSH ChaCha20-Poly1305 AEAD cipher implementation.
///
/// This implements `chacha20-poly1305@openssh.com` as specified in the
/// OpenSSH PROTOCOL.chacha20poly1305 document. This is NOT the standard
/// RFC 7539 AEAD construction.
///
/// Key differences from standard ChaCha20-Poly1305:
/// - Uses a 512-bit key split into two 256-bit keys
/// - K_2 (first 32 bytes) encrypts payload and derives Poly1305 key
/// - K_1 (second 32 bytes) encrypts the 4-byte packet length
/// - The nonce is the 64-bit sequence number (big-endian)
/// - Packet length is encrypted separately with K_1
/// - Poly1305 tag covers (encrypted_length || encrypted_payload)
class SSHCipherChaCha20Poly1305 {
  /// Total key size: two 256-bit keys = 64 bytes.
  static const keySize = 64;

  /// Poly1305 tag size in bytes.
  static const tagSize = 16;

  /// The main key (K_2) used for payload encryption and Poly1305 key
  /// derivation. This is the first 32 bytes of the 64-byte key.
  final Uint8List _mainKey;

  /// The length key (K_1) used for encrypting the 4-byte packet length.
  /// This is the second 32 bytes of the 64-byte key.
  final Uint8List _lengthKey;

  SSHCipherChaCha20Poly1305({required Uint8List key}) :
    _mainKey = Uint8List.sublistView(key, 0, 32),
    _lengthKey = Uint8List.sublistView(key, 32, 64) {
    if (key.length != keySize) {
      throw ArgumentError.value(
        key.length,
        'key',
        'ChaCha20-Poly1305 requires exactly $keySize bytes',
      );
    }
  }

  /// Builds the 8-byte nonce from the packet sequence number.
  ///
  /// The nonce is the 64-bit sequence number encoded as big-endian.
  /// Uses explicit byte-level encoding to guarantee big-endian layout
  /// regardless of the host platform's native endianness.
  static Uint8List _nonceFromSequence(int sequenceNumber) {
    final nonce = Uint8List(8);
    for (int i = 7; i >= 0; i--) {
      nonce[i] = sequenceNumber & 0xFF;
      sequenceNumber >>= 8;
    }
    return nonce;
  }

  /// Runs ChaCha20 on [input] using [key] with the given [nonce] and
  /// starting block [counter].
  ///
  /// The original ChaCha20 uses an 8-byte IV. PointyCastle's ChaCha20Engine
  /// initialises the counter to zero in state words 12-13 and puts the
  /// 8-byte IV into state words 14-15. To start from a non-zero counter we
  /// embed the counter into the first 4 bytes of the nonce and shift the
  /// actual 8-byte nonce accordingly so that the overall 128-bit state
  /// (counter || nonce) is laid out correctly.
  static Uint8List _chacha20(
    Uint8List key,
    Uint8List nonce,
    Uint8List input,
    int counter,
  ) {
    // Pointycastle's ChaCha20Engine takes an 8-byte IV and starts with
    // counter = 0 in state[12..13]. We need to set a specific counter value.
    //
    // State layout: [constants(0-3)] [key(4-11)] [counter(12-13)] [iv(14-15)]
    //
    // OpenSSH chacha20-poly1305 uses the original ChaCha20 (DJ Bernstein's)
    // with a 64-bit nonce and 64-bit counter. The nonce is the packet
    // sequence number.
    //
    // To start at a specific counter value, we pack the counter into the
    // lower 64 bits of the [counter(12-13)] field. Since the ChaCha20Engine
    // always starts at counter=0, we pre-process by generating and
    // discarding (counter * 64) bytes of keystream, then process our input.
    //
    // For counter=0 (Poly1305 key derivation) this is zero waste.
    // For counter=1 (payload encryption) we skip one 64-byte block.
    final engine = ChaCha20Engine();
    engine.init(
      true, // direction doesn't matter for a stream cipher
      ParametersWithIV(KeyParameter(key), nonce),
    );

    // Skip `counter` blocks (each block is 64 bytes)
    if (counter > 0) {
      final skip = Uint8List(64 * counter);
      final skipOut = Uint8List(64 * counter);
      engine.processBytes(skip, 0, skip.length, skipOut, 0);
    }

    final output = Uint8List(input.length);
    engine.processBytes(input, 0, input.length, output, 0);
    return output;
  }

  /// Derives the one-time Poly1305 key by encrypting 32 zero bytes with
  /// ChaCha20 using K_2, the given nonce, and counter=0.
  Uint8List _derivePolyKey(Uint8List nonce) {
    final zeros = Uint8List(32);
    return _chacha20(_mainKey, nonce, zeros, 0);
  }

  /// Computes a Poly1305 tag over [data] using [polyKey] as the one-time key.
  static Uint8List _poly1305Tag(Uint8List polyKey, Uint8List data) {
    final mac = Poly1305();
    mac.init(KeyParameter(polyKey));
    mac.update(data, 0, data.length);
    final tag = Uint8List(tagSize);
    mac.doFinal(tag, 0);
    return tag;
  }

  /// Constant-time comparison of two byte arrays.
  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  /// Encrypts the 4-byte packet length using K_1.
  Uint8List encryptLength(int packetLength, int sequenceNumber) {
    final nonce = _nonceFromSequence(sequenceNumber);
    final lengthBytes = Uint8List(4);
    ByteData.sublistView(lengthBytes).setUint32(0, packetLength);
    return _chacha20(_lengthKey, nonce, lengthBytes, 0);
  }

  /// Decrypts the 4-byte encrypted packet length using K_1.
  int decryptLength(Uint8List encryptedLength, int sequenceNumber) {
    final nonce = _nonceFromSequence(sequenceNumber);
    final decrypted = _chacha20(_lengthKey, nonce, encryptedLength, 0);
    return ByteData.sublistView(decrypted).getUint32(0);
  }

  /// Encrypts a full SSH packet payload.
  ///
  /// Input: [payload] is the raw packet data (padding_length + payload + padding).
  /// Returns: encrypted_length (4) + encrypted_payload + tag (16).
  Uint8List encrypt(Uint8List payload, int packetLength, int sequenceNumber) {
    final nonce = _nonceFromSequence(sequenceNumber);

    // Step 1: Encrypt the 4-byte packet length with K_1
    final lengthBytes = Uint8List(4);
    ByteData.sublistView(lengthBytes).setUint32(0, packetLength);
    final encryptedLength = _chacha20(_lengthKey, nonce, lengthBytes, 0);

    // Step 2: Derive one-time Poly1305 key from K_2, counter=0
    final polyKey = _derivePolyKey(nonce);

    // Step 3: Encrypt the payload with K_2, counter=1
    final encryptedPayload = _chacha20(_mainKey, nonce, payload, 1);

    // Step 4: Compute Poly1305 tag over (encrypted_length || encrypted_payload)
    final aadData = Uint8List(4 + encryptedPayload.length);
    aadData.setRange(0, 4, encryptedLength);
    aadData.setRange(4, aadData.length, encryptedPayload);
    final tag = _poly1305Tag(polyKey, aadData);

    // Zero the one-time Poly1305 key immediately after use.
    zeroBytes(polyKey);

    // Step 5: Build output: encrypted_length + encrypted_payload + tag
    final output = Uint8List(4 + encryptedPayload.length + tagSize);
    output.setRange(0, 4, encryptedLength);
    output.setRange(4, 4 + encryptedPayload.length, encryptedPayload);
    output.setRange(
      4 + encryptedPayload.length,
      output.length,
      tag,
    );

    return output;
  }

  /// Decrypts a full SSH packet.
  ///
  /// [encryptedLength] is the 4 encrypted length bytes (already read).
  /// [encryptedPayload] is the encrypted payload bytes.
  /// [tag] is the 16-byte Poly1305 tag.
  ///
  /// Returns the decrypted payload on success.
  /// Throws [SSHMacMismatchException] if the tag verification fails.
  Uint8List decrypt(
    Uint8List encryptedLength,
    Uint8List encryptedPayload,
    Uint8List tag,
    int sequenceNumber,
  ) {
    final nonce = _nonceFromSequence(sequenceNumber);

    // Step 1: Derive one-time Poly1305 key from K_2, counter=0
    final polyKey = _derivePolyKey(nonce);

    // Step 2: Verify Poly1305 tag over (encrypted_length || encrypted_payload)
    final aadData = Uint8List(4 + encryptedPayload.length);
    aadData.setRange(0, 4, encryptedLength);
    aadData.setRange(4, aadData.length, encryptedPayload);
    final expectedTag = _poly1305Tag(polyKey, aadData);

    // Zero the one-time Poly1305 key immediately after use.
    zeroBytes(polyKey);

    if (!_constantTimeEquals(expectedTag, tag)) {
      throw SSHMacMismatchException();
    }

    // Step 3: Decrypt the payload with K_2, counter=1
    return _chacha20(_mainKey, nonce, encryptedPayload, 1);
  }
}
