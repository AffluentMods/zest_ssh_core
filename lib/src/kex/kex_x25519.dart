import 'dart:typed_data';

import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_kex.dart';
import 'package:zest_ssh_core/src/utils/bigint.dart';
import 'package:zest_ssh_core/src/utils/list.dart';
import 'package:pinenacl/tweetnacl.dart';

class SSHKexX25519 implements SSHKexECDH {
  /// Randomly generated private key.
  late final Uint8List privateKey;

  /// Public key computed from the private key.
  @override
  late final Uint8List publicKey;

  SSHKexX25519() {
    privateKey = randomBytes(32);
    publicKey = X25519.scalarMultBase(privateKey);
  }

  @override
  BigInt computeSecret(Uint8List remotePublicKey) {
    final secret = X25519.sharedSecret(privateKey, remotePublicKey);
    return decodeBigIntWithSign(1, secret);
  }
}

/// Curve25519 scalar multiplication (RFC 7748), shared by the classic
/// `curve25519-sha256` exchange and the hybrid post-quantum ones.
class X25519 {
  X25519._();

  /// Length of a scalar and of a group element, in bytes.
  static const int keyLength = 32;

  /// n * P for a group element [p].
  static Uint8List scalarMult(Uint8List n, Uint8List p) {
    if (n.length != keyLength) {
      throw ArgumentError('n must be 32 bytes long');
    }
    if (p.length != keyLength) {
      throw ArgumentError('p must be 32 bytes long');
    }
    final q = Uint8List(keyLength);
    TweetNaCl.crypto_scalarmult(q, n, p);
    return q;
  }

  /// n * G for the standard base point.
  static Uint8List scalarMultBase(Uint8List n) {
    if (n.length != keyLength) {
      throw ArgumentError('n must be 32 bytes long');
    }
    final q = Uint8List(keyLength);
    TweetNaCl.crypto_scalarmult_base(q, n);
    return q;
  }

  /// The raw 32-byte shared secret for our [privateKey] and the peer's
  /// [remotePublicKey], refusing an all-zero result: X25519 yields all zeros
  /// when the peer's public value is a low-order point (RFC 7748 section
  /// 6.1), and accepting it would let a MITM force a fully-known key. The
  /// check is a constant-time OR-accumulate.
  static Uint8List sharedSecret(Uint8List privateKey, Uint8List remotePublicKey) {
    final secret = scalarMult(privateKey, remotePublicKey);
    var acc = 0;
    for (final b in secret) {
      acc |= b;
    }
    if (acc == 0) {
      // SSHError so the transport tears down cleanly (see kex_dh.dart).
      throw SSHStateError(
          'X25519 produced an all-zero shared secret (low-order point)');
    }
    return secret;
  }
}
