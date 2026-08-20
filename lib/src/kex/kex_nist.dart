import 'dart:typed_data';

import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_kex.dart';
import 'package:zest_ssh_core/src/utils/bigint.dart';
import 'package:zest_ssh_core/src/utils/list.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';
import 'package:pointycastle/pointycastle.dart';

/// The Elliptic Curve Diffie-Hellman (ECDH) key exchange method generates a
/// shared secret from an ephemeral local elliptic curve private key and
/// ephemeral remote elliptic curve public key.
class SSHKexNist implements SSHKexECDH {
  /// The elliptic curve domain parameters.
  final ECDomainParameters curve;

  /// The length of the shared secret in bytes.
  final int secretBits;

  /// Secret random number.
  late final BigInt privateKey;

  /// Public key.
  @override
  late final Uint8List publicKey;

  SSHKexNist({required this.curve, required this.secretBits}) {
    privateKey = _generatePrivateKey();
    final c = curve.G * privateKey;
    publicKey = c!.getEncoded(false);
  }

  SSHKexNist.p256() : this(curve: ECCurve_secp256r1(), secretBits: 256);

  SSHKexNist.p384() : this(curve: ECCurve_secp384r1(), secretBits: 384);

  SSHKexNist.p521() : this(curve: ECCurve_secp521r1(), secretBits: 521);

  /// Compute shared secret.
  @override
  BigInt computeSecret(Uint8List remotePubilcKey) {
    final s = _decodeAndValidatePoint(remotePubilcKey);
    final shared = s * privateKey;
    if (shared == null || shared.isInfinity) {
      throw SSHStateError('ECDH produced an invalid shared point');
    }
    final secret = shared.x!.toBigInteger()!;
    // A degenerate secret (0 or 1) is only reachable via a maliciously
    // chosen public key - reject rather than derive session keys from it.
    if (secret == BigInt.zero || secret == BigInt.one) {
      throw SSHStateError('ECDH shared secret is degenerate');
    }
    return secret;
  }

  /// Decode the server's ephemeral ECDH public key and validate it BEFORE
  /// multiplying it by our private scalar.
  ///
  /// RFC 5656 sends the point in uncompressed SEC1 form (`0x04 || X || Y`).
  /// Blindly trusting it enables an invalid-curve attack: a malicious server
  /// sends a point that is NOT on the negotiated curve, and the resulting
  /// "shared secret" leaks bits of our ephemeral private key over repeated
  /// connections. NIST P-curves have cofactor 1, so verifying the point lies
  /// on the curve (and is not the identity) fully constrains it to the
  /// prime-order subgroup - no separate small-subgroup check is needed.
  ECPoint _decodeAndValidatePoint(Uint8List bytes) {
    final fieldBytes = (curve.curve.fieldSize + 7) ~/ 8;
    if (bytes.length != 1 + 2 * fieldBytes || bytes[0] != 0x04) {
      throw SSHStateError('Malformed ECDH public key encoding');
    }
    final point = curve.curve.decodePoint(bytes);
    if (point == null || point.isInfinity) {
      throw SSHStateError('ECDH public key is the point at infinity');
    }
    // On-curve check: y^2 == x^3 + a*x + b over the curve's prime field.
    // All arithmetic is in F_p via ECFieldElement, so this is exact.
    final x = point.x!;
    final y = point.y!;
    final lhs = (y * y).toBigInteger();
    final rhs =
        (((x * x) * x) + (curve.curve.a! * x) + curve.curve.b!).toBigInteger();
    if (lhs != rhs) {
      throw SSHStateError('ECDH public key is not on the negotiated curve');
    }
    return point;
  }

  BigInt _generatePrivateKey() {
    // ceil(secretBits / 8): P-521 needs 66 bytes, but `secretBits ~/ 8` gave 65
    // (520 bits), dropping the top bit and drawing the scalar from a reduced
    // range. P-256 / P-384 are byte-aligned and unaffected.
    final byteLen = (secretBits + 7) ~/ 8;
    late BigInt x;
    do {
      x = decodeBigIntWithSign(1, randomBytes(byteLen)) % curve.n;
    } while (x == BigInt.zero);
    return x;
  }
}
