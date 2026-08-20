import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:pointycastle/export.dart';

class SSHEcdsaPublicKey implements SSHHostKey {
  final String type;

  final String curveId;

  final Uint8List q;

  SSHEcdsaPublicKey({
    required this.type,
    required this.curveId,
    required this.q,
  });

  factory SSHEcdsaPublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (!type.startsWith('ecdsa-sha2-')) {
      throw Exception('Invalid key type: $type');
    }
    final curveId = reader.readUtf8();
    // Bind the algorithm name to the embedded curve id. A well-formed ECDSA
    // host key always names its curve consistently - `ecdsa-sha2-nistp256`
    // carries `nistp256`. Without this check a server could pair one curve's
    // name (driving the hash choice via [curveHash]) with a different curve's
    // parameters, inducing a curve/hash confusion during verification.
    if (type != 'ecdsa-sha2-$curveId') {
      throw Exception('ECDSA key type "$type" does not match curve "$curveId"');
    }
    final q = reader.readString();
    return SSHEcdsaPublicKey(type: type, curveId: curveId, q: q);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeUtf8(curveId);
    writer.writeString(q);
    return writer.takeBytes();
  }

  bool verify(
    Uint8List message,
    SSHEcdsaSignature signature,
  ) {
    final domain = curve;
    // Validate the public point BEFORE trusting it for verification. A
    // malformed or off-curve point must fail closed (reject the host) rather
    // than reach pointycastle and either throw or verify against a bogus
    // point. Fail-closed here surfaces to the caller as a normal signature
    // failure, tearing the handshake down cleanly.
    final point = _tryDecodeValidPoint(domain, q);
    if (point == null) return false;

    final signer = ECDSASigner(curveHash);
    signer.init(false, PublicKeyParameter(ECPublicKey(point, domain)));

    return signer.verifySignature(
      message,
      ECSignature(signature.r, signature.s),
    );
  }

  /// Decode [q] as an uncompressed SEC1 point and confirm it is a valid,
  /// non-identity point on [domain]'s curve. Returns null (reject) on any
  /// malformation instead of throwing.
  ECPoint? _tryDecodeValidPoint(ECDomainParameters domain, Uint8List q) {
    final fieldBytes = (domain.curve.fieldSize + 7) ~/ 8;
    if (q.length != 1 + 2 * fieldBytes || q[0] != 0x04) return null;
    final ECPoint? point;
    try {
      point = domain.curve.decodePoint(q);
    } catch (_) {
      return null;
    }
    if (point == null || point.isInfinity) return null;
    // On-curve check: y^2 == x^3 + a*x + b over the curve's prime field.
    final x = point.x!;
    final y = point.y!;
    final lhs = (y * y).toBigInteger();
    final rhs = (((x * x) * x) + (domain.curve.a! * x) + domain.curve.b!)
        .toBigInteger();
    if (lhs != rhs) return null;
    return point;
  }

  ECDomainParameters get curve {
    switch (curveId) {
      case 'nistp256':
        return ECCurve_secp256r1();
      case 'nistp384':
        return ECCurve_secp384r1();
      case 'nistp521':
        return ECCurve_secp521r1();
      default:
        throw Exception('Unsupported curve: $curveId');
    }
  }

  Digest get curveHash {
    switch (curveId) {
      case 'nistp256':
        return SHA256Digest();
      case 'nistp384':
        return SHA384Digest();
      case 'nistp521':
        return SHA512Digest();
      default:
        throw Exception('Unsupported curve: $curveId');
    }
  }

  @override
  String toString() {
    return 'SSHEcdsaKey(type: $type, curveId: $curveId, q: ${hex.encode(q)})';
  }
}

class SSHEcdsaSignature implements SSHSignature {
  final String type;

  final BigInt r;

  final BigInt s;

  SSHEcdsaSignature(this.type, this.r, this.s);

  factory SSHEcdsaSignature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (!type.startsWith('ecdsa-sha2-')) {
      throw FormatException('Invalid signature type: $type');
    }
    final blobReader = SSHMessageReader(reader.readString());
    final r = blobReader.readMpint();
    final s = blobReader.readMpint();
    return SSHEcdsaSignature(type, r, s);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    final blobWriter = SSHMessageWriter();
    blobWriter.writeMpint(r);
    blobWriter.writeMpint(s);
    writer.writeString(blobWriter.takeBytes());
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSHEcdsaSignature($type)';
  }
}
