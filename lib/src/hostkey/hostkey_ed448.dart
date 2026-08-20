import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
// WARNING: sign_dart is an unvetted third-party dependency used for Ed448
// operations. It has not undergone a formal security audit. All inputs and
// outputs are validated at the call-site to mitigate risks from potential
// implementation flaws.
import 'package:sign_dart/sign_dart.dart';

class SSHEd448PublicKey implements SSHHostKey {
  static const type = 'ssh-ed448';

  /// 57-byte Ed448 public key.
  final Uint8List key;

  SSHEd448PublicKey(this.key);

  factory SSHEd448PublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHEd448PublicKey.type) {
      throw Exception('Invalid key type: $type');
    }
    final key = reader.readString();
    if (key.length != 57) {
      throw FormatException(
        'Invalid Ed448 public key size: ${key.length} bytes (expected 57)',
      );
    }
    return SSHEd448PublicKey(key);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeString(key);
    return writer.takeBytes();
  }

  /// Verifies Ed448 [signature] on [message] using this public key.
  bool verify(Uint8List message, SSHEd448Signature signature) {
    final curve = TwistedEdwardCurve.ed448();
    final verifier = EdPublicKey.fromBytes(key, curve);
    return verifier.verify(message, signature.signature);
  }

  @override
  String toString() {
    return 'SSHEd448Key(${hex.encode(key)})';
  }
}

class SSHEd448Signature implements SSHSignature {
  static const type = 'ssh-ed448';

  /// 114-byte Ed448 signature.
  final Uint8List signature;

  SSHEd448Signature(this.signature);

  factory SSHEd448Signature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHEd448Signature.type) {
      throw Exception('Invalid signature type: $type');
    }
    final signature = reader.readString();
    if (signature.length != 114) {
      throw FormatException(
        'Invalid Ed448 signature size: ${signature.length} bytes (expected 114)',
      );
    }
    return SSHEd448Signature(signature);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeString(signature);
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSHEd448Signature(${hex.encode(signature)})';
  }
}
