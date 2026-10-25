import 'package:convert/convert.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:pinenacl/ed25519.dart';

class SSHEd25519PublicKey implements SSHHostKey {
  static const type = 'ssh-ed25519';

  final Uint8List key;

  SSHEd25519PublicKey(this.key);

  factory SSHEd25519PublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHEd25519PublicKey.type) {
      throw Exception('Invalid key type: $type');
    }
    final key = reader.readString();
    if (key.length != 32) {
      throw FormatException(
        'Invalid Ed25519 public key size: ${key.length} bytes (expected 32)',
      );
    }
    return SSHEd25519PublicKey(key);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeString(key);
    return writer.takeBytes();
  }

  /// Whether [signature] is this key's own signature of [message].
  ///
  /// False for one that is not, of whatever length. (The library that
  /// checks it says so by throwing, and never answers no: a signature that
  /// did not fit ended a connection as a packet that could not be read, and
  /// not as a host key that had not signed.)
  bool verify(Uint8List message, SSHEd25519Signature signature) {
    try {
      return VerifyKey(key).verify(
        signature: Signature(signature.signature),
        message: message,
      );
    } on Exception {
      return false;
    }
  }

  @override
  String toString() {
    return 'SSHEd25519Key(${hex.encode(key)})';
  }
}

class SSHEd25519Signature implements SSHSignature {
  static const type = 'ssh-ed25519';

  final Uint8List signature;

  SSHEd25519Signature(this.signature);

  factory SSHEd25519Signature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHEd25519Signature.type) {
      throw Exception('Invalid signature type: $type');
    }
    final signature = reader.readString();
    return SSHEd25519Signature(signature);
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
    return 'SSHEd25519Signature(${hex.encode(signature)})';
  }
}
