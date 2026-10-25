import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

import 'package:pinenacl/ed25519.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

import '../utils/bigint.dart';

/// The signature of [data] by the RSA key of these numbers, of the kind
/// [type] ([SSHRsaSignatureType]): made, and given out only once it has
/// been checked with the key's public half ([SSHRsaPublicKey.verify]).
///
/// An RSA key signs in two halves, one for each of its primes [p] and [q].
/// A signature of which one half is wrong gives one of the primes away to
/// whoever sees it and knows what was signed, and a server sees every
/// signature a client signs in with. So a signature that is not the key's
/// own never leaves here: an [SSHKeySignError] says so, and so it does
/// where the numbers of the key do not fit each other in the first place.
SSHRsaSignature signRsaChecked({
  required BigInt n,
  required BigInt e,
  required BigInt d,
  required BigInt p,
  required BigInt q,
  required Uint8List data,
  required String type,
}) {
  final RSASigner signer;
  switch (type) {
    case SSHRsaSignatureType.sha1:
      signer = RSASigner(SHA1Digest(), '06052b0e03021a');
    case SSHRsaSignatureType.sha256:
      signer = RSASigner(SHA256Digest(), '0609608648016503040201');
    case SSHRsaSignatureType.sha512:
      signer = RSASigner(SHA512Digest(), '0609608648016503040203');
    default:
      throw FormatException('Unknown signature type: $type');
  }
  final asymmetric.RSAPrivateKey key;
  try {
    key = asymmetric.RSAPrivateKey(n, d, p, q);
  } on ArgumentError {
    throw SSHKeySignError(
      'The numbers of this RSA key do not fit each other: nothing was '
      'signed with it',
    );
  }
  final SSHRsaSignature signature;
  try {
    signer.init(true, PrivateKeyParameter<asymmetric.RSAPrivateKey>(key));
    signature = SSHRsaSignature(type, signer.generateSignature(data).bytes);
  } on ArgumentError {
    // (What the library that signs says of a key that cannot hold the hash
    // with what goes before it.)
    throw SSHKeySignError(
      'This RSA key is too short for a signature of the kind $type '
      '(${n.bitLength} bits): nothing was signed with it',
    );
  }
  if (!SSHRsaPublicKey(e, n).verify(data, signature)) {
    throw SSHKeySignError(
      'The signature this RSA key made is not its own, and was not given '
      'out: the numbers of the key do not fit each other, or it was '
      'computed wrongly',
    );
  }
  return signature;
}

class SSHRsaPublicKey implements SSHHostKey {
  static const type = 'ssh-rsa';

  final BigInt e;

  final BigInt n;

  SSHRsaPublicKey(this.e, this.n);

  factory SSHRsaPublicKey.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    if (type != SSHRsaPublicKey.type) {
      throw Exception('Invalid key type: $type');
    }
    final e = reader.readMpint();
    final n = reader.readMpint();
    return SSHRsaPublicKey(e, n);
  }

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUtf8(type);
    writer.writeMpint(e);
    writer.writeMpint(n);
    return writer.takeBytes();
  }

  /// Whether [signature] is this key's signature of [message]
  /// (RSASSA-PKCS1-v1_5, RFC 8017, 8.2.2).
  ///
  /// What the signature comes back to under the key is compared, byte for
  /// byte, with the one thing it has to come back to: nothing of it is
  /// read as a structure, so there is nothing a made-up signature could
  /// put where it is not looked at. It is computed with the package's own
  /// arithmetic ([modPowExact]): the signature is the other side's to pick,
  /// and `BigInt.modPow` answers wrong for numbers that are picked for it.
  ///
  /// A key that is too short to hold a signature of the kind asked for, and
  /// a kind that is none, are a [FormatException]: no signature could be
  /// such a key's.
  bool verify(Uint8List message, SSHRsaSignature signature) {
    final Digest digest;
    final List<int> digestInfo;
    switch (signature.type) {
      case SSHRsaSignatureType.sha1:
        digest = SHA1Digest();
        digestInfo = _sha1DigestInfo;
      case SSHRsaSignatureType.sha256:
        digest = SHA256Digest();
        digestInfo = _sha256DigestInfo;
      case SSHRsaSignatureType.sha512:
        digest = SHA512Digest();
        digestInfo = _sha512DigestInfo;
      default:
        throw FormatException('Unknown signature type: ${signature.type}');
    }
    final expected = _encoded([...digestInfo, ...digest.process(message)]);
    final bytes = signature.signature;
    // A signature is as long as the modulus. One that is shorter is read
    // as it is, as OpenSSH reads it (some servers leave out noughts in
    // front); one that is longer is no signature of this key.
    if (bytes.length > expected.length) return false;
    final s = decodeBigIntWithSign(1, bytes);
    if (s >= n) return false;
    // (What it comes back to is less than the modulus, so no longer.)
    final back = encodeBigIntAsUnsigned(modPowExact(s, e, n));
    final front = expected.length - back.length;
    var differs = 0;
    for (var i = 0; i < expected.length; i++) {
      differs |= expected[i] ^ (i < front ? 0 : back[i - front]);
    }
    return differs == 0;
  }

  /// What a signature of this key has to come back to for the hash that
  /// [hashWithItsName] ends with, as long as the key's modulus: a nought, a
  /// one, bytes of 0xff (eight at the least), a nought, and the hash under
  /// the name of its kind (RFC 8017, 9.2).
  Uint8List _encoded(List<int> hashWithItsName) {
    final length = (n.bitLength + 7) ~/ 8;
    final padding = length - 3 - hashWithItsName.length;
    if (padding < 8) {
      throw FormatException(
        'The RSA key is too short to hold a signature of this kind: '
        '${n.bitLength} bits',
      );
    }
    return Uint8List.fromList([0, 1, ...List.filled(padding, 0xff), 0, ...hashWithItsName]);
  }

  // The names of the three kinds of hash, as they stand before the hash in
  // a signature (the DigestInfo of RFC 8017, 9.2, note 1).
  static const _sha1DigestInfo = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14, //
  ];
  static const _sha256DigestInfo = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, //
  ];
  static const _sha512DigestInfo = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40, //
  ];

  @override
  String toString() {
    return 'SSHRsaKey($type, n: $n, e: $e)';
  }
}

/// The kinds of RSA signature, by the names they are asked for and sent
/// under (RFC 8332): one key makes all three.
abstract class SSHRsaSignatureType {
  /// With SHA-1: the first kind, which a current server no longer takes.
  static const sha1 = 'ssh-rsa';
  static const sha256 = 'rsa-sha2-256';
  static const sha512 = 'rsa-sha2-512';

  /// The three, the strongest first.
  static const all = [sha512, sha256, sha1];

  /// [type], where it is one of the three; an [ArgumentError] where not.
  static String known(String type) =>
      all.contains(type) ? type : throw ArgumentError.value(type, 'type', 'no kind of RSA signature');
}

class SSHRsaSignature implements SSHSignature {
  final String type;

  final Uint8List signature;

  SSHRsaSignature(this.type, this.signature);

  factory SSHRsaSignature.decode(Uint8List data) {
    final reader = SSHMessageReader(data);
    final type = reader.readUtf8();
    final signature = reader.readString();
    return SSHRsaSignature(type, signature);
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
    return 'SSHRsaSignature(${hex.encode(signature)})';
  }
}
