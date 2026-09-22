import 'package:zest_ssh_core/src/ssh_algorithm.dart';
import 'package:pointycastle/export.dart';

class SSHKexType extends SSHAlgorithm {
  /// Hybrid ML-KEM-768 + X25519 (OpenSSH 9.9+ default). Post-quantum.
  static const mlkem768x25519 = SSHKexType._(
    name: 'mlkem768x25519-sha256',
    digestFactory: digestSha256,
    isHybridPostQuantum: true,
  );

  /// Hybrid Streamlined NTRU Prime 761 + X25519 (OpenSSH 9.0 to 9.8
  /// default, still offered by 10.x). Post-quantum.
  static const sntrup761x25519 = SSHKexType._(
    name: 'sntrup761x25519-sha512',
    digestFactory: digestSha512,
    isHybridPostQuantum: true,
  );

  /// The original vendor spelling of the same exchange (OpenSSH 8.5+).
  static const sntrup761x25519OpenSSH = SSHKexType._(
    name: 'sntrup761x25519-sha512@openssh.com',
    digestFactory: digestSha512,
    isHybridPostQuantum: true,
  );

  static const x25519 = SSHKexType._(
    name: 'curve25519-sha256@libssh.org',
    digestFactory: digestSha256,
  );

  /// The IANA name of the same exchange (RFC 8731).
  static const x25519Iana = SSHKexType._(
    name: 'curve25519-sha256',
    digestFactory: digestSha256,
  );

  static const nistp256 = SSHKexType._(
    name: 'ecdh-sha2-nistp256',
    digestFactory: digestSha256,
  );

  static const nistp384 = SSHKexType._(
    name: 'ecdh-sha2-nistp384',
    digestFactory: digestSha384,
  );

  static const nistp521 = SSHKexType._(
    name: 'ecdh-sha2-nistp521',
    digestFactory: digestSha512,
  );

  static const dhGexSha256 = SSHKexType._(
    name: 'diffie-hellman-group-exchange-sha256',
    digestFactory: digestSha256,
    isGroupExchange: true,
  );

  static const dhGexSha1 = SSHKexType._(
    name: 'diffie-hellman-group-exchange-sha1',
    digestFactory: digestSha1,
    isGroupExchange: true,
  );

  static const dh14Sha1 = SSHKexType._(
    name: 'diffie-hellman-group14-sha1',
    digestFactory: digestSha1,
  );

  static const dh14Sha256 = SSHKexType._(
    name: 'diffie-hellman-group14-sha256',
    digestFactory: digestSha256,
  );

  static const dh1Sha1 = SSHKexType._(
    name: 'diffie-hellman-group1-sha1',
    digestFactory: digestSha1,
  );

  const SSHKexType._({
    required this.name,
    required this.digestFactory,
    this.isGroupExchange = false,
    this.isHybridPostQuantum = false,
  });

  /// The name of the algorithm. For example, `"ecdh-sha2-nistp256"`.
  @override
  final String name;

  final Digest Function() digestFactory;

  final bool isGroupExchange;

  /// True for the hybrid exchanges that combine a post-quantum KEM with
  /// X25519, so a recorded session cannot be decrypted by a future quantum
  /// computer. Surfaced to the app for its connection details.
  final bool isHybridPostQuantum;

  /// Whether a negotiated exchange name (as reported in the diagnostics) is
  /// one of the post-quantum hybrids. For UI badges.
  static bool isPostQuantumName(String name) =>
      name == mlkem768x25519.name ||
      name == sntrup761x25519.name ||
      name == sntrup761x25519OpenSSH.name;

  Digest createDigest() => digestFactory();
}

Digest digestSha1() => SHA1Digest();
Digest digestSha256() => SHA256Digest();
Digest digestSha384() => SHA384Digest();
Digest digestSha512() => SHA512Digest();
