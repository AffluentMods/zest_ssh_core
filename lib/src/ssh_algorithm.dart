import 'package:zest_ssh_core/src/algorithm/ssh_cipher_type.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_hostkey_type.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_kex_type.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_mac_type.dart';

abstract class SSHAlgorithm {
  /// The name of the algorithm.
  String get name;

  const SSHAlgorithm();

  @override
  String toString() {
    return '$runtimeType($name)';
  }
}

extension SSHAlgorithmList<T extends SSHAlgorithm> on List<T> {
  List<String> toNameList() {
    return map((algorithm) => algorithm.name).toList();
  }

  T? getByName(String name) {
    for (var algorithm in this) {
      if (algorithm.name == name) {
        return algorithm;
      }
    }
    return null;
  }
}

class SSHAlgorithms {
  /// Algorithm used for the key exchange.
  final List<SSHKexType> kex;

  /// Algorithm used for the host key.
  final List<SSHHostkeyType> hostkey;

  /// Algorithm used for the encryption.
  final List<SSHCipherType> cipher;

  /// Algorithm used for the authentication.
  final List<SSHMacType> mac;

  const SSHAlgorithms({
    this.kex = const [
      SSHKexType.x25519,
      SSHKexType.nistp521,
      SSHKexType.nistp384,
      SSHKexType.nistp256,
      SSHKexType.dhGexSha256,
      SSHKexType.dh14Sha256,
      // SHA-1 key exchanges (dh14Sha1, dhGexSha1) removed from defaults -
      // SHA-1 is collision-broken, so the strong defaults must not be
      // negotiable down to it. Opt-in only via the compatibility profile
      // (custom SSHAlgorithms). dh1Sha1 (1024-bit DH Group 1) likewise
      // excluded.
    ],
    this.hostkey = const [
      SSHHostkeyType.ed25519,
      SSHHostkeyType.rsaSha512,
      SSHHostkeyType.rsaSha256,
      // rsaSha1 (ssh-rsa, SHA-1 signatures) removed from defaults - a
      // downgrade to SHA-1 host-key signatures must be opt-in only via the
      // compatibility profile, not offered to every server by default.
      SSHHostkeyType.ecdsa521,
      SSHHostkeyType.ecdsa384,
      SSHHostkeyType.ecdsa256,
      // Ed448 not offered by default until sign_dart is vetted
      // SSHHostkeyType.ed448,
    ],
    this.cipher = const [
      SSHCipherType.chacha20poly1305,
      // Prefer the 256-bit key over the 128-bit one when a server offers
      // both - a security-forward client should negotiate the stronger
      // cipher first.
      SSHCipherType.aes256ctr,
      SSHCipherType.aes128ctr,
      // CBC mode ciphers removed from defaults - CVE-2008-5161 plaintext
      // recovery when not paired with ETM MACs. Opt-in via custom
      // SSHAlgorithms if required for legacy servers.
    ],
    this.mac = const [
      // ETM (Encrypt-Then-MAC) variants are strongest -- prefer them.
      SSHMacType.hmacSha512Etm,
      SSHMacType.hmacSha256Etm,
      // Full-length HMAC variants next.
      SSHMacType.hmacSha512,
      SSHMacType.hmacSha256,
      SSHMacType.hmacSha1,
      // Truncated 96-bit MACs are weaker -- list last.
      SSHMacType.hmacSha512_96,
      SSHMacType.hmacSha256_96,
      // hmac-md5 removed from defaults - MD5 is deprecated.
      // Opt-in via custom SSHAlgorithms if required for legacy servers.
    ],
  });
}
