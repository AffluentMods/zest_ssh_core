// SPDX-License-Identifier: MIT
import 'package:zest_ssh_core/src/algorithm/ssh_cipher_type.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_hostkey_type.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_kex_type.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_mac_type.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart' show SSHRsaSignatureType;

abstract class SSHAlgorithm {
  /// The name of the algorithm.
  String get name;

  const SSHAlgorithm();

  /// What this kind of algorithm is called in code, spelled out by each
  /// kind and not asked of the program (`runtimeType`): a program that is
  /// built with its names obfuscated, as a released app most often is, has
  /// another name for nearly every type, and the client's debug lines
  /// print the algorithms a connection agreed on. A kind that spells no
  /// name out is an "SSHAlgorithm".
  String get typeName => 'SSHAlgorithm';

  @override
  String toString() {
    return '$typeName($name)';
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

  /// The kinds of signature an RSA key of the client's own may sign in
  /// with ([SSHRsaSignatureType]), the one it would rather make first. A
  /// server is asked about the first of them that it says it takes (RFC
  /// 8332, 3.3).
  ///
  /// The first kind, with SHA-1 ("ssh-rsa"), is not among them unless it is
  /// put there: SHA-1 no longer holds against a forged signature, and a
  /// current server refuses it. An OpenSSH server older than 7.2 (2016)
  /// knows no other.
  final List<String> rsaSignatures;

  /// The shortest RSA host key that is taken, by its modulus, in bits. A
  /// server that shows a shorter one is not connected to
  /// (`SSHHostkeyFault.tooShort`), before anything is computed with the
  /// key and before anybody is asked about it: such a key can be worked
  /// out by whoever has the means, who can then answer in the server's
  /// place. 2048 where nothing is said: NIST's floor for RSA until 2030
  /// (SP 800-131A), where OpenSSH still takes 1024. 1024 takes what
  /// OpenSSH takes; 0 takes a key of any length, for an old device that
  /// has no other, where whoever connects to it has said so.
  final int minRsaHostKeyBits;

  /// The shortest Diffie-Hellman group that is asked for in a group
  /// exchange, and taken, in bits (`SSHKexDH.requireGroupOfAnExchange`).
  /// 2048 where nothing is said (`SSHKexDH.gexMin`), which is what OpenSSH
  /// takes: a group of 1024 bits can be broken by whoever has the means,
  /// and with it everything that was recorded of the sessions under it.
  /// 1024 (`SSHKexDH.gexMinOldServers`) is for an old server whose SSH
  /// server has no longer group and cannot be updated, where whoever
  /// connects to it has said so. Nothing under 1024 is ever asked for or
  /// taken, whatever is said here.
  final int minDhGroupBits;

  const SSHAlgorithms({
    this.kex = const [
      // Post-quantum hybrid first: an OpenSSH 9.9+ server picks it, an
      // older server simply does not list it and we fall through.
      SSHKexType.mlkem768x25519,
      SSHKexType.sntrup761x25519,
      SSHKexType.sntrup761x25519OpenSSH,
      SSHKexType.x25519,
      SSHKexType.x25519Iana,
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
      // AES-GCM, after everything that was offered before it. The first
      // name of the client's list that the server has as well is the one
      // agreed on (RFC 4253, 7.1), so a server that has any of the three
      // above is connected to exactly as before, and these two are agreed
      // on only with a server that has none of them: one set to GCM
      // ciphers alone, as some hardened servers are, which could not be
      // connected to at all while they were not offered.
      SSHCipherType.aes256gcm,
      SSHCipherType.aes128gcm,
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
    this.rsaSignatures = const [
      SSHRsaSignatureType.sha512,
      SSHRsaSignatureType.sha256,
    ],
    this.minRsaHostKeyBits = 2048,
    this.minDhGroupBits = 2048,
  });
}
