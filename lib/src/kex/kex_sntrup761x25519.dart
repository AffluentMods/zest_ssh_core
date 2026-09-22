import 'dart:typed_data';

import 'package:pointycastle/digests/sha512.dart';
import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
import 'package:zest_ssh_core/src/kex/sntrup761.dart';
import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_kex.dart';
import 'package:zest_ssh_core/src/utils/list.dart';

/// `sntrup761x25519-sha512` (and its `@openssh.com` spelling): the hybrid
/// post-quantum exchange OpenSSH has offered since 8.5 and negotiated by
/// default from 9.0 to 9.8, so it is what an Ubuntu 24.04 or Debian 12
/// server still picks. Streamlined NTRU Prime 761 plus X25519, in the
/// ordinary ECDH_INIT / ECDH_REPLY messages.
///
/// Wire format (client side):
///   C_INIT  = sntrup761 public key (1158) || X25519 public (32)
///   S_REPLY = sntrup761 ciphertext (1039) || X25519 public (32)
///   K       = SHA-512(K_PQ || K_CL), encoded as an SSH `string`
class SSHKexSntrup761X25519 implements SSHKexHybrid {
  static const int initSize = Sntrup761.publicKeySize + X25519.keyLength; // 1190
  static const int replySize =
      Sntrup761.ciphertextSize + X25519.keyLength; // 1071

  late final Uint8List _secretKey;
  late final Uint8List _x25519PrivateKey;

  @override
  late final Uint8List publicKey;

  SSHKexSntrup761X25519() {
    final kem = Sntrup761.keyPair(randomBytes);
    _secretKey = kem.sk;
    _x25519PrivateKey = randomBytes(X25519.keyLength);
    final x25519Public = X25519.scalarMultBase(_x25519PrivateKey);
    final blob = Uint8List(initSize);
    blob.setRange(0, Sntrup761.publicKeySize, kem.pk);
    blob.setRange(Sntrup761.publicKeySize, initSize, x25519Public);
    publicKey = blob;
  }

  @override
  Uint8List computeSharedSecret(Uint8List serverReply) {
    if (serverReply.length != replySize) {
      throw SSHHandshakeError(
          'sntrup761x25519 reply must be $replySize bytes, got ${serverReply.length}');
    }
    final ciphertext =
        Uint8List.sublistView(serverReply, 0, Sntrup761.ciphertextSize);
    final serverX25519 = Uint8List.sublistView(
        serverReply, Sntrup761.ciphertextSize, replySize);
    final kPq = Sntrup761.decaps(_secretKey, ciphertext);
    final kCl = X25519.sharedSecret(_x25519PrivateKey, serverX25519);
    final digest = SHA512Digest();
    digest.update(kPq, 0, kPq.length);
    digest.update(kCl, 0, kCl.length);
    final out = Uint8List(digest.digestSize);
    digest.doFinal(out, 0);
    return out;
  }
}
