import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';
import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
import 'package:zest_ssh_core/src/kex/mlkem768.dart';
import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_kex.dart';
import 'package:zest_ssh_core/src/utils/list.dart';

/// `mlkem768x25519-sha256`: the hybrid post-quantum key exchange OpenSSH
/// 9.9+ negotiates by default (draft-ietf-sshm-mlkem-hybrid-kex). Both a
/// classical X25519 exchange and an ML-KEM-768 encapsulation run inside the
/// ordinary ECDH_INIT / ECDH_REPLY messages; the session is only as weak as
/// the STRONGER of the two, so a future quantum computer that breaks X25519
/// still cannot recover a recorded session.
///
/// Wire format (client side):
///   C_INIT  = ML-KEM-768 encapsulation key (1184) || X25519 public (32)
///   S_REPLY = ML-KEM-768 ciphertext (1088)        || X25519 public (32)
///   K       = SHA-256(K_PQ || K_CL), encoded as an SSH `string`
class SSHKexMlKem768X25519 implements SSHKexHybrid {
  static const int initSize =
      MlKem768.encapsulationKeySize + X25519.keyLength; // 1216
  static const int replySize =
      MlKem768.ciphertextSize + X25519.keyLength; // 1120

  late final Uint8List _decapsulationKey;
  late final Uint8List _x25519PrivateKey;

  @override
  late final Uint8List publicKey;

  SSHKexMlKem768X25519() {
    final kem = MlKem768.keyGen(randomBytes);
    _decapsulationKey = kem.dk;
    _x25519PrivateKey = randomBytes(X25519.keyLength);
    final x25519Public = X25519.scalarMultBase(_x25519PrivateKey);
    final blob = Uint8List(initSize);
    blob.setRange(0, MlKem768.encapsulationKeySize, kem.ek);
    blob.setRange(MlKem768.encapsulationKeySize, initSize, x25519Public);
    publicKey = blob;
  }

  @override
  Uint8List computeSharedSecret(Uint8List serverReply) {
    if (serverReply.length != replySize) {
      throw SSHHandshakeError(
          'mlkem768x25519 reply must be $replySize bytes, got ${serverReply.length}');
    }
    final ciphertext =
        Uint8List.sublistView(serverReply, 0, MlKem768.ciphertextSize);
    final serverX25519 =
        Uint8List.sublistView(serverReply, MlKem768.ciphertextSize, replySize);
    // ML-KEM never fails on a bad ciphertext (implicit rejection gives an
    // unrelated secret and the exchange-hash signature then fails), while
    // a low-order X25519 point is refused outright.
    final kPq = MlKem768.decaps(_decapsulationKey, ciphertext);
    final kCl = X25519.sharedSecret(_x25519PrivateKey, serverX25519);
    final digest = SHA256Digest();
    digest.update(kPq, 0, kPq.length);
    digest.update(kCl, 0, kCl.length);
    final out = Uint8List(digest.digestSize);
    digest.doFinal(out, 0);
    return out;
  }
}
