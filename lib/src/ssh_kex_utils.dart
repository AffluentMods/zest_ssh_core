import 'dart:typed_data';

import 'package:zest_ssh_core/src/kex/kex_dh.dart';
import 'package:zest_ssh_core/src/ssh_algorithm.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:pointycastle/export.dart';

abstract class SSHKexUtils {
  /// The first algorithm on the client's name-list and is also supported by the
  /// server must be chosen. (rfc4253, section 7.1)
  static T? selectAlgorithm<T extends SSHAlgorithm>({
    required List<T> localAlgorithms,
    required List<String> remoteAlgorithms,
    required bool isServer,
  }) {
    if (isServer) {
      for (final clientAlgorithm in remoteAlgorithms) {
        final serverAlgorithm = localAlgorithms.getByName(clientAlgorithm);
        if (serverAlgorithm != null) {
          return serverAlgorithm;
        }
      }
    } else {
      for (final clientAlgorithm in localAlgorithms) {
        if (remoteAlgorithms.contains(clientAlgorithm.name)) {
          return clientAlgorithm;
        }
      }
    }
    return null;
  }

  static Uint8List computeExchangeHash({
    required Digest digest,
    SSHKexDH? groupExchange,
    required String clientVersion,
    required String serverVersion,
    required Uint8List clientKexInit,
    required Uint8List serverKexInit,
    required Uint8List hostKey,
    required Uint8List clientPublicKey,
    required Uint8List serverPublicKey,
    required Uint8List sharedSecret,
  }) {
    final writer = SSHMessageWriter();
    writer.writeUtf8(clientVersion);
    writer.writeUtf8(serverVersion);
    writer.writeString(clientKexInit);
    writer.writeString(serverKexInit);
    writer.writeString(hostKey);

    if (groupExchange != null) {
      writer.writeUint32(SSHKexDH.gexMin);
      writer.writeUint32(SSHKexDH.gexPref);
      writer.writeUint32(SSHKexDH.gexMax);
      writer.writeMpint(groupExchange.p);
      writer.writeMpint(groupExchange.g);
    }

    writer.writeString(clientPublicKey);
    writer.writeString(serverPublicKey);
    // Already encoded: `mpint K` for the classic exchanges, `string K` for
    // the hybrid post-quantum ones (see encodeSharedSecretMpint / String).
    writer.writeBytes(sharedSecret);

    final message = writer.takeBytes();
    digest.update(message, 0, message.length);
    final result = Uint8List(digest.digestSize);
    digest.doFinal(result, 0);
    return result;
  }

  /// The wire encoding of a classic (DH / ECDH) shared secret: `mpint K`.
  static Uint8List encodeSharedSecretMpint(BigInt k) {
    final writer = SSHMessageWriter();
    writer.writeMpint(k);
    return writer.takeBytes();
  }

  /// The wire encoding of a hybrid post-quantum shared secret: `string K`
  /// (the hash output), as OpenSSH's kex-sntrup761x25519 / mlkem768x25519
  /// put it in the exchange hash and the key derivation.
  static Uint8List encodeSharedSecretString(Uint8List k) {
    final writer = SSHMessageWriter();
    writer.writeString(k);
    return writer.takeBytes();
  }

  /// Derive various keys from the exchange hash. [sharedSecret] is the
  /// wire-encoded secret (see [encodeSharedSecretMpint]).
  static Uint8List deriveKey({
    required Digest digest,
    required Uint8List sharedSecret,
    required Uint8List exchangeHash,
    required SSHDeriveKeyType keyType,
    required Uint8List sessionId,
    required int keySize,
  }) {
    final result = BytesBuilder(copy: false);

    while (result.length < keySize) {
      final writer = SSHMessageWriter();
      writer.writeBytes(sharedSecret);
      writer.writeBytes(exchangeHash);
      if (result.isEmpty) {
        writer.writeUint8(keyType.magicChar);
        writer.writeBytes(sessionId);
      } else {
        writer.writeBytes(result.toBytes());
      }

      final dataToHash = writer.takeBytes();
      // final digester = SHA256Digest();
      digest.update(dataToHash, 0, dataToHash.length);
      final hash = Uint8List(digest.digestSize);
      digest.doFinal(hash, 0);
      result.add(hash);
    }

    return Uint8List.sublistView(result.takeBytes(), 0, keySize);
  }
}

enum SSHDeriveKeyType {
  clientIV,
  serverIV,
  clientKey,
  serverKey,
  clientMacKey,
  serverMacKey,
}

extension SSHDeriveKeyTypeX on SSHDeriveKeyType {
  /// The magic character used in ke derivation.
  int get magicChar {
    switch (this) {
      case SSHDeriveKeyType.clientIV:
        return 'A'.codeUnits.first;
      case SSHDeriveKeyType.serverIV:
        return 'B'.codeUnits.first;
      case SSHDeriveKeyType.clientKey:
        return 'C'.codeUnits.first;
      case SSHDeriveKeyType.serverKey:
        return 'D'.codeUnits.first;
      case SSHDeriveKeyType.clientMacKey:
        return 'E'.codeUnits.first;
      case SSHDeriveKeyType.serverMacKey:
        return 'F'.codeUnits.first;
    }
  }
}
