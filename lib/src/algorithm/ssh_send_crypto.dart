// SPDX-License-Identifier: MIT
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'ssh_cipher_chacha20_poly1305.dart';

/// Pure, isolate-safe SSH send-side packet encryption.
///
/// These are the exact crypto steps from `SSHTransport._sendChaChaPacket` and
/// `_sendAeadPacket`, extracted so the inline (main-isolate) path and the
/// background crypto worker call the SAME function. Byte-identical output is
/// therefore structural, not merely hoped-for. Both are pure functions of their
/// arguments: ChaCha20-Poly1305 and AES-GCM rebuild a fresh engine per call and
/// derive their nonce solely from the sequence number, so no state survives a
/// packet and they run correctly on any isolate given the key and the sequence.
///
/// What a packet's nonce follows from stays owned by the transport on the main
/// isolate and is passed in explicitly per packet: for ChaCha the number of the
/// packet, which IS the nonce, and for GCM how many packets its keys have
/// protected before it. A second owner of either would risk nonce reuse.

/// Encrypts one ChaCha20-Poly1305 (`chacha20-poly1305@openssh.com`) packet.
///
/// [key] is the 64-byte send key, [plaintext] is `padLen||payload||padding`,
/// [packetLength] is `plaintext.length`, and [seq] is the packet sequence
/// number (also the nonce). Returns the on-the-wire bytes:
/// `encrypted_length(4) || encrypted_payload || Poly1305 tag(16)`.
Uint8List encryptChaChaPacket(
  Uint8List key,
  int seq,
  Uint8List plaintext,
  int packetLength,
) {
  return SSHCipherChaCha20Poly1305(key: key)
      .encrypt(plaintext, packetLength, seq);
}

/// Encrypts one AES-GCM AEAD packet.
///
/// [key] is 16/32 bytes, [iv] is the 12-byte AEAD IV, [packetsBefore] is how
/// many packets these keys have protected before this one (see
/// [sshAeadNonceForSequence]), [aad] is the 4-byte cleartext packet length, and
/// [plaintext] is `padLen||payload||padding`. Returns
/// `aad(4) || GCM ciphertext || GCM tag(16)`.
Uint8List encryptGcmPacket(
  Uint8List key,
  Uint8List iv,
  int packetsBefore,
  Uint8List aad,
  Uint8List plaintext,
) {
  final cipher = GCMBlockCipher(AESEngine());
  cipher.init(
    true,
    AEADParameters(
        KeyParameter(key), 128, sshAeadNonceForSequence(iv, packetsBefore), aad),
  );
  final ct = cipher.process(plaintext);
  return (BytesBuilder(copy: false)
        ..add(aad)
        ..add(ct))
      .takeBytes();
}

/// Derives the AES-GCM nonce of a packet from the 12-byte [iv] its keys give:
/// the low 64 bits are counted on by [packetsBefore], the number of packets
/// those keys have protected before it (RFC 5647, 7.1: the count starts at the
/// IV and goes on by one with every packet). That is NOT the number of the
/// packet, which goes on across new keys unless the strict key exchange is in
/// force: only there are the two the same. Pure function.
Uint8List sshAeadNonceForSequence(Uint8List iv, int packetsBefore) {
  if (iv.length != 12) {
    throw ArgumentError.value(iv, 'iv', 'AEAD IV must be 12 bytes long');
  }
  final nonce = Uint8List.fromList(iv);
  final view = ByteData.sublistView(nonce);
  final counter = view.getUint64(4);
  view.setUint64(4, counter + packetsBefore);
  return nonce;
}
