import 'dart:typed_data';

/// Interface for a class that implements key exchange logic.
abstract class SSHKex {}

/// Interface for a class that implements ECDH key exchange.
abstract class SSHKexECDH implements SSHKex {
  /// Public key computed from the private key.
  Uint8List get publicKey;

  BigInt computeSecret(Uint8List remotePublicKey);
}

/// A hybrid post-quantum key exchange (mlkem768x25519, sntrup761x25519):
/// the client sends ONE blob (KEM public key || X25519 public key) in
/// ECDH_INIT, the server answers with ONE blob (KEM ciphertext || X25519
/// public key) in ECDH_REPLY, and the shared secret is a hash of both
/// secrets. Unlike every classic exchange, that secret goes into the
/// exchange hash and the key derivation as an SSH `string`, not an `mpint`.
abstract class SSHKexHybrid implements SSHKex {
  /// The client's blob for ECDH_INIT.
  Uint8List get publicKey;

  /// The hashed shared secret for the server's ECDH_REPLY blob.
  Uint8List computeSharedSecret(Uint8List serverReply);
}
