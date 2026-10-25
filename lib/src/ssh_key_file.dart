import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/algorithm/ssh_cipher_type.dart';
import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_key_pair.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:zest_ssh_core/src/ssh_pem.dart';
import 'package:zest_ssh_core/src/utils/bcrypt.dart';
import 'package:zest_ssh_core/src/utils/cipher_ext.dart';

/// What an OpenSSH private key file holds, with its private part in the
/// clear: the public key of each key in it, and [body], the private part as
/// the file's format lays it out (two equal check numbers, then each key's
/// type, its numbers and its comment), without the padding that rounds it up
/// to the cipher's block.
class OpenSSHKeyFileParts {
  OpenSSHKeyFileParts({required this.publicKeys, required this.body});

  final List<Uint8List> publicKeys;
  final Uint8List body;
}

/// Writes private keys in OpenSSH's own file format (`openssh-key-v1`, the
/// `BEGIN OPENSSH PRIVATE KEY` file), sealed under a passphrase or not, as
/// ssh-keygen writes them: the passphrase made into a key and a starting
/// point with bcrypt_pbkdf over a random 16-byte salt, and the private part
/// sealed with aes256-ctr, padded with 1, 2, 3... up to the cipher's 16-byte
/// block (8 bytes where it is not sealed), the base64 broken into lines of
/// 70. A file written here and one ssh-keygen wrote from the same parts, the
/// same salt and the same rounds are the same bytes.
abstract class OpenSSHKeyFile {
  /// How many rounds of bcrypt_pbkdf a passphrase gets: ssh-keygen's own
  /// number since OpenSSH 9.8 (it was 16 before).
  static const int defaultRounds = 24;

  /// The cipher a sealed file uses, ssh-keygen's.
  static const String cipherName = 'aes256-ctr';

  /// The private part of the key file [pem], opened with [passphrase]
  /// where it is sealed: an OpenSSH file kept as it is (its check numbers
  /// and comments too), a PEM file (`RSA PRIVATE KEY`, `EC PRIVATE KEY`)
  /// laid out as OpenSSH lays out the same key, with no comment. Throws
  /// [SSHKeyDecryptError] where the passphrase is missing or wrong.
  static OpenSSHKeyFileParts open(String pem, [String? passphrase]) {
    final decoded = SSHPem.decode(pem);
    if (decoded.type != 'OPENSSH PRIVATE KEY') {
      final keys = SSHKeyPair.fromPem(pem, _given(passphrase));
      return _partsOf(keys);
    }
    final file = OpenSSHKeyPairs.decode(decoded.content);
    final Uint8List plain;
    if (file.isEncrypted) {
      final given = _given(passphrase);
      if (given == null) throw SSHKeyDecryptError('Private key is encrypted');
      plain = _crypt(
        file.privateKeyBlob,
        cipher: file.cipherName,
        options: file.kdfOptions as OpenSSHBcryptKdfOptions,
        passphrase: given,
        forEncryption: false,
      );
    } else {
      plain = file.privateKeyBlob;
    }
    final reader = SSHMessageReader(plain);
    final check1 = reader.readUint32();
    final check2 = reader.readUint32();
    if (check1 != check2) {
      throw SSHKeyDecryptError(file.isEncrypted ? 'Invalid passphrase' : 'Invalid private key');
    }
    // Each key read through, to find where the private part ends and its
    // padding starts.
    for (var i = 0; i < file.publicKeys.length; i++) {
      final type = reader.readUtf8();
      switch (type) {
        case 'ssh-rsa':
          OpenSSHRsaKeyPair.readFrom(reader);
        case 'ssh-ed25519':
          OpenSSHEd25519KeyPair.readFrom(reader);
        case 'ssh-ed448':
          OpenSSHEd448KeyPair.readFrom(reader);
        case 'ecdsa-sha2-nistp256' || 'ecdsa-sha2-nistp384' || 'ecdsa-sha2-nistp521':
          OpenSSHEcdsaKeyPair.readFrom(reader);
        default:
          throw UnsupportedError('Unsupported key type: $type');
      }
    }
    final padding = reader.readToEnd();
    for (var i = 0; i < padding.length; i++) {
      if (padding[i] != i + 1) throw SSHKeyDecodeError('Invalid private key padding');
    }
    return OpenSSHKeyFileParts(
      publicKeys: file.publicKeys,
      body: Uint8List.fromList(Uint8List.sublistView(plain, 0, plain.length - padding.length)),
    );
  }

  /// [parts] as an OpenSSH key file, sealed under [passphrase] where there
  /// is one (null or empty: not sealed). [salt] (16 bytes) is drawn at random
  /// unless given; giving it is for a test that compares with ssh-keygen.
  static String seal(
    OpenSSHKeyFileParts parts, {
    String? passphrase,
    int rounds = defaultRounds,
    Uint8List? salt,
  }) {
    final given = _given(passphrase);
    if (given != null && (rounds < 1 || rounds > 1000)) {
      throw ArgumentError.value(rounds, 'rounds', 'must be 1 to 1000');
    }
    final options = given == null ? null : OpenSSHBcryptKdfOptions(salt ?? _randomBytes(16), rounds);
    final block = given == null ? 8 : SSHCipherType.aes256ctr.blockSize;
    final padded = BytesBuilder(copy: false)..add(parts.body);
    for (var i = 1; (parts.body.length + i - 1) % block != 0; i++) {
      padded.addByte(i);
    }
    var private = padded.takeBytes();
    if (options != null) {
      private = _crypt(private, cipher: cipherName, options: options, passphrase: given!, forEncryption: true);
    }
    return OpenSSHKeyPairs(
      cipherName: options == null ? 'none' : cipherName,
      kdfName: options == null ? 'none' : 'bcrypt',
      kdfOptions: options,
      publicKeys: parts.publicKeys,
      privateKeyBlob: private,
    ).toPem();
  }

  /// [pem] written again as an OpenSSH key file, opened with [passphrase]
  /// and sealed under [newPassphrase] (null or empty: not sealed): to add,
  /// change or take off a key's passphrase. The keys in it, their check
  /// numbers and comments are kept; a PEM file becomes an OpenSSH one.
  static String rewrite(
    String pem, {
    String? passphrase,
    String? newPassphrase,
    int rounds = defaultRounds,
  }) =>
      seal(open(pem, passphrase), passphrase: newPassphrase, rounds: rounds);

  /// Whether [pem] is sealed under a passphrase.
  static bool isSealed(String pem) => SSHKeyPair.isEncryptedPem(pem);

  static String? _given(String? passphrase) => passphrase == null || passphrase.isEmpty ? null : passphrase;

  static OpenSSHKeyFileParts _partsOf(List<SSHKeyPair> keys) {
    final writer = SSHMessageWriter();
    final check = Random.secure().nextInt(0xFFFFFFFF);
    writer.writeUint32(check);
    writer.writeUint32(check);
    final publicKeys = <Uint8List>[];
    for (final key in keys) {
      switch (key) {
        case OpenSSHKeyPair():
          writer.writeUtf8(key.name);
          key.writeTo(writer);
        case RsaPrivateKey(:final n, :final e, :final d, :final p, :final q, :final coefficient):
          // OpenSSH's order: n, e, d, iqmp (q^-1 mod p, the PEM file's
          // coefficient), p, q, then the comment.
          writer.writeUtf8('ssh-rsa');
          writer.writeMpint(n);
          writer.writeMpint(e);
          writer.writeMpint(d);
          writer.writeMpint(coefficient);
          writer.writeMpint(p);
          writer.writeMpint(q);
          writer.writeUtf8('');
        default:
          throw UnsupportedError('Unsupported key: ${key.type}');
      }
      publicKeys.add(key.toPublicKey().encode());
    }
    return OpenSSHKeyFileParts(publicKeys: publicKeys, body: writer.takeBytes());
  }

  static Uint8List _crypt(
    Uint8List data, {
    required String cipher,
    required OpenSSHBcryptKdfOptions options,
    required String passphrase,
    required bool forEncryption,
  }) {
    final type = SSHCipherType.fromName(cipher);
    if (type == null || type.isAead) throw UnsupportedError('Unsupported cipher: $cipher');
    if (data.length % type.blockSize != 0) throw SSHKeyDecodeError('Invalid private key length');
    final secret = utf8.encode(passphrase);
    final derived = Uint8List(type.keySize + type.ivSize);
    bcrypt_pbkdf(
      secret,
      secret.length,
      options.salt,
      options.salt.length,
      derived,
      derived.length,
      options.rounds,
    );
    final key = Uint8List.sublistView(derived, 0, type.keySize);
    final iv = Uint8List.sublistView(derived, type.keySize);
    return type.createCipher(key, iv, forEncryption: forEncryption).processAll(data);
  }

  static Uint8List _randomBytes(int length) {
    final random = Random.secure();
    return Uint8List.fromList([for (var i = 0; i < length; i++) random.nextInt(256)]);
  }
}
