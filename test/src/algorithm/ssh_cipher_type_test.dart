import 'dart:typed_data';
import 'dart:mirrors';

import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/ssh_algorithm.dart';
import 'package:zest_ssh_core/src/utils/cipher_ext.dart';
import 'package:test/test.dart';

void main() {
  testCipher(SSHCipherType.aes128cbc);
  testCipher(SSHCipherType.aes192cbc);
  testCipher(SSHCipherType.aes256cbc);
  testCipher(SSHCipherType.aes128ctr);
  testCipher(SSHCipherType.aes192ctr);
  testCipher(SSHCipherType.aes256ctr);
  group('SSHAlgorithm', () {
    test('toString() returns correct format', () {
      final algorithm = SSHKexType.x25519;
      expect(algorithm.toString(), equals(SSHKexType.x25519.toString()));
    });
  });

  group('SSHAlgorithmList extension', () {
    test('toNameList() returns list of names', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final names = algorithms.toNameList();
      expect(names, equals([SSHKexType.x25519.name, SSHKexType.nistp521.name]));
    });

    test('getByName() returns correct algorithm', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final algorithm = algorithms.getByName(SSHKexType.nistp521.name);
      expect(algorithm, isNotNull);
      expect(algorithm!.name, equals(SSHKexType.nistp521.name));
    });

    test('getByName() returns null when not found', () {
      final algorithms = [SSHKexType.x25519, SSHKexType.nistp521];
      final algorithm = algorithms.getByName('nonexistent');
      expect(algorithm, isNull);
    });
  });

  group('AEAD cipher metadata', () {
    test('AES-GCM ciphers are marked as AEAD', () {
      expect(SSHCipherType.aes128gcm.isAead, isTrue);
      expect(SSHCipherType.aes256gcm.isAead, isTrue);
      expect(SSHCipherType.aes128gcm.ivSize, 12);
      expect(SSHCipherType.aes128gcm.aeadTagSize, 16);
    });

    test('AEAD ciphers do not expose BlockCipher API', () {
      expect(
        () => SSHCipherType.aes128gcm.createCipher(
          Uint8List(SSHCipherType.aes128gcm.keySize),
          Uint8List(SSHCipherType.aes128gcm.ivSize),
          forEncryption: true,
        ),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('fromName resolves AES-GCM ciphers', () {
      expect(
        SSHCipherType.fromName('aes128-gcm@openssh.com'),
        SSHCipherType.aes128gcm,
      );
      expect(
        SSHCipherType.fromName('aes256-gcm@openssh.com'),
        SSHCipherType.aes256gcm,
      );
    });

    test('createCipher throws when cipher factory is missing', () {
      final library = reflectClass(SSHCipherType).owner as LibraryMirror;
      final ctor = MirrorSystem.getSymbol('_', library);
      final dynamic custom = reflectClass(SSHCipherType).newInstance(
        ctor,
        const [],
        {
          #name: 'custom-null-factory',
          #keySize: 16,
          #ivSize: 16,
          #blockSize: 16,
          #isAead: false,
          #aeadTagSize: 0,
          #cipherFactory: null,
        },
      ).reflectee;

      expect(
        () => custom.createCipher(
          Uint8List(16),
          Uint8List(16),
          forEncryption: true,
        ),
        throwsA(isA<StateError>()),
      );
    });
  });

  test('Default values are set correctly', () {
    final algorithms = SSHAlgorithms();

    expect(
        algorithms.kex,
        equals([
          // SHA-1 key exchanges (dh14Sha1, dhGexSha1, dh1Sha1) are dropped
          // from the secure defaults - opt-in only via a compatibility profile.
          SSHKexType.x25519,
          SSHKexType.nistp521,
          SSHKexType.nistp384,
          SSHKexType.nistp256,
          SSHKexType.dhGexSha256,
          SSHKexType.dh14Sha256,
        ]));

    expect(
        algorithms.hostkey,
        equals([
          SSHHostkeyType.ed25519,
          SSHHostkeyType.rsaSha512,
          SSHHostkeyType.rsaSha256,
          // rsaSha1 (SHA-1 host-key signatures) dropped from secure defaults.
          SSHHostkeyType.ecdsa521,
          SSHHostkeyType.ecdsa384,
          SSHHostkeyType.ecdsa256,
        ]));

    expect(
        algorithms.cipher,
        equals([
          // AES-256 preferred over AES-128; CBC ciphers dropped (CVE-2008-5161).
          SSHCipherType.chacha20poly1305,
          SSHCipherType.aes256ctr,
          SSHCipherType.aes128ctr,
        ]));

    expect(
        algorithms.mac,
        equals([
          // ETM variants first, then full-length HMACs, then 96-bit truncated;
          // hmac-md5 dropped from secure defaults.
          SSHMacType.hmacSha512Etm,
          SSHMacType.hmacSha256Etm,
          SSHMacType.hmacSha512,
          SSHMacType.hmacSha256,
          SSHMacType.hmacSha1,
          SSHMacType.hmacSha512_96,
          SSHMacType.hmacSha256_96,
        ]));
  });
}

void testCipher(SSHCipherType type) {
  test('$type encrypt/decrypt', () {
    final key = Uint8List(type.keySize);
    final iv = Uint8List(type.blockSize);
    final encrypter = type.createCipher(key, iv, forEncryption: true);
    final decrypter = type.createCipher(key, iv, forEncryption: false);

    final plainText = Uint8List(type.blockSize * 100);
    for (var i = 0; i < plainText.length; i++) {
      plainText[i] = i & 0xff;
    }

    final cipherText = encrypter.processAll(plainText);
    final decrypted = decrypter.processAll(cipherText);

    expect(decrypted, plainText);
  });

  test('$type rejects invalid key length', () {
    expect(
      () => type.createCipher(
        Uint8List(type.keySize - 1),
        Uint8List(type.blockSize),
        forEncryption: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('$type rejects invalid IV length', () {
    expect(
      () => type.createCipher(
        Uint8List(type.keySize),
        Uint8List(type.ivSize - 1),
        forEncryption: true,
      ),
      throwsA(isA<ArgumentError>()),
    );
  });

  // test('$type needs init after reset', () {
  //   final key = Uint8List(type.keySize);
  //   final iv = Uint8List(type.blockSize);
  //   final encrypter = type.createCipher(key, iv, forEncryption: true);
  //   encrypter.processAll(Uint8List(type.blockSize));
  //   encrypter.reset();
  //   expect(
  //     () => encrypter.processAll(Uint8List(type.blockSize)),
  //     throwsA(isA<StateError>()),
  //   );
  // });
}
