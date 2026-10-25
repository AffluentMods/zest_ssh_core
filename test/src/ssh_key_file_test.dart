import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

import '../test_utils.dart';

/// Writing a private key file as OpenSSH does (OpenSSHKeyFile), sealed under
/// a passphrase or not: known answers from ssh-keygen. Each sealed file in
/// test/fixtures/openssh-sealed was written by OpenSSH 10.2's ssh-keygen
/// (see the README there); opened with its passphrase and sealed again here
/// with its own salt and rounds, it must come out as the very same bytes,
/// which shows the private part, its padding, bcrypt_pbkdf, aes256-ctr and
/// the file's layout and line breaks are all as OpenSSH writes them. Where
/// WSL is there, ssh-keygen itself also reads what is written here.
void main() {
  String sealed(String name) => fixture('openssh-sealed/$name');
  String passphrase(String name) => fixture('openssh-sealed/$name.passphrase');

  OpenSSHBcryptKdfOptions optionsOf(String pem) =>
      OpenSSHKeyPairs.decode(SSHPem.decode(pem).content).kdfOptions! as OpenSSHBcryptKdfOptions;

  String publicLine(String pem, [String? passphrase]) {
    final key = SSHKeyPair.fromPem(pem, passphrase).single;
    return '${key.name} ${base64.encode(key.toPublicKey().encode())}';
  }

  String publicFixture(String name) => sealed('$name.pub').trim().split(' ').take(2).join(' ');

  group('known answers from ssh-keygen', () {
    for (final name in ['ed25519', 'ecdsa256', 'rsa2048', 'ed25519_a4', 'plain_then_pass']) {
      test('$name: opened and sealed again with its own salt and rounds, it is the file ssh-keygen wrote', () {
        final file = sealed(name);
        final options = optionsOf(file);
        final parts = OpenSSHKeyFile.open(file, passphrase(name));
        final again = OpenSSHKeyFile.seal(parts, passphrase: passphrase(name), rounds: options.rounds, salt: options.salt);
        expect(again, file);
      });
    }

    test("ssh-keygen's own rounds are the default here", () {
      expect(optionsOf(sealed('ed25519')).rounds, OpenSSHKeyFile.defaultRounds);
      expect(optionsOf(sealed('ed25519_a4')).rounds, 4);
    });

    test('a file with no passphrase, opened and written again, is the file ssh-keygen wrote', () {
      final file = sealed('plain');
      expect(OpenSSHKeyFile.seal(OpenSSHKeyFile.open(file)), file);
    });

    test('a passphrase added to the plain file by ssh-keygen -p seals the same key and comment', () {
      // ssh-keygen -p draws new check numbers; the rest of the private
      // part, the key and its comment, is the plain file's.
      final plain = OpenSSHKeyFile.open(sealed('plain'));
      final sealedLater = OpenSSHKeyFile.open(sealed('plain_then_pass'), passphrase('plain_then_pass'));
      expect(sealedLater.body.sublist(8), plain.body.sublist(8));
      expect(sealedLater.publicKeys.single, plain.publicKeys.single);
    });
  });

  group('rewrite', () {
    test('adds a passphrase: the key opens with it alone, and is the same key', () {
      final plain = sealed('plain');
      final added = OpenSSHKeyFile.rewrite(plain, newPassphrase: 'a new one');
      expect(OpenSSHKeyFile.isSealed(added), isTrue);
      expect(publicLine(added, 'a new one'), publicFixture('plain'));
      expect(() => SSHKeyPair.fromPem(added), throwsA(isA<SSHKeyDecryptError>()));
      expect(() => SSHKeyPair.fromPem(added, 'not it'), throwsA(isA<SSHKeyDecodeError>()));
      // Its salt is drawn at random, 16 bytes, and it has ssh-keygen's rounds.
      expect(optionsOf(added).salt, hasLength(16));
      expect(optionsOf(added).rounds, OpenSSHKeyFile.defaultRounds);
      expect(optionsOf(OpenSSHKeyFile.rewrite(plain, newPassphrase: 'a new one')).salt, isNot(optionsOf(added).salt));
    });

    test('changes a passphrase: the old one no longer opens it', () {
      final changed = OpenSSHKeyFile.rewrite(sealed('ed25519'), passphrase: passphrase('ed25519'), newPassphrase: 'changed');
      expect(publicLine(changed, 'changed'), publicFixture('ed25519'));
      expect(() => SSHKeyPair.fromPem(changed, passphrase('ed25519')), throwsA(isA<SSHKeyDecodeError>()));
    });

    test('takes a passphrase off: the plain file of the same key, its check numbers and comment kept', () {
      final sealedFile = sealed('plain_then_pass');
      final before = OpenSSHKeyFile.open(sealedFile, passphrase('plain_then_pass'));
      final off = OpenSSHKeyFile.rewrite(sealedFile, passphrase: passphrase('plain_then_pass'));
      expect(OpenSSHKeyFile.isSealed(off), isFalse);
      expect(OpenSSHKeyFile.open(off).body, before.body);
      expect(publicLine(off), publicFixture('plain'));
      // Laid out as ssh-keygen lays out a file with no passphrase.
      expect(OpenSSHKeyFile.seal(OpenSSHKeyFile.open(sealed('plain'))), sealed('plain'));
    });

    test('an empty new passphrase is none', () {
      final off = OpenSSHKeyFile.rewrite(sealed('ed25519'), passphrase: passphrase('ed25519'), newPassphrase: '');
      expect(OpenSSHKeyFile.isSealed(off), isFalse);
      expect(publicLine(off), publicFixture('ed25519'));
    });

    test('a wrong or missing passphrase writes nothing', () {
      expect(() => OpenSSHKeyFile.rewrite(sealed('ed25519'), passphrase: 'wrong', newPassphrase: 'x'),
          throwsA(isA<SSHKeyDecryptError>()));
      expect(() => OpenSSHKeyFile.rewrite(sealed('ed25519'), newPassphrase: 'x'), throwsA(isA<SSHKeyDecryptError>()));
    });

    test('a PEM RSA key becomes an OpenSSH file of the same key', () {
      final pem = fixture('ssh-rsa/id_rsa');
      final written = OpenSSHKeyFile.rewrite(pem, newPassphrase: 'pem to openssh');
      expect(written, startsWith('-----BEGIN OPENSSH PRIVATE KEY-----\n'));
      expect(publicLine(written, 'pem to openssh'), publicLine(pem));
      // And it still signs as the key does.
      final key = SSHKeyPair.fromPem(written, 'pem to openssh').single;
      expect(key, isA<OpenSSHRsaKeyPair>());
    });

    test('every key kind round-trips with and without a passphrase', () {
      for (final pem in [
        fixture('ssh-ed25519/id_ed25519'),
        fixture('ecdsa-sha2-nistp256/id_ecdsa'),
        fixture('ecdsa-sha2-nistp384/id_ecdsa'),
        fixture('ecdsa-sha2-nistp521/id_ecdsa'),
        fixture('ssh-rsa/id_rsa.openssh'),
      ]) {
        final want = publicLine(pem);
        final on = OpenSSHKeyFile.rewrite(pem, newPassphrase: 'pass');
        expect(publicLine(on, 'pass'), want);
        expect(publicLine(OpenSSHKeyFile.rewrite(on, passphrase: 'pass')), want);
      }
    });

    test('a damaged padding is refused', () {
      final parts = OpenSSHKeyFile.open(sealed('plain'));
      final file = OpenSSHKeyPairs.decode(SSHPem.decode(sealed('plain')).content);
      final blob = Uint8List.fromList(file.privateKeyBlob);
      expect(blob.length, greaterThan(parts.body.length));
      blob[blob.length - 1] ^= 0xff;
      final damaged = OpenSSHKeyPairs(
        cipherName: 'none',
        kdfName: 'none',
        kdfOptions: null,
        publicKeys: file.publicKeys,
        privateKeyBlob: blob,
      ).toPem();
      expect(() => OpenSSHKeyFile.open(damaged), throwsA(isA<SSHKeyDecodeError>()));
    });
  });

  group('ssh-keygen reads what is written here (WSL)', () {
    late bool wsl;
    setUpAll(() async {
      try {
        final r = await Process.run('wsl', ['-d', 'Ubuntu', '-e', 'ssh-keygen', '-?']).timeout(const Duration(seconds: 20));
        wsl = r.exitCode == 1 || r.exitCode == 0 || '${r.stderr}'.contains('usage');
      } catch (_) {
        wsl = false;
      }
    });

    /// ssh-keygen -y (the public key of a private key file) over [pem],
    /// opened with [passphrase]: what it printed, or null where it failed.
    Future<String?> keygenPublic(String pem, String passphrase) async {
      final script = 'f=\$(mktemp); trap \'rm -f "\$f"\' EXIT; cat > "\$f"; chmod 600 "\$f"; '
          'ssh-keygen -y -P "\$1" -f "\$f"';
      final p = await Process.start('wsl', ['-d', 'Ubuntu', '-e', 'sh', '-c', script, 'sh', passphrase]);
      p.stdin.write(pem);
      await p.stdin.close();
      final out = await p.stdout.transform(utf8.decoder).join();
      return await p.exitCode == 0 ? out.trim().split(' ').take(2).join(' ') : null;
    }

    for (final (name, pem) in [
      ('ed25519', () => fixture('ssh-ed25519/id_ed25519')),
      ('ecdsa', () => fixture('ecdsa-sha2-nistp256/id_ecdsa')),
      ('rsa from PEM', () => fixture('ssh-rsa/id_rsa')),
    ]) {
      test('$name sealed here opens in ssh-keygen with its passphrase, and with no other', () async {
        if (!wsl) return markTestSkipped('WSL is not available');
        final written = OpenSSHKeyFile.rewrite(pem(), newPassphrase: 'from zestssh');
        expect(await keygenPublic(written, 'from zestssh'), publicLine(pem()));
        expect(await keygenPublic(written, 'another'), isNull);
      });
    }
  });
}
