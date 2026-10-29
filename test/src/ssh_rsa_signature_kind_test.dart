// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/message/msg_ext_info.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

import 'played_server.dart';
import 'real_openssh_server.dart';

/// An RSA key signs in with the kind of signature the server takes.
///
/// An RSA key makes three kinds of signature (RFC 8332): with SHA-512, with
/// SHA-256, and the first kind, with SHA-1 ("ssh-rsa"). A server takes some
/// and refuses the others, and says which with its "server-sig-algs". The
/// client signed with SHA-256 whatever the server said: so an RSA key was
/// refused by a server that takes only SHA-512, as one that is set up
/// strictly does, and by one that knows only the first kind, as a server
/// older than OpenSSH 7.2 does, and nothing said why.
///
/// With a played server, which says what a test has it say; and with three
/// real OpenSSH servers (tool/test_sshd.sh: the first, one that takes only
/// SHA-512 from an RSA key, and one that takes only the first kind), skipped
/// where they are not running.
void main() {
  const sha512 = 'rsa-sha2-512';
  const sha256 = 'rsa-sha2-256';
  const sha1 = 'ssh-rsa';

  SSHKeyPair fromFile(String path) => SSHKeyPair.fromPem(File('test/fixtures/$path').readAsStringSync()).single;
  final rsa = fromFile('ssh-rsa/ssh_host_rsa_key') as OpenSSHRsaKeyPair;
  final ed25519 = fromFile('ssh-ed25519/ssh_host_ed25519_key');

  /// The same key as a key file in the older form holds it.
  RsaPrivateKey inPemForm(OpenSSHRsaKeyPair key) => RsaPrivateKey(
        BigInt.zero,
        key.n,
        key.e,
        key.d,
        key.p,
        key.q,
        key.d % (key.p - BigInt.one),
        key.d % (key.q - BigInt.one),
        key.iqmp,
      );

  group('the key by itself', () {
    final data = Uint8List.fromList('what a sign-in signs'.codeUnits);

    for (final (form, key) in <(String, SSHKeyPair)>[
      ('a key file of OpenSSH', rsa),
      ('a key file in the older form', inPemForm(rsa)),
    ]) {
      test('$form: it signs with SHA-256 unless it is made to sign otherwise, and can be made to sign in each of '
          'the three ways', () async {
        expect(key.type, sha256);
        expect(key, isA<SSHRsaSignatureChoice>());
        final choice = key as SSHRsaSignatureChoice;
        expect(choice.rsaSignatureTypes, [sha512, sha256, sha1]);
        for (final kind in [sha512, sha256, sha1]) {
          final signing = choice.signingAsRsa(kind);
          expect(signing.type, kind);
          expect(signing.name, 'ssh-rsa');
          expect(signing.toPublicKey().encode(), key.toPublicKey().encode());
          expect(signing.runtimeType, key.runtimeType);
          for (final signature in [signing.sign(data), await signing.signAsync(data)]) {
            final made = SSHRsaSignature.decode(signature.encode());
            expect(made.type, kind);
            expect(SSHRsaPublicKey.decode(key.toPublicKey().encode()).verify(data, made), isTrue, reason: kind);
          }
          // It can be made to sign otherwise again, whatever it signs with now.
          expect((signing as SSHRsaSignatureChoice).signingAsRsa(sha256).type, sha256);
        }
        // The key it was made of signs as it did.
        expect(key.type, sha256);
        expect(SSHRsaSignature.decode(key.sign(data).encode()).type, sha256);
      });

      test('$form: what is no kind of RSA signature is refused when the key is made to sign with it', () {
        final choice = key as SSHRsaSignatureChoice;
        for (final none in ['rsa-sha2-384', 'ssh-ed25519', '', 'RSA-SHA2-512']) {
          expect(() => choice.signingAsRsa(none), throwsArgumentError, reason: none);
        }
      });
    }

    test('what a client may make unless it is told otherwise: SHA-512 and SHA-256, in that order, and not SHA-1',
        () {
      expect(const SSHAlgorithms().rsaSignatures, [sha512, sha256]);
      expect(SSHRsaSignatureType.all, [sha512, sha256, sha1]);
    });
  });

  group('a played server', () {
    /// A client with [keys] on a played server that says it takes [takes]
    /// of the kinds of signature (null: it says nothing), and that takes
    /// keys and nothing else. [mayMake]: the kinds of RSA signature the
    /// client may make, where they are not what a client may make by itself.
    Future<(PlayedServer, Future<Object?>)> start(
      List<SSHKeyPair> keys, {
      required List<String>? takes,
      List<String>? mayMake,
    }) async {
      final server = PlayedServer();
      final speaks = server.speaks;
      final client = SSHClient(
        server.socket,
        username: 'deploy',
        algorithms: mayMake == null
            ? speaks
            : SSHAlgorithms(
                kex: speaks.kex,
                hostkey: speaks.hostkey,
                cipher: speaks.cipher,
                mac: speaks.mac,
                rsaSignatures: mayMake,
              ),
        keepAliveInterval: null,
        identities: keys,
      );
      addTearDown(client.close);
      final ended = client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
      await server.greet(afterNewKeys: [
        if (takes != null) SSH_Message_ExtInfo({'server-sig-algs': latin1.encode(takes.join(','))}).encode(),
      ]);
      final first = SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));
      expect(first.methodName, 'none');
      server.send([SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode()]);
      return (server, ended);
    }

    Future<SSH_Message_Userauth_Request> asks(PlayedServer server) async =>
        SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));

    void no(PlayedServer server) =>
        server.send([SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode()]);

    void letIn(PlayedServer server) => server.send([SSH_Message_Userauth_Success().encode()]);

    Future<void> nothingMore(PlayedServer server) async =>
        expect(await server.sent(SSH_Message_Userauth_Request.messageId), isFalse, reason: 'nothing more is asked');

    /// What a key signs to sign in with [request] (RFC 4252, 7).
    Uint8List signedFor(PlayedServer server, SSH_Message_Userauth_Request request) => (SSHMessageWriter()
          ..writeString(server.sessionId)
          ..writeUint8(SSH_Message_Userauth_Request.messageId)
          ..writeUtf8('deploy')
          ..writeUtf8('ssh-connection')
          ..writeUtf8('publickey')
          ..writeBool(true)
          ..writeUtf8(request.publicKeyAlgorithm!)
          ..writeString(request.publicKey!))
        .takeBytes();

    /// The server is asked about the RSA key as [kind], says yes, and is
    /// sent the key's own signature of that kind for this sign-in.
    Future<void> expectAskedAndSignedAs(PlayedServer server, String kind) async {
      final question = await asks(server);
      expect(question.methodName, 'publickey');
      expect(question.publicKeyAlgorithm, kind);
      expect(question.publicKey, rsa.toPublicKey().encode());
      expect(question.signature, isNull);
      server.takesKey(question);
      final signed = await asks(server);
      expect(signed.publicKeyAlgorithm, kind);
      expect(signed.publicKey, rsa.toPublicKey().encode());
      final signature = SSHRsaSignature.decode(signed.signature!);
      expect(signature.type, kind);
      expect(SSHRsaPublicKey.decode(signed.publicKey!).verify(signedFor(server, signed), signature), isTrue,
          reason: 'the signature is not the key\'s own of this sign-in, as $kind');
    }

    for (final (takes, kind) in [
      (['ssh-ed25519', sha512, sha256], sha512),
      (['ssh-ed25519', sha256, sha512], sha512),
      (['ssh-ed25519', sha256], sha256),
      (['ssh-ed25519', sha512], sha512),
      ([sha1, sha256], sha256),
    ]) {
      test('a server that says it takes ${takes.join(', ')}: the key is asked about and signs as $kind', () async {
        final (server, ended) = await start([rsa], takes: takes);
        await expectAskedAndSignedAs(server, kind);
        letIn(server);
        expect(await ended, isNull);
        await nothingMore(server);
      });
    }

    test('a server that says it takes only the first kind, with SHA-1: the key is not asked about, nothing of it is '
        'sent, and the sign-in fails saying that the key was passed over and what the server takes', () async {
      final (server, ended) = await start([rsa], takes: ['ssh-ed25519', sha1]);
      final failed = await ended;
      await nothingMore(server);
      expect(failed, isA<SSHAuthFailError>());
      failed as SSHAuthFailError;
      expect(failed.keysPassedOver, ['ssh-rsa']);
      expect(failed.serverSignatureAlgorithms, ['ssh-ed25519', sha1]);
      expect(failed.methodsTried, isEmpty, reason: 'nothing was tried with the server');
      expect(failed.serverTakes, ['publickey']);
      expect(() => failed.keysPassedOver.add('another'), throwsUnsupportedError);
    });

    test('the same server, and a client that may make the first kind: the key signs as ssh-rsa', () async {
      final (server, ended) = await start([rsa], takes: ['ssh-ed25519', sha1], mayMake: [sha512, sha256, sha1]);
      await expectAskedAndSignedAs(server, sha1);
      letIn(server);
      expect(await ended, isNull);
    });

    test('a client that may make the first kind still makes a better one where the server takes it', () async {
      final (server, ended) = await start([rsa], takes: [sha1, sha256], mayMake: [sha512, sha256, sha1]);
      await expectAskedAndSignedAs(server, sha256);
      letIn(server);
      expect(await ended, isNull);
    });

    test('the order is the client\'s: one that would rather make SHA-256 makes it where the server takes both',
        () async {
      final (server, ended) = await start([rsa], takes: [sha512, sha256], mayMake: [sha256, sha512]);
      await expectAskedAndSignedAs(server, sha256);
      letIn(server);
      expect(await ended, isNull);
    });

    test('a server that says it takes no signature of an RSA key: the key is passed over, and the next key is '
        'asked about', () async {
      final (server, ended) = await start([rsa, ed25519], takes: ['ssh-ed25519']);
      final question = await asks(server);
      expect(question.publicKeyAlgorithm, 'ssh-ed25519');
      expect(question.signature, isNull);
      no(server);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      failed as SSHAuthFailError;
      expect(failed.keysPassedOver, ['ssh-rsa']);
      expect(failed.methodsTried, ['publickey']);
      expect(failed.serverSignatureAlgorithms, ['ssh-ed25519']);
      await nothingMore(server);
    });

    test('a key of another kind is asked about whatever the server says it takes, and a refusal says nothing of '
        'keys that were passed over', () async {
      for (final takes in [
        [sha512, sha256],
        <String>[],
      ]) {
        final (server, ended) = await start([ed25519], takes: takes);
        final question = await asks(server);
        expect(question.publicKeyAlgorithm, 'ssh-ed25519', reason: '$takes');
        no(server);
        final failed = await ended;
        expect(failed, isA<SSHAuthFailError>());
        failed as SSHAuthFailError;
        expect(failed.keysPassedOver, isEmpty);
        expect(failed.serverSignatureAlgorithms, takes);
      }
    });

    test('a server that says it takes no signature at all: an RSA key is passed over', () async {
      final (server, ended) = await start([rsa], takes: const []);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      expect((failed as SSHAuthFailError).keysPassedOver, ['ssh-rsa']);
      expect(failed.serverSignatureAlgorithms, isEmpty);
      await nothingMore(server);
    });

    test('a server that says nothing of what it takes: the key is asked about as rsa-sha2-256, as before, and where '
        'that is refused, in no other way', () async {
      final (server, ended) = await start([rsa], takes: null);
      final question = await asks(server);
      expect(question.publicKeyAlgorithm, sha256);
      expect(question.signature, isNull);
      no(server);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      failed as SSHAuthFailError;
      expect(failed.keysPassedOver, isEmpty);
      expect(failed.serverSignatureAlgorithms, isNull);
      expect(failed.methodsTried, ['publickey']);
      await nothingMore(server);
    });

    test('the same server, and a client that may make the first kind: refused as rsa-sha2-256, the key is asked '
        'about as ssh-rsa, and signs as that', () async {
      final (server, ended) = await start([rsa], takes: null, mayMake: [sha512, sha256, sha1]);
      final question = await asks(server);
      expect(question.publicKeyAlgorithm, sha256);
      no(server);
      await expectAskedAndSignedAs(server, sha1);
      letIn(server);
      expect(await ended, isNull);
    });

    test('the same again, with a server that takes the key as rsa-sha2-256: it is asked about once', () async {
      final (server, ended) = await start([rsa], takes: null, mayMake: [sha512, sha256, sha1]);
      await expectAskedAndSignedAs(server, sha256);
      letIn(server);
      expect(await ended, isNull);
      await nothingMore(server);
    });

    test('a key that signs in as one step of several is not asked about again in its other way', () async {
      final (server, ended) = await start([rsa], takes: null, mayMake: [sha512, sha256, sha1]);
      await expectAskedAndSignedAs(server, sha256);
      // The key is right, and is not all: the server wants another key, and there is none.
      server.send([
        SSH_Message_Userauth_Failure(methodsLeft: const ['publickey'], partialSuccess: true).encode(),
      ]);
      await nothingMore(server);
      expect(await ended, isA<SSHAuthFailError>());
    });

    test('a server that says nothing, and a client that may make SHA-512 and no other: the key is asked about as '
        'rsa-sha2-512', () async {
      final (server, ended) = await start([rsa], takes: null, mayMake: [sha512]);
      await expectAskedAndSignedAs(server, sha512);
      letIn(server);
      expect(await ended, isNull);
    });

    test('a client that may make no kind of RSA signature passes an RSA key over, whatever the server says',
        () async {
      for (final takes in [
        [sha512, sha256],
        null,
      ]) {
        final (server, ended) = await start([rsa], takes: takes, mayMake: const []);
        final failed = await ended;
        expect(failed, isA<SSHAuthFailError>(), reason: '$takes');
        expect((failed as SSHAuthFailError).keysPassedOver, ['ssh-rsa'], reason: '$takes');
        await nothingMore(server);
      }
    });

    test('a server that says it takes both kinds with SHA-2, and refuses the key: it is asked about once, and not '
        'again as the other kind', () async {
      final (server, ended) = await start([rsa], takes: [sha512, sha256]);
      final question = await asks(server);
      expect(question.publicKeyAlgorithm, sha512);
      no(server);
      await nothingMore(server);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      expect((failed as SSHAuthFailError).keysPassedOver, isEmpty);
      expect(failed.methodsTried, ['publickey']);
    });

    test('a client that may make the first kind and no other, and a server that says nothing: the key is asked '
        'about once, as ssh-rsa', () async {
      final (server, ended) = await start([rsa], takes: null, mayMake: [sha1]);
      final question = await asks(server);
      expect(question.publicKeyAlgorithm, sha1);
      no(server);
      await nothingMore(server);
      expect(await ended, isA<SSHAuthFailError>());
    });

    test('a key that makes one kind of RSA signature only: asked about as that where the server takes it, and '
        'passed over where it does not', () async {
      final seen = <String>[];
      final (server, ended) = await start([_Wrapped(rsa, seen, null, const [sha256])], takes: [sha512, sha256]);
      await expectAskedAndSignedAs(server, sha256);
      letIn(server);
      expect(await ended, isNull);
      expect(seen, [sha256]);

      final (other, otherEnded) = await start([_Wrapped(rsa, seen, null, const [sha256])], takes: [sha512]);
      final failed = await otherEnded;
      expect(failed, isA<SSHAuthFailError>());
      expect((failed as SSHAuthFailError).keysPassedOver, ['ssh-rsa']);
      await nothingMore(other);
    });

    test('a key file in the older form signs the same way', () async {
      final (server, ended) = await start([inPemForm(rsa)], takes: [sha512, sha256]);
      await expectAskedAndSignedAs(server, sha512);
      letIn(server);
      expect(await ended, isNull);
    });

    test('what wraps an RSA key and says so is asked for the kind, and what wraps a key of another kind is asked '
        'about as it is', () async {
      final seen = <String>[];
      final (server, ended) = await start([_Wrapped(rsa, seen)], takes: [sha512, sha256]);
      await expectAskedAndSignedAs(server, sha512);
      letIn(server);
      expect(await ended, isNull);
      expect(seen, [sha512]);

      final unseen = <String>[];
      final (other, otherEnded) = await start([_Wrapped(ed25519, unseen)], takes: [sha512, sha256]);
      final question = await asks(other);
      expect(question.publicKeyAlgorithm, 'ssh-ed25519');
      other.takesKey(question);
      expect((await asks(other)).signature, isNotNull);
      letIn(other);
      expect(await otherEnded, isNull);
      expect(unseen, isEmpty);
    });

    test('two RSA keys, of which the server refuses the first: each is asked about once, as the kind the server '
        'takes', () async {
      final second = OpenSSHRsaKeyPair(rsa.n, rsa.e, rsa.d, rsa.iqmp, rsa.p, rsa.q, 'the same key again');
      final (server, ended) = await start([rsa, second], takes: [sha512]);
      final one = await asks(server);
      expect(one.publicKeyAlgorithm, sha512);
      no(server);
      final two = await asks(server);
      expect(two.publicKeyAlgorithm, sha512);
      expect(two.signature, isNull);
      no(server);
      expect(await ended, isA<SSHAuthFailError>());
      await nothingMore(server);
    });
  });

  group('real OpenSSH servers', () {
    final all = RealOpenSshServer.fromEnvironment();
    final only512 = RealOpenSshServer.sha512Only();
    final only1 = RealOpenSshServer.sha1Only();
    final unavailable = <RealOpenSshServer, String?>{};

    setUpAll(() async {
      for (final server in [all, only512, only1]) {
        unavailable[server] = await server.unavailable();
      }
    });

    /// A sign-in with the RSA key the servers know, wrapped so that it says
    /// what was asked of it: how it ended (null: signed in, and a command
    /// ran), the kinds it was made to sign with, and the kinds of the
    /// signatures it made.
    Future<({Object? failed, List<String> madeToSignAs, List<String> signedAs})> signIn(
      RealOpenSshServer server, {
      List<String>? mayMake,
    }) async {
      final asked = <String>[];
      final signed = <String>[];
      final key = SSHKeyPair.fromPem(File(server.rsaKeyPath).readAsStringSync()).single;
      final client = SSHClient(
        await SSHSocket.connect(server.host, server.port, timeout: const Duration(seconds: 5)),
        username: server.user,
        algorithms: mayMake == null ? const SSHAlgorithms() : SSHAlgorithms(rsaSignatures: mayMake),
        identities: [_Wrapped(key, asked, signed)],
      );
      addTearDown(client.close);
      Object? failed;
      try {
        await client.authenticated.timeout(const Duration(seconds: 20));
        expect(utf8.decode(await client.run('echo signed-in')), contains('signed-in'));
      } catch (e) {
        failed = e;
      }
      client.close();
      return (failed: failed, madeToSignAs: asked, signedAs: signed);
    }

    test('one that takes both kinds with SHA-2: the key signs in, as rsa-sha2-512', () async {
      if (unavailable[all] != null) return markTestSkipped(unavailable[all]!);
      final outcome = await signIn(all);
      expect(outcome.failed, isNull);
      expect(outcome.madeToSignAs, [sha512]);
      expect(outcome.signedAs, [sha512]);
    }, timeout: const Timeout(Duration(seconds: 60)));

    test('one that takes only SHA-512 from an RSA key: the key signs in', () async {
      if (unavailable[only512] != null) return markTestSkipped(unavailable[only512]!);
      final outcome = await signIn(only512);
      expect(outcome.failed, isNull, reason: 'the key was refused by a server that knows it');
      expect(outcome.signedAs, [sha512]);
    }, timeout: const Timeout(Duration(seconds: 60)));

    test('one that takes only the first kind, with SHA-1: the key is passed over with nothing sent of it, and the '
        'sign-in fails saying so', () async {
      if (unavailable[only1] != null) return markTestSkipped(unavailable[only1]!);
      final outcome = await signIn(only1);
      expect(outcome.failed, isA<SSHAuthFailError>());
      final failed = outcome.failed! as SSHAuthFailError;
      expect(failed.keysPassedOver, ['ssh-rsa']);
      expect(failed.serverSignatureAlgorithms, contains(sha1));
      expect(failed.serverSignatureAlgorithms, isNot(contains(sha256)));
      expect(failed.methodsTried, isEmpty);
      expect(outcome.signedAs, isEmpty);
    }, timeout: const Timeout(Duration(seconds: 60)));

    test('the same server, and a client that may make the first kind: the key signs in, as ssh-rsa', () async {
      if (unavailable[only1] != null) return markTestSkipped(unavailable[only1]!);
      final outcome = await signIn(only1, mayMake: [sha512, sha256, sha1]);
      expect(outcome.failed, isNull, reason: 'the key was refused by a server that knows it');
      expect(outcome.signedAs, [sha1]);
    }, timeout: const Timeout(Duration(seconds: 60)));

    test('a client that may make the first kind makes SHA-512 for a server that takes it', () async {
      if (unavailable[all] != null) return markTestSkipped(unavailable[all]!);
      final outcome = await signIn(all, mayMake: [sha512, sha256, sha1]);
      expect(outcome.failed, isNull);
      expect(outcome.signedAs, [sha512]);
    }, timeout: const Timeout(Duration(seconds: 60)));
  });
}

/// A key that wraps another and signs with it, as a certificate or a key
/// that signs somewhere else does: it says of the kinds of RSA signature
/// what the key it wraps says, or [_only] where it is told to make no
/// others; it writes down each kind it is made to sign with ([_asked]),
/// and the kind of each signature it makes ([_signed]).
class _Wrapped implements SSHRsaSignatureChoice {
  _Wrapped(this._key, this._asked, [this._signed, this._only]);

  final SSHKeyPair _key;
  final List<String> _asked;
  final List<String>? _signed;
  final List<String>? _only;

  @override
  List<String> get rsaSignatureTypes {
    final key = _key;
    return _only ?? (key is SSHRsaSignatureChoice ? key.rsaSignatureTypes : const []);
  }

  @override
  SSHKeyPair signingAsRsa(String type) {
    _asked.add(type);
    return _Wrapped((_key as SSHRsaSignatureChoice).signingAsRsa(type), _asked, _signed, _only);
  }

  @override
  String get name => _key.name;

  @override
  String get type => _key.type;

  @override
  SSHHostKey toPublicKey() => _key.toPublicKey();

  @override
  SSHSignature sign(Uint8List data) {
    _signed?.add(_key.type);
    return _key.sign(data);
  }

  @override
  Future<SSHSignature> signAsync(Uint8List data) async => sign(data);

  @override
  String toPem() => _key.toPem();
}
