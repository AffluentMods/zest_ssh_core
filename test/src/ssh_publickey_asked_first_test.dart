// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ed25519.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:zest_ssh_core/src/transport/ssh_events.dart';

import 'played_server.dart';
import 'real_openssh_server.dart';

/// A key is signed with only for a server that has said it takes the key.
///
/// The protocol has a question for it (RFC 4252, 7): a client names the key
/// it would sign in with and sends no signature, and the server answers
/// that it would take the key (SSH_MSG_USERAUTH_PK_OK) or that it would
/// not. It is there, the RFC says, "to avoid unnecessary processing and
/// user interaction". The client did not ask: it signed with every key it
/// had for every server that takes keys at all, and sent the signature. A
/// hardware key was touched and an agent was asked, for a server that then
/// said no.
///
/// With a played server, and keys that count how often they sign; and with
/// a real OpenSSH server (the first one tool/test_sshd.sh starts, on
/// 127.0.0.1:2299), whose own log is read. The second is skipped where that
/// server is not running.
void main() {
  SSHKeyPair fromFile(String path) => SSHKeyPair.fromPem(File('test/fixtures/$path').readAsStringSync()).single;

  group('with a played server', () {
    // What the client of the test that runs said of its sign-in as it went.
    late List<SSHEvent> events;

    /// A client with [keys] on a played server that has said that it takes
    /// keys and nothing else: the server, and how the sign-in ends (null
    /// where it was signed in, else what it failed with).
    Future<(PlayedServer, Future<Object?>)> start(List<SSHKeyPair> keys) async {
      final server = PlayedServer();
      final client = SSHClient(
        server.socket,
        username: 'deploy',
        algorithms: server.speaks,
        keepAliveInterval: null,
        identities: keys,
      );
      addTearDown(client.close);
      events = [];
      final listening = client.events.listen(events.add);
      addTearDown(listening.cancel);
      final ended = client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
      await server.greet();
      final first = SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));
      expect(first.methodName, 'none');
      server.send([SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode()]);
      return (server, ended);
    }

    Future<SSH_Message_Userauth_Request> asks(PlayedServer server) async =>
        SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));

    void no(PlayedServer server) =>
        server.send([SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode()]);

    Future<void> nothingMore(PlayedServer server) async =>
        expect(await server.sent(SSH_Message_Userauth_Request.messageId), isFalse, reason: 'nothing more is asked');

    /// What a key signs to sign in with [request] (RFC 4252, 7): the
    /// connection, the account, the service it is for, and the key.
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

    test('a key the server takes: asked about first, with no signature; signed with once, after the yes; and what '
        'it signs is this connection, the account and the key', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final (server, ended) = await start([key]);
      final question = await asks(server);
      expect(question.methodName, 'publickey');
      expect(question.user, 'deploy');
      expect(question.serviceName, 'ssh-connection');
      expect(question.publicKeyAlgorithm, 'ssh-ed25519');
      expect(question.publicKey, key.toPublicKey().encode());
      expect(question.signature, isNull, reason: 'it signed before it was told that the key is taken');
      await nothingMore(server);
      expect(key.signed, 0);

      server.takesKey(question);
      final signed = await asks(server);
      expect(signed.methodName, 'publickey');
      expect(signed.user, 'deploy');
      expect(signed.publicKeyAlgorithm, 'ssh-ed25519');
      expect(signed.publicKey, key.toPublicKey().encode());
      expect(
        SSHEd25519PublicKey.decode(signed.publicKey!)
            .verify(signedFor(server, signed), SSHEd25519Signature.decode(signed.signature!)),
        isTrue,
        reason: 'the signature is not the key\'s own of what a sign-in on this connection signs',
      );
      expect(key.signed, 1);
      server.send([SSH_Message_Userauth_Success().encode()]);
      expect(await ended, isNull);
      await nothingMore(server);
      expect(key.signed, 1);
      // One try with the key, of which the question and the signature are the two halves.
      expect(events.whereType<SSHEventAuthMethodAttempted>().map((e) => e.method), ['none', 'publickey']);
      expect(events.whereType<SSHEventAuthMethodSucceeded>().single.method, 'publickey');
    });

    test('a key the server does not take: nothing is signed with it, and the sign-in fails as one the server '
        'refused, with the key among what was tried', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final (server, ended) = await start([key]);
      expect((await asks(server)).signature, isNull);
      no(server);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      expect((failed as SSHAuthFailError).methodsTried, ['publickey']);
      expect(failed.serverTakes, ['publickey']);
      expect(key.signed, 0, reason: 'it signed for a server that does not take the key');
      await nothingMore(server);
    });

    test('two keys, of which the server takes the second: each is asked about in turn, and only the second signs',
        () async {
      final first = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final second = _Counted(fromFile('ecdsa-sha2-nistp256/ssh_host_ecdsa_key'));
      final (server, ended) = await start([first, second]);
      final one = await asks(server);
      expect(one.publicKey, first.toPublicKey().encode());
      expect(one.signature, isNull);
      no(server);
      final two = await asks(server);
      expect(two.publicKeyAlgorithm, 'ecdsa-sha2-nistp256');
      expect(two.publicKey, second.toPublicKey().encode());
      expect(two.signature, isNull);
      server.takesKey(two);
      final signed = await asks(server);
      expect(signed.publicKey, second.toPublicKey().encode());
      expect(signed.signature, isNotNull);
      server.send([SSH_Message_Userauth_Success().encode()]);
      expect(await ended, isNull);
      expect((first.signed, second.signed), (0, 1));
    });

    test('a yes that names another key than the one asked about is no yes to it: nothing is signed, and the next '
        'key is asked about', () async {
      final first = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final second = _Counted(fromFile('ecdsa-sha2-nistp256/ssh_host_ecdsa_key'));
      final (server, ended) = await start([first, second]);
      final one = await asks(server);
      expect(one.signature, isNull);
      // The kind of the key that was asked about, and another key: the second one's here, and then one cut short.
      server.send([
        SSH_Message_Userauth_PkOk(publicKeyAlgorithm: 'ssh-ed25519', publicKey: second.toPublicKey().encode()).encode(),
      ]);
      final two = await asks(server);
      expect(two.publicKey, second.toPublicKey().encode());
      expect(two.signature, isNull);
      final cutShort = Uint8List.sublistView(two.publicKey!, 0, two.publicKey!.length - 1);
      server.send([SSH_Message_Userauth_PkOk(publicKeyAlgorithm: two.publicKeyAlgorithm!, publicKey: cutShort).encode()]);
      expect(await ended, isA<SSHAuthFailError>());
      await nothingMore(server);
      expect((first.signed, second.signed), (0, 0));
    });

    test('a yes that names the key and its own kind, where a kind of signature was asked for, is a yes: an RSA key '
        'signs as it asked to', () async {
      final key = _Counted(fromFile('ssh-rsa/ssh_host_rsa_key'));
      final (server, ended) = await start([key]);
      final question = await asks(server);
      expect(question.publicKeyAlgorithm, 'rsa-sha2-256');
      expect(question.signature, isNull);
      // Some servers put the kind of the key here, and not the kind of signature they were asked about.
      server.send([SSH_Message_Userauth_PkOk(publicKeyAlgorithm: 'ssh-rsa', publicKey: question.publicKey!).encode()]);
      final signed = await asks(server);
      expect(signed.publicKeyAlgorithm, 'rsa-sha2-256');
      expect(signed.publicKey, question.publicKey);
      expect(SSHMessageReader(signed.signature!).readUtf8(), 'rsa-sha2-256');
      expect(
        SSHRsaPublicKey.decode(signed.publicKey!)
            .verify(signedFor(server, signed), SSHRsaSignature.decode(signed.signature!)),
        isTrue,
        reason: 'the signature is not the key\'s own of a sign-in under the kind of signature it asked with',
      );
      server.send([SSH_Message_Userauth_Success().encode()]);
      expect(await ended, isNull);
      expect(key.signed, 1);
    });

    test('a key that the server takes and whose signature it then refuses: the next key is asked about', () async {
      final first = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final second = _Counted(fromFile('ecdsa-sha2-nistp256/ssh_host_ecdsa_key'));
      final (server, ended) = await start([first, second]);
      server.takesKey(await asks(server));
      expect((await asks(server)).signature, isNotNull);
      no(server);
      final two = await asks(server);
      expect(two.publicKey, second.toPublicKey().encode());
      expect(two.signature, isNull);
      no(server);
      expect(await ended, isA<SSHAuthFailError>());
      expect((first.signed, second.signed), (1, 0));
      expect(events.whereType<SSHEventAuthMethodAttempted>().map((e) => e.method), ['none', 'publickey', 'publickey']);
    });

    test('a key that signs somewhere else (an agent, a hardware key) is asked to sign only after the yes', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'), elsewhere: true);
      final (server, ended) = await start([key]);
      final question = await asks(server);
      expect(question.signature, isNull);
      await server.settle();
      expect(key.asked, 0);
      server.takesKey(question);
      expect((await asks(server)).signature, isNotNull);
      server.send([SSH_Message_Userauth_Success().encode()]);
      expect(await ended, isNull);
      expect((key.asked, key.signed), (1, 1));
    });

    test('a second yes to one question: the key signs once', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final (server, ended) = await start([key]);
      final question = await asks(server);
      server.takesKey(question);
      expect((await asks(server)).signature, isNotNull);
      server.takesKey(question);
      await nothingMore(server);
      expect(key.signed, 1);
      server.send([SSH_Message_Userauth_Success().encode()]);
      expect(await ended, isNull);
      expect(key.signed, 1);
    });

    test('a no, and a yes after it: the sign-in had ended with the no, and nothing is signed', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final (server, ended) = await start([key]);
      final question = await asks(server);
      no(server);
      expect(await ended, isA<SSHAuthFailError>());
      server.takesKey(question);
      await nothingMore(server);
      expect(key.signed, 0);
    });

    test('a server that lets in on the question alone, and says yes after it: the sign-in was over, and nothing is '
        'signed', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final (server, ended) = await start([key]);
      final question = await asks(server);
      expect(question.signature, isNull);
      server.send([SSH_Message_Userauth_Success().encode()]);
      expect(await ended, isNull);
      server.takesKey(question);
      await nothingMore(server);
      expect(key.signed, 0);
    });

    test('a yes that cannot be read is no yes: the connection ends, and nothing is signed', () async {
      final key = _Counted(fromFile('ssh-ed25519/ssh_host_ed25519_key'));
      final (server, ended) = await start([key]);
      expect((await asks(server)).signature, isNull);
      // A kind of signature that says it is eleven bytes long, and one byte of it.
      server.send([
        Uint8List.fromList([SSH_Message_Userauth_PkOk.messageId, 0, 0, 0, 11, 0x73]),
      ]);
      final failed = await ended;
      expect(failed, isA<SSHAuthAbortError>());
      expect((failed as SSHAuthAbortError).reason, isA<SSHPacketError>());
      await nothingMore(server);
      expect(key.signed, 0);
    });

    test('the yes, as a message: read as it is written', () {
      final key = Uint8List.fromList(List<int>.generate(51, (i) => i));
      final yes = SSH_Message_Userauth_PkOk.decode(
          SSH_Message_Userauth_PkOk(publicKeyAlgorithm: 'ssh-ed25519', publicKey: key).encode());
      expect(yes.publicKeyAlgorithm, 'ssh-ed25519');
      expect(yes.publicKey, key);
      expect(SSH_Message_Userauth_PkOk(publicKeyAlgorithm: 'ssh-ed25519', publicKey: key).encode().first, 60);
      expect('$yes', 'SSH_Message_Userauth_PkOk(publicKeyAlgorithm: ssh-ed25519)');
    });
  });

  group('with a real OpenSSH server', () {
    final real = RealOpenSshServer.fromEnvironment();
    String? unavailable;

    setUpAll(() async => unavailable = await real.unavailable());

    test('a key the server does not know, before the one it knows: the first signs nothing, the second signs in, '
        'and the server writes of a question it said yes to', () async {
      if (unavailable != null) return markTestSkipped(unavailable!);
      final stranger = _Counted(fromFile('ssh-ed25519/id_ed25519'));
      final known = _Counted(SSHKeyPair.fromPem(File(real.keyPath).readAsStringSync()).single);
      final client = SSHClient(
        await SSHSocket.connect(real.host, real.port, timeout: const Duration(seconds: 5)),
        username: real.user,
        identities: [stranger, known],
      );
      addTearDown(client.close);
      await client.authenticated.timeout(const Duration(seconds: 20));
      expect((stranger.signed, known.signed), (0, 1));
      // The port the server sees this connection come from, which is what its log names it by.
      final seenFrom = int.parse(utf8.decode(await client.run(r'echo $SSH_CLIENT')).split(' ')[1]);
      client.close();
      final lines = await real.logged(seenFrom);
      int written(String start) => lines.where((line) => line.startsWith(start)).length;
      expect(written('Failed publickey for USER'), 1, reason: lines.join('\n'));
      // "Postponed" is what the server writes of a question it said yes to, and waits for the signature.
      expect(written('Postponed publickey for USER'), 1, reason: lines.join('\n'));
      expect(written('Accepted publickey for USER'), 1, reason: lines.join('\n'));
    }, timeout: const Timeout(Duration(seconds: 60)));
  });
}

/// A key that counts how often it was signed with. [elsewhere]: it signs
/// as a key in an agent does, a moment after it was asked and never at
/// once ([asked] counts the asking).
class _Counted implements SSHKeyPair {
  _Counted(this._key, {this.elsewhere = false});

  final SSHKeyPair _key;
  final bool elsewhere;
  var asked = 0;
  var signed = 0;

  @override
  String get name => _key.name;

  @override
  String get type => _key.type;

  @override
  SSHHostKey toPublicKey() => _key.toPublicKey();

  @override
  SSHSignature sign(Uint8List data) {
    if (elsewhere) throw UnsupportedError('this key signs somewhere else');
    signed++;
    return _key.sign(data);
  }

  @override
  Future<SSHSignature> signAsync(Uint8List data) async {
    if (!elsewhere) return sign(data);
    asked++;
    await Future<void>.delayed(const Duration(milliseconds: 5));
    signed++;
    return _key.sign(data);
  }

  @override
  String toPem() => _key.toPem();
}
