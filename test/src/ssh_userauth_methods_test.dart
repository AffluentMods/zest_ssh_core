// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_userauth.dart' show SSHUserInfoPrompt;
import 'package:zest_ssh_core/src/transport/ssh_events.dart';

import 'played_server.dart';

/// Which ways of signing in a client tries, and in what order.
///
/// A server says, with every sign-in it refuses, which ways it takes
/// ("authentications that can continue", RFC 4252, 5.1). The client read
/// that list and dropped it. It tried what it had in an order of its own:
/// every key, then the password, then the server's questions, then "none".
/// So a password went to a server that had just said it takes only keys,
/// each of those tries counted against the tries a server allows a
/// connection, a server that lets everybody in was sent the key and the
/// password first, and after a first step of two that was accepted the
/// client went on with whatever it had next, not with what the server named.
///
/// The real server is the test sshd of tool/test_sshd.sh (127.0.0.1:2299),
/// which takes keys and nothing else; its tests skip themselves when it is
/// not running.
void main() {
  final strangerPem = File('test/fixtures/ssh-ed25519/id_ed25519').readAsStringSync();

  group('a server played by the test', () {
    // The client of the test that runs, and what it said of its sign-in as it went.
    late SSHClient client;
    late List<SSHEvent> events;

    /// A client that has what it is said to have, on a connection to a
    /// played server that has taken it as far as the sign-in.
    Future<(PlayedServer, Future<Object?>, _Asked)> start({
      int keys = 1,
      bool password = true,
      bool questions = true,
    }) async {
      final server = PlayedServer();
      final asked = _Asked();
      client = SSHClient(
        server.socket,
        username: 'deploy',
        algorithms: PlayedServer.algorithms,
        keepAliveInterval: null,
        identities: [for (var i = 0; i < keys; i++) ...SSHKeyPair.fromPem(strangerPem)],
        onPasswordRequest: password
            ? () {
                asked.password++;
                return 'the password';
              }
            : null,
        onUserInfoRequest: questions
            ? (request) {
                asked.questions++;
                return [for (final _ in request.prompts) 'an answer'];
              }
            : null,
      );
      addTearDown(client.close);
      events = [];
      final listening = client.events.listen(events.add);
      addTearDown(listening.cancel);
      // How the sign-in ended: null where it was signed in, else what it failed with.
      final ended = client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
      await server.greet();
      return (server, ended, asked);
    }

    Future<SSH_Message_Userauth_Request> asks(PlayedServer server) async =>
        SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));

    void refuse(PlayedServer server, List<String> takes, {bool partly = false}) =>
        server.send([SSH_Message_Userauth_Failure(methodsLeft: takes, partialSuccess: partly).encode()]);

    void letIn(PlayedServer server) => server.send([SSH_Message_Userauth_Success().encode()]);

    Future<void> nothingMore(PlayedServer server) async =>
        expect(await server.sent(SSH_Message_Userauth_Request.messageId), isFalse, reason: 'nothing more is asked');

    test('it asks first which ways the server takes, and offers nothing with that', () async {
      final (server, _, asked) = await start();
      final first = await asks(server);
      expect((first.methodName, first.user, first.serviceName), ('none', 'deploy', 'ssh-connection'));
      await nothingMore(server);
      expect((asked.password, asked.questions), (0, 0));
      // What it says it has, in the order it would try them, after the question.
      expect(events.whereType<SSHEventAuthStarted>().single.availableMethods,
          ['none', 'publickey', 'password', 'keyboard-interactive']);
      expect(events.whereType<SSHEventAuthMethodAttempted>().map((e) => e.method), ['none']);
    });

    test('a server that takes only keys is offered the key, and never the password or an answer', () async {
      final (server, ended, asked) = await start();
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['publickey']);
      final key = await asks(server);
      expect(key.methodName, 'publickey');
      // (Asked about first, and signed with for a server that takes it: ssh_publickey_asked_first_test.dart.)
      expect(key.signature, isNull);
      refuse(server, ['publickey']);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      await nothingMore(server);
      expect((asked.password, asked.questions), (0, 0));
      // What was tried, and what the server takes, for whoever says why it failed.
      expect((failed as SSHAuthFailError).methodsTried, ['publickey']);
      expect(failed.serverTakes, ['publickey']);
      expect('$failed', 'SSHAuthFailError(All authentication methods failed)');
      // Both are what they were when it failed, whoever is handed them.
      expect(() => failed.methodsTried.add('password'), throwsUnsupportedError);
      expect(() => failed.serverTakes!.add('password'), throwsUnsupportedError);
    });

    test('a client that has only a password for it tries nothing, and says what the server takes', () async {
      final (server, ended, asked) = await start(keys: 0, questions: false);
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['publickey']);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      await nothingMore(server);
      expect(asked.password, 0, reason: 'the password is not sent to a server that takes none');
      expect((failed as SSHAuthFailError).methodsTried, isEmpty);
      expect(failed.serverTakes, ['publickey']);
    });

    test('a server that takes a password and questions: the key is not offered, the password is, and then the answers',
        () async {
      final (server, ended, asked) = await start();
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['password', 'keyboard-interactive']);
      final password = await asks(server);
      expect((password.methodName, password.password), ('password', 'the password'));
      // It refuses the password, and still takes answers.
      refuse(server, ['keyboard-interactive']);
      expect((await asks(server)).methodName, 'keyboard-interactive');
      server.send([
        SSH_Message_Userauth_InfoRequest(
          name: '',
          instruction: '',
          lang: '',
          prompts: [SSHUserInfoPrompt('Verification code: ', false)],
        ).encode(),
      ]);
      final answers = SSH_Message_Userauth_InfoResponse.decode(
          await server.next(SSH_Message_Userauth_InfoResponse.messageId));
      expect(answers.responses, ['an answer']);
      letIn(server);
      expect(await ended, isNull);
      expect((asked.password, asked.questions), (1, 1));
    });

    test('after a first step that the server accepts, the next is the one it names', () async {
      final (server, ended, asked) = await start(keys: 2);
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['publickey']);
      final key = await asks(server);
      expect(key.methodName, 'publickey');
      server.takesKey(key);
      expect((await asks(server)).signature, isNotNull);
      // The key is right, and is not all: the server's questions come next. Not the other key, nor the password.
      refuse(server, ['keyboard-interactive'], partly: true);
      expect((await asks(server)).methodName, 'keyboard-interactive');
      letIn(server);
      expect(await ended, isNull);
      await nothingMore(server);
      expect(asked.password, 0);
    });

    test('several keys are offered one after another while the server takes keys', () async {
      final (server, ended, _) = await start(keys: 3, password: false, questions: false);
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['publickey', 'password']);
      for (var i = 0; i < 2; i++) {
        expect((await asks(server)).methodName, 'publickey');
        refuse(server, ['publickey', 'password']);
      }
      final third = await asks(server);
      expect(third.methodName, 'publickey');
      server.takesKey(third);
      expect((await asks(server)).signature, isNotNull);
      letIn(server);
      expect(await ended, isNull);
    });

    test('a server that lets everybody in is sent no key and no password', () async {
      final (server, ended, asked) = await start();
      expect((await asks(server)).methodName, 'none');
      letIn(server);
      expect(await ended, isNull);
      await nothingMore(server);
      expect((asked.password, asked.questions), (0, 0));
      expect(client.diagnostics.authMethodSucceeded, 'none');
      expect(events.whereType<SSHEventAuthMethodSucceeded>().single.method, 'none');
    });

    test('a server that takes nothing, or nothing this client has: it fails at once, saying what the server takes',
        () async {
      for (final takes in [
        <String>[],
        ['hostbased', 'gssapi-with-mic'],
      ]) {
        final (server, ended, asked) = await start();
        expect((await asks(server)).methodName, 'none');
        refuse(server, takes);
        final failed = await ended;
        expect(failed, isA<SSHAuthFailError>(), reason: '$takes');
        await nothingMore(server);
        expect((asked.password, asked.questions), (0, 0));
        expect((failed as SSHAuthFailError).methodsTried, isEmpty);
        expect(failed.serverTakes, takes);
      }
    });

    test('what was tried is named once each, in the order it was tried: two keys, then answers', () async {
      final (server, ended, asked) = await start(keys: 2, password: false);
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['publickey', 'keyboard-interactive']);
      for (var i = 0; i < 2; i++) {
        expect((await asks(server)).methodName, 'publickey');
        refuse(server, ['publickey', 'keyboard-interactive']);
      }
      // No key is left: its questions, which it then refuses the answers to.
      expect((await asks(server)).methodName, 'keyboard-interactive');
      refuse(server, ['publickey', 'keyboard-interactive']);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      await nothingMore(server);
      expect((failed as SSHAuthFailError).methodsTried, ['publickey', 'keyboard-interactive']);
      expect(failed.serverTakes, ['publickey', 'keyboard-interactive']);
      expect(asked.questions, 0, reason: 'it asked nothing before it refused');
    });

    test('a server that goes on refusing key after key is given up on, and the failure still says what was tried',
        () async {
      final (server, ended, _) = await start(keys: 30, password: false, questions: false);
      expect((await asks(server)).methodName, 'none');
      var keys = 0;
      Object? failed;
      unawaited(ended.then((e) => failed = e));
      refuse(server, ['publickey']);
      while (failed == null && keys < 30) {
        expect((await asks(server)).methodName, 'publickey');
        keys++;
        refuse(server, ['publickey']);
        await server.settle();
      }
      expect(failed, isA<SSHAuthFailError>());
      expect(keys, 20, reason: 'as many tries as a client makes of one sign-in');
      expect('$failed', 'SSHAuthFailError(Max authentication attempts (20) exceeded)');
      expect((failed! as SSHAuthFailError).methodsTried, ['publickey']);
      expect((failed! as SSHAuthFailError).serverTakes, ['publickey']);
    });

    test('a failure that is made with its words alone has tried nothing, and knows nothing of a server', () {
      final plain = SSHAuthFailError('All authentication methods failed');
      expect(plain.methodsTried, isEmpty);
      expect(plain.serverTakes, isNull);
    });

    test('a server whose list changes is followed: a way it stops taking is not tried again', () async {
      final (server, ended, asked) = await start(keys: 2);
      expect((await asks(server)).methodName, 'none');
      refuse(server, ['publickey', 'password']);
      expect((await asks(server)).methodName, 'publickey');
      // It has had enough of keys.
      refuse(server, ['password']);
      expect((await asks(server)).methodName, 'password');
      refuse(server, ['password']);
      final failed = await ended;
      expect(failed, isA<SSHAuthFailError>());
      await nothingMore(server);
      expect((failed as SSHAuthFailError).methodsTried, ['publickey', 'password']);
      expect(failed.serverTakes, ['password']);
      expect((asked.password, asked.questions), (1, 0));
    });
  });

  group('a real server that takes only keys', () {
    final env = Platform.environment;
    final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
    final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
    final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
    final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
        (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
    final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';
    String? unavailable;

    setUpAll(() async {
      try {
        if (!File(keyPath).existsSync()) throw StateError('no key at $keyPath');
        (await Socket.connect(host, port, timeout: const Duration(seconds: 2))).destroy();
      } catch (e) {
        unavailable = 'no test sshd at $host:$port ($e)';
      }
    });

    /// How a sign-in with [keys] (and a password, and answers to questions,
    /// where said) ends, and what was asked of the client for it.
    Future<(Object?, _Asked)> signIn(List<SSHKeyPair> keys, {bool password = true, bool questions = true}) async {
      final asked = _Asked();
      final client = SSHClient(
        await SSHSocket.connect(host, port, timeout: const Duration(seconds: 5)),
        username: user,
        identities: keys,
        onPasswordRequest: password
            ? () {
                asked.password++;
                return 'not-the-password';
              }
            : null,
        onUserInfoRequest: questions
            ? (request) {
                asked.questions++;
                return [for (final _ in request.prompts) 'no'];
              }
            : null,
      );
      addTearDown(client.close);
      final ended = await client.authenticated
          .then<Object?>((_) => null, onError: (Object e) => e)
          .timeout(const Duration(seconds: 20));
      return (ended, asked);
    }

    test('a key it knows signs in, with nothing else asked for', () async {
      if (unavailable != null) return markTestSkipped(unavailable!);
      final (ended, asked) = await signIn(SSHKeyPair.fromPem(File(keyPath).readAsStringSync()));
      expect(ended, isNull);
      expect((asked.password, asked.questions), (0, 0));
    });

    test('a key it does not know: refused, and the password that is there too is never sent', () async {
      if (unavailable != null) return markTestSkipped(unavailable!);
      final (ended, asked) = await signIn(SSHKeyPair.fromPem(strangerPem));
      expect(ended, isA<SSHAuthFailError>());
      expect((asked.password, asked.questions), (0, 0));
      final failed = ended! as SSHAuthFailError;
      expect(failed.methodsTried, ['publickey']);
      expect(failed.serverTakes, ['publickey']);
    });

    test('a password alone: nothing is tried, and the failure says that the server takes keys', () async {
      if (unavailable != null) return markTestSkipped(unavailable!);
      final (ended, asked) = await signIn(const [], questions: false);
      expect(ended, isA<SSHAuthFailError>());
      expect(asked.password, 0);
      final failed = ended! as SSHAuthFailError;
      expect(failed.methodsTried, isEmpty);
      expect(failed.serverTakes, ['publickey']);
    });
  });
}

/// How often the client was asked for its password, and for answers to the
/// server's questions.
class _Asked {
  int password = 0;
  int questions = 0;
}
