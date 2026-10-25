import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/ssh_keepalive.dart';
import 'package:zest_ssh_core/src/utils/async_queue.dart';

/// Whatever waits for a reply that will never come is told so, where it
/// waited for ever: the queue replies are handed out by can be ended
/// (AsyncQueue.close), a request made of a server that refuses it is an
/// error where it is made (a subsystem the server does not have), a request
/// to the server as a whole that is still unanswered when the connection
/// ends fails then, and a keep-alive that fails on a connection that ended
/// throws at nobody.
void main() {
  group('a queue that can be ended', () {
    test('hands out what was added, in order, to whoever asks before or after', () async {
      final queue = AsyncQueue<int>();
      final first = queue.next;
      queue
        ..add(1)
        ..add(2);
      expect(await first, 1);
      expect(await queue.next, 2);
      expect(queue.isClosed, isFalse);
    });

    test('ended: those waiting get the error, each of them, and so does whoever asks later', () async {
      final queue = AsyncQueue<int>();
      final waiting = [Future<int>.value(queue.next), Future<int>.value(queue.next)];
      expect(queue.hasWaiters, isTrue);
      final ended = StateError('ended');
      queue.close(ended);
      expect(queue.isClosed, isTrue);
      expect(queue.hasWaiters, isFalse);
      for (final wait in waiting) {
        await expectLater(wait, throwsA(same(ended)));
      }
      await expectLater(Future<int>.value(queue.next), throwsA(same(ended)));
    });

    test('ended: what was added before and not taken yet is still handed out, then the error', () async {
      final queue = AsyncQueue<int>()
        ..add(7)
        ..add(8);
      final ended = StateError('ended');
      queue.close(ended);
      expect(await queue.next, 7);
      expect(await queue.next, 8);
      await expectLater(Future<int>.value(queue.next), throwsA(same(ended)));
    });

    test('ended: what is added later is dropped, and ending it again changes nothing', () async {
      final queue = AsyncQueue<int>();
      final ended = StateError('ended');
      queue
        ..close(ended)
        ..add(9)
        ..close(StateError('again'));
      await expectLater(Future<int>.value(queue.next), throwsA(same(ended)));
    });
  });

  test('a keep-alive whose ping fails throws at nobody, and goes on at its pace', () async {
    final uncaught = <Object>[];
    var pings = 0;
    late SSHKeepAlive keepAlive;
    await runZonedGuarded(() async {
      keepAlive = SSHKeepAlive(
        interval: const Duration(milliseconds: 20),
        ping: () async {
          pings++;
          throw SSHStateError('Connection closed before the request was answered');
        },
      )..start();
      await Future<void>.delayed(const Duration(milliseconds: 150));
      keepAlive.stop();
    }, (error, stack) => uncaught.add(error));
    expect(pings, greaterThan(2));
    expect(uncaught, isEmpty);
  });

  // Against a real OpenSSH server (tool/test_sshd.sh, 127.0.0.1:2299).
  // Skipped when it is not running.
  group('a real server', () {
    final env = Platform.environment;
    final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
    final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
    final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
    final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
        (Platform.isWindows
            ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test'
            : '${env['HOME']}/zestssh-sshd-test');
    final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';
    // A key the server gives no terminal.
    final restrictedKeyPath = env['ZESTSSH_TEST_SSHD_RESTRICTED_KEY'] ?? '$dir/client_restricted_ed25519';

    Future<bool> serverUp() async {
      try {
        final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
        s.destroy();
        return File(keyPath).existsSync() && File(restrictedKeyPath).existsSync();
      } catch (_) {
        return false;
      }
    }

    /// A client signed in to the server. With [quietAfter], nothing the
    /// server says reaches it once it has sent a message whose description
    /// has that text in it: the message goes out, and no reply comes back.
    Future<(SSHClient, _GatedSocket)> connect({bool restricted = false, String? quietAfter}) async {
      final socket = _GatedSocket(await SSHSocket.connect(host, port));
      final identities = SSHKeyPair.fromPem(File(restricted ? restrictedKeyPath : keyPath).readAsStringSync());
      final client = SSHClient(
        socket,
        username: user,
        identities: identities,
        printTrace: (line) {
          if (quietAfter != null && line != null && line.startsWith('->') && line.contains(quietAfter)) {
            socket.hold = true;
          }
        },
      );
      await client.authenticated;
      return (client, socket);
    }

    test('a subsystem the server does not have is refused where it is asked for', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, _) = await connect();
      addTearDown(client.close);
      await expectLater(
        client.subsystem('no-such-subsystem').timeout(const Duration(seconds: 10)),
        throwsA(isA<SSHChannelRequestError>().having((e) => e.message, 'message', contains('no-such-subsystem'))),
      );
      // The session goes on: the refusal was the request's, not the connection's.
      final answer = await client.run('echo still-here').timeout(const Duration(seconds: 10));
      expect(String.fromCharCodes(answer), contains('still-here'));
    });

    // A server allows a connection only so many sessions at a time (OpenSSH:
    // ten, unless told otherwise), and a channel left open there after a
    // refusal counts as one of them for as long as the connection lasts. So
    // each refusal is asked for more often than that: every time it is the
    // refusal that comes back, and never "no more sessions".
    const more = 14;
    const notTaken = {'ZEST_NOT_TAKEN': '1'};
    const x11 = SSHX11Config(authenticationCookie: '00112233445566778899aabbccddeeff');
    const noSubsystem = 'The server refused the "no-such-subsystem" subsystem';

    // What is refused, how it is asked for, what the refusal says, and
    // whether it takes the restricted key. (Agent forwarding that is refused
    // ends no session: ssh_agent_refused_test.dart.)
    final refusals = <(String, Future<Object?> Function(SSHClient), String, bool)>[
      ('a subsystem', (c) => c.subsystem('no-such-subsystem'), noSubsystem, false),
      ('SFTP', (c) => c.sftp(), 'The server refused the "sftp" subsystem', false),
      (
        'an environment variable before a command',
        (c) => c.execute('true', environment: notTaken),
        'Failed to set environment variable: ZEST_NOT_TAKEN',
        false,
      ),
      (
        'an environment variable before a shell',
        (c) => c.shell(pty: null, environment: notTaken),
        'Failed to set environment variable: ZEST_NOT_TAKEN',
        false,
      ),
      (
        'X11 forwarding before a command',
        (c) => c.execute('true', x11: x11),
        'Failed to request x11 forwarding',
        false,
      ),
      (
        'X11 forwarding before a shell',
        (c) => c.shell(pty: null, x11: x11),
        'Failed to request x11 forwarding',
        false,
      ),
      (
        'a terminal before a command',
        (c) => c.execute('true', pty: const SSHPtyConfig()),
        'Failed to start pty',
        true,
      ),
      ('a terminal before a shell', (c) => c.shell(), 'Failed to start pty', true),
    ];

    for (final (what, ask, message, restricted) in refusals) {
      test('refused, $what leaves no channel open on the server', () async {
        if (!await serverUp()) {
          markTestSkipped('the test OpenSSH server is not running');
          return;
        }
        final (client, _) = await connect(restricted: restricted);
        addTearDown(client.close);
        for (var i = 0; i < more; i++) {
          await expectLater(
            ask(client).timeout(const Duration(seconds: 10)),
            throwsA(isA<SSHChannelRequestError>().having((e) => e.message, 'message', message)),
            reason: 'the ${i + 1}. time',
          );
        }
        // And a session still opens.
        final answer = await client.run('echo still-here').timeout(const Duration(seconds: 10));
        expect(String.fromCharCodes(answer), contains('still-here'));
      });
    }

    /// How [asked] has ended by now: null while it waits, 'answered', or
    /// what it failed with.
    Object? Function() watch(Future<Object?> asked) {
      Object? ended;
      unawaited(asked.then<void>((_) => ended = 'answered', onError: (Object e) => ended = e));
      return () => ended;
    }

    Future<void> aMoment() => Future<void>.delayed(const Duration(milliseconds: 300));

    final closed = isA<SSHStateError>()
        .having((e) => e.message, 'message', 'Connection closed before the request was answered');
    const reset = SocketException('Connection reset by peer');
    final broken = isA<SSHSocketError>().having((e) => e.error, 'error', same(reset));

    test('a request to the server that is still unanswered when the connection ends fails then', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, socket) = await connect();
      // Nothing the server says reaches the client from here on: the
      // request goes out, and its reply does not come back.
      socket.hold = true;
      final ended = watch(client.forwardRemote(host: '127.0.0.1', port: 0));
      await aMoment();
      expect(ended(), isNull, reason: 'it waits for its reply');
      // The connection ends.
      socket.destroy();
      await aMoment();
      expect(ended(), closed, reason: 'and is told so, where it waited for ever');
      // A keep-alive on that connection fails as well, and does not wait.
      await expectLater(client.ping().timeout(const Duration(seconds: 2)), throwsA(isA<SSHError>()));
    });

    test('the network breaks under such a request: it fails with what the network said', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, socket) = await connect();
      addTearDown(client.close);
      socket.hold = true;
      final forward = watch(client.forwardRemote(host: '127.0.0.1', port: 0));
      final alive = watch(client.ping());
      await aMoment();
      expect([forward(), alive()], [isNull, isNull]);
      socket.breakWith(reset);
      await aMoment();
      expect(forward(), broken);
      expect(alive(), broken);
    });

    test('a remote forward closed on a connection that ends before the server answered, or has ended: an error '
        'for nobody', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      // Closing a forward asks the server to stop listening and does not
      // wait for its answer: what becomes of the question has nobody to
      // catch it.
      final uncaught = <Object>[];
      await runZonedGuarded(() async {
        // The connection ends with the question on its way.
        final (client, socket) = await connect();
        final forward = await client.forwardRemote(host: '127.0.0.1', port: 0);
        expect(forward, isNotNull);
        socket.hold = true;
        forward!.close();
        await aMoment();
        socket.destroy();
        await aMoment();

        // The connection has ended before the forward is closed.
        final (other, otherSocket) = await connect();
        final late = await other.forwardRemote(host: '127.0.0.1', port: 0);
        otherSocket.destroy();
        await aMoment();
        late!.close();
        await aMoment();
      }, (error, stack) => uncaught.add(error));
      expect(uncaught, isEmpty);
    });

    test('a terminal asked for and not answered when the connection ends: the shell fails then, and says the '
        'connection ended', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      // The channel opens, the request for a terminal goes out, and from
      // then on the server is not heard.
      final (client, socket) = await connect(quietAfter: 'requestType: pty-req');
      final ended = watch(client.shell());
      await aMoment();
      expect(socket.hold, isTrue, reason: 'the request for a terminal was sent');
      expect(ended(), isNull, reason: 'it waits for its reply');
      socket.destroy();
      await aMoment();
      expect(ended(), closed);
    });

    test('the client is closed with a terminal asked for and not answered: the same', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, socket) = await connect(quietAfter: 'requestType: pty-req');
      final ended = watch(client.shell());
      await aMoment();
      expect(socket.hold, isTrue, reason: 'the request for a terminal was sent');
      expect(ended(), isNull, reason: 'it waits for its reply');
      client.close();
      await aMoment();
      expect(ended(), closed);
    });

    test('a channel still being opened when the connection ends: what ended the connection, too', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final opening = isA<SSHStateError>()
          .having((e) => e.message, 'message', 'Connection closed while waiting for channel open');
      for (final (what, end, expected) in <(String, void Function(_GatedSocket), Matcher)>[
        ('the network breaks', (s) => s.breakWith(reset), broken),
        ('the connection closes', (s) => s.destroy(), opening),
      ]) {
        final (client, socket) = await connect();
        addTearDown(client.close);
        // The request to open a channel goes out, and its answer is not heard.
        socket.hold = true;
        final ended = watch(client.execute('true'));
        await aMoment();
        expect(ended(), isNull, reason: what);
        end(socket);
        await aMoment();
        expect(ended(), expected, reason: what);
      }
    });

    test('the same with the network breaking, for a command and for SFTP: what the network said', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      for (final (what, sent, ask) in <(String, String, Future<Object?> Function(SSHClient))>[
        ('a command', 'requestType: exec', (c) => c.execute('true')),
        ('SFTP', 'requestType: subsystem', (c) => c.sftp()),
      ]) {
        final (client, socket) = await connect(quietAfter: sent);
        addTearDown(client.close);
        final ended = watch(ask(client));
        await aMoment();
        expect(socket.hold, isTrue, reason: 'the request for $what was sent');
        expect(ended(), isNull, reason: what);
        socket.breakWith(reset);
        await aMoment();
        expect(ended(), broken, reason: what);
      }
    });
  });
}

/// A real socket whose incoming data can be held back, as on a connection
/// that has gone quiet.
class _GatedSocket implements SSHSocket {
  _GatedSocket(this._socket) {
    _socket.stream.listen(
      (data) {
        if (!hold) _incoming.add(data);
      },
      onError: _incoming.addError,
      onDone: _incoming.close,
    );
  }

  final SSHSocket _socket;
  final _incoming = StreamController<Uint8List>();

  /// While true, what the server sends is dropped.
  bool hold = false;

  /// The network breaks: the connection ends with [error].
  void breakWith(Object error) => _incoming.addError(error);

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _socket.sink;

  @override
  Future<void> get done => _socket.done;

  @override
  Future<void> flush() => _socket.flush();

  @override
  Future<void> close() => _socket.close();

  @override
  void destroy() => _socket.destroy();
}
