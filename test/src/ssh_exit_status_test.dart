import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/message/msg_disconnect.dart';

import 'played_server.dart';

/// How a program ended is known when it ends at once.
///
/// A server says how a program ended in a request on the program's channel
/// (its exit status, or the signal that ended it), right before it closes
/// the channel. The client took such a request only once its session was
/// there, and the session was made after the server's yes to the program
/// had been waited for. A program that ends at once (`true`, `exit 3`, an
/// account whose shell prints a notice and leaves) has its end in the same
/// read as that yes: the request found nobody listening and was dropped,
/// and the session never learned how the program had ended. Whether that
/// happened depended on how the bytes arrived, so it happened now and then.
///
/// Held two ways: with a server played by the test, which says what it
/// sends message by message, and against a real OpenSSH server
/// (tool/test_sshd.sh, 127.0.0.1:2299) through a connection on which what
/// the server sends can be kept back and handed over in one read. Those
/// are skipped when the server is not running.
void main() {
  const patience = Duration(seconds: 20);

  Future<String> text(Stream<Uint8List> stream) async => utf8.decode(await stream.expand((b) => b).toList());

  group('a server played by the test', () {
    /// A plain client signed in to a played server, closed when the test is over.
    Future<PlayedServer> signedIn() async {
      final server = await PlayedServer.signedIn();
      addTearDown(server.client.close);
      return server;
    }

    /// What starting a program comes to: the session, or what it failed
    /// with. (Listened to from the start, so that a failure is seen where
    /// it is waited for and thrown at nobody before.)
    Future<Object> outcomeOf(Future<SSHSession> starting) =>
        starting.then<Object>((session) => session, onError: (Object error) => error).timeout(patience);

    test('the yes and the end of a command in one read: its exit status is known, and the channel is closed from '
        'here too', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('exit 3'));
      final channel = await server.confirmChannel();
      final request = await channel.nextRequest();
      expect(request.requestType, 'exec');
      expect(request.command, 'exit 3');
      server.send([channel.success, channel.exitStatus(3), channel.eof, channel.close]);
      final session = await outcome;
      expect(session, isA<SSHSession>());
      await (session as SSHSession).done.timeout(patience);
      expect(session.exitCode, 3);
      expect(session.exitSignal, isNull);
      expect(session.endedBecause, isNull, reason: 'closed in order');
      expect(await server.sent(SSH_Message_Channel_Close.messageId), isTrue);
    });

    test('a command whose connection ends under it: no exit status, and its session says that it was cut off',
        () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.success, channel.data('half\n')]);
      final session = await outcome as SSHSession;
      await server.settle();
      expect(session.endedBecause, isNull, reason: 'it still runs');
      server.hangUp();
      await session.done.timeout(patience);
      expect(session.exitCode, isNull);
      expect(session.exitSignal, isNull);
      expect(session.endedBecause, isA<SSHStateError>());
      expect(await text(session.stdout).timeout(patience), 'half\n');
    });

    test('the server ends the connection under a command, saying why: its session says so, in the server\'s words',
        () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.success]);
      final session = await outcome as SSHSession;
      server.send([SSH_Message_Disconnect(reasonCode: 11, description: 'Idle timeout').encode()]);
      await session.done.timeout(patience);
      expect(session.exitCode, isNull);
      expect(
        session.endedBecause,
        isA<SSHDisconnectError>()
            .having((e) => e.description, 'its words', 'Idle timeout')
            .having((e) => e.authentic, 'the server\'s own', isTrue),
      );
    });

    test('a command the server closes in order with no exit status, and the connection ended right behind it: not '
        'cut off', () async {
      // There are devices that say nothing of how a command ended, and some
      // close the connection as soon as the command is over.
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('show version'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.success, channel.data('version 12\n'), channel.eof, channel.close]);
      server.hangUp();
      final session = await outcome as SSHSession;
      await session.done.timeout(patience);
      expect(await text(session.stdout).timeout(patience), 'version 12\n');
      expect(session.exitCode, isNull);
      expect(session.endedBecause, isNull);
    });

    test('with what the command printed, on both of its streams', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([
        channel.success,
        channel.data('out\n'),
        channel.errorData('err\n'),
        channel.exitStatus(4),
        channel.eof,
        channel.close,
      ]);
      final session = await outcome as SSHSession;
      expect(await text(session.stdout).timeout(patience), 'out\n');
      expect(await text(session.stderr).timeout(patience), 'err\n');
      await session.done.timeout(patience);
      expect(session.exitCode, 4);
    });

    test('a command ended by a signal: the signal is known', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.success, channel.exitSignal('TERM'), channel.eof, channel.close]);
      final session = await outcome as SSHSession;
      await session.done.timeout(patience);
      expect(session.exitCode, isNull);
      expect(session.exitSignal?.signalName, 'TERM');
    });

    test('a shell that prints a notice and leaves: what it printed, and its exit status', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.shell(pty: null));
      final channel = await server.confirmChannel();
      expect((await channel.nextRequest()).requestType, 'shell');
      server.send([
        channel.success,
        channel.data('This account is currently not available.\n'),
        channel.exitStatus(1),
        channel.eof,
        channel.close,
      ]);
      final session = await outcome as SSHSession;
      expect(await text(session.stdout).timeout(patience), 'This account is currently not available.\n');
      await session.done.timeout(patience);
      expect(session.exitCode, 1);
    });

    test('the end in a later read than the yes, as it mostly comes: as before', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.success]);
      final session = await outcome as SSHSession;
      await server.settle();
      expect(session.exitCode, isNull, reason: 'it still runs');
      server.send([channel.data('built\n'), channel.exitStatus(2), channel.eof, channel.close]);
      expect(await text(session.stdout).timeout(patience), 'built\n');
      await session.done.timeout(patience);
      expect(session.exitCode, 2);
    });

    test('a server that says how the command ended before it says that it started it: known all the same',
        () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('exit 6'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.exitStatus(6), channel.success, channel.eof, channel.close]);
      final session = await outcome as SSHSession;
      await session.done.timeout(patience);
      expect(session.exitCode, 6);
    });

    test('a request the session does not know, which wants an answer, is answered no, in the same read as the '
        'yes too', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([
        channel.success,
        SSH_Message_Channel_Request(
          recipientChannel: channel.clientId,
          requestType: 'keepalive@openssh.com',
          wantReply: true,
        ).encode(),
      ]);
      expect(await outcome, isA<SSHSession>());
      final answer = SSH_Message_Channel_Failure.decode(await server.next(SSH_Message_Channel_Failure.messageId));
      expect(answer.recipientChannel, channel.serverId);
    });

    test('a command the server will not start: starting it fails with that, the channel is closed, and the '
        'connection goes on', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.failure]);
      expect(
        await outcome,
        isA<SSHChannelRequestError>().having((e) => e.message, 'message', 'Failed to execute'),
      );
      final closed = SSH_Message_Channel_Close.decode(await server.next(SSH_Message_Channel_Close.messageId));
      expect(closed.recipientChannel, channel.serverId);
      server.send([channel.close]);

      // The next command starts, on a channel of its own.
      final next = outcomeOf(server.client.execute('exit 0'));
      final second = await server.confirmChannel();
      await second.nextRequest();
      server.send([second.success, second.exitStatus(0), second.eof, second.close]);
      final session = await next as SSHSession;
      await session.done.timeout(patience);
      expect(session.exitCode, 0);
      expect(server.client.isClosed, isFalse);
    });

    test('the no and the end of the channel in one read: the same', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.execute('make'));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.failure, channel.close]);
      expect(
        await outcome,
        isA<SSHChannelRequestError>().having((e) => e.message, 'message', 'Failed to execute'),
      );
      await server.settle();
      expect(server.client.isClosed, isFalse);
    });

    test('a shell the server will not start fails as a shell that was not started', () async {
      final server = await signedIn();
      final outcome = outcomeOf(server.client.shell(pty: null));
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.failure]);
      expect(
        await outcome,
        isA<SSHChannelRequestError>().having((e) => e.message, 'message', 'Failed to start shell'),
      );
      expect(await server.sent(SSH_Message_Channel_Close.messageId), isTrue);
    });
  });

  // Against a real OpenSSH server. What it sends is kept back from the
  // moment the client asks for the program, and handed over in one read.
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
    // A key that runs one command whatever is asked for, a shell too: it
    // prints a word and ends at once, with the status 7.
    final forcedKeyPath = '$dir/client_forced_ed25519';

    Future<bool> serverUp(String key) async {
      try {
        final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
        s.destroy();
        return File(key).existsSync();
      } catch (_) {
        return false;
      }
    }

    /// A client signed in with [key], on a connection that keeps back what
    /// the server sends from the moment the client asks for what [holdAt]
    /// names (a line of its trace says so, before the request goes out).
    Future<(SSHClient, _OneRead)> connect({String? key, String? holdAt}) async {
      final gate = _OneRead(await SSHSocket.connect(host, port));
      final client = SSHClient(
        gate,
        username: user,
        identities: SSHKeyPair.fromPem(File(key ?? keyPath).readAsStringSync()),
        printTrace: (line) {
          if (holdAt != null && line != null && line.startsWith('->') && line.contains(holdAt)) gate.hold = true;
        },
      );
      addTearDown(client.close);
      await client.authenticated.timeout(patience);
      return (client, gate);
    }

    test('a command that ends at once, its start and its end in one read: its exit status is known', () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, gate) = await connect(holdAt: 'requestType: exec');
      final starting = client.execute('exit 3');
      await gate.settled();
      gate.release();
      final session = await starting.timeout(patience);
      await session.done.timeout(patience);
      expect(session.exitCode, 3);
      expect(session.exitSignal, isNull);
    });

    test('with what it printed, on both of its streams', () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, gate) = await connect(holdAt: 'requestType: exec');
      final starting = client.execute('echo out; echo err >&2; exit 4');
      await gate.settled();
      gate.release();
      final session = await starting.timeout(patience);
      final out = text(session.stdout);
      final err = text(session.stderr);
      await session.done.timeout(patience);
      expect(await out.timeout(patience), 'out\n');
      expect(await err.timeout(patience), 'err\n');
      expect(session.exitCode, 4);
    });

    test('a command ended by a signal: the signal is known', () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, gate) = await connect(holdAt: 'requestType: exec');
      final starting = client.execute(r'kill -TERM $$');
      await gate.settled();
      gate.release();
      final session = await starting.timeout(patience);
      await session.done.timeout(patience);
      expect(session.exitCode, isNull);
      expect(session.exitSignal?.signalName, 'TERM');
    });

    test('a command run to its end in one call says how it ended', () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, gate) = await connect(holdAt: 'requestType: exec');
      final running = client.runWithResult('echo done; exit 5');
      await gate.settled();
      gate.release();
      final result = await running.timeout(patience);
      expect(utf8.decode(result.stdout), 'done\n');
      expect(result.exitCode, 5);
    });

    test('a shell that prints a word and leaves: what it printed, and its exit status', () async {
      if (!await serverUp(forcedKeyPath)) {
        markTestSkipped('the test OpenSSH server or its fourth key is not there');
        return;
      }
      final (client, gate) = await connect(key: forcedKeyPath, holdAt: 'requestType: shell');
      final starting = client.shell(pty: null);
      await gate.settled();
      gate.release();
      final session = await starting.timeout(patience);
      final out = text(session.stdout);
      await session.done.timeout(patience);
      expect(await out.timeout(patience), 'forced\n');
      expect(session.exitCode, 7);
    });

    test('as the bytes come: forty commands in a row, each with its own exit status', () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, _) = await connect();
      final statuses = <int?>[];
      for (var i = 0; i < 40; i++) {
        final session = await client.execute('exit ${i % 7}').timeout(patience);
        await session.done.timeout(patience);
        statuses.add(session.exitCode);
      }
      expect(statuses, [for (var i = 0; i < 40; i++) i % 7]);
    });

    test('as the bytes come: a command that runs for a while says how it ended', () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, _) = await connect();
      final session = await client.execute('sleep 0.3; echo late; exit 9').timeout(patience);
      final out = text(session.stdout);
      await session.done.timeout(patience);
      expect(await out.timeout(patience), 'late\n');
      expect(session.exitCode, 9);
    });

    test('a command that ends its own connection: no exit status, and its session says that it was cut off',
        () async {
      if (!await serverUp(keyPath)) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, _) = await connect();
      // The server's process for this connection, ended as a host that goes down ends it.
      final session = await client.execute(r'echo half; sleep 0.5; kill -KILL $PPID; sleep 5').timeout(patience);
      final out = text(session.stdout);
      await session.done.timeout(patience);
      expect(await out.timeout(patience), 'half\n');
      expect(session.exitCode, isNull);
      expect(session.endedBecause, isNotNull);
    });

    test('a key that runs one command runs it whatever is asked for', () async {
      if (!await serverUp(forcedKeyPath)) {
        markTestSkipped('the test OpenSSH server or its fourth key is not there');
        return;
      }
      final (client, _) = await connect(key: forcedKeyPath);
      final result = await client.runWithResult('exit 0').timeout(patience);
      expect(utf8.decode(result.stdout), 'forced\n');
      expect(result.exitCode, 7);
    });
  });
}

/// A real socket whose incoming data can be kept back and handed over in
/// one read, as it arrives on a connection that was slow for a moment.
class _OneRead implements SSHSocket {
  _OneRead(this._socket) {
    _socket.stream.listen(
      (data) {
        if (hold) {
          _kept.add(data);
          _lastKept = DateTime.now();
        } else {
          _incoming.add(data);
        }
      },
      onError: _incoming.addError,
      onDone: _incoming.close,
    );
  }

  final SSHSocket _socket;
  final _incoming = StreamController<Uint8List>(sync: true);
  final _kept = BytesBuilder();
  DateTime? _lastKept;

  /// While true, what the server sends is kept back.
  var hold = false;

  /// Waits until the server has sent something and then nothing more for a
  /// moment: its yes to the program, and all that the program's end brings.
  Future<void> settled() async {
    final waited = Stopwatch()..start();
    while (true) {
      final last = _lastKept;
      if (last != null && DateTime.now().difference(last) > const Duration(milliseconds: 300)) return;
      if (waited.elapsed > const Duration(seconds: 15)) fail('the server sent nothing to keep back');
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  /// Hands over all that was kept back, as one read, and keeps nothing back
  /// from here on.
  void release() {
    hold = false;
    _incoming.add(_kept.takeBytes());
  }

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
