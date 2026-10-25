import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/ssh_keepalive.dart';

/// Keep-alives that notice silence. The client sent a keep-alive every so
/// often and never looked at whether anything came back: a connection that
/// had gone quiet (a network that drops everything, a host that froze, a
/// phone that changed networks) stayed "connected", with a terminal that
/// took typing and showed nothing, until the system itself gave the
/// connection up, which can take a long time or for ever.
///
/// Now three keep-alives in a row with nothing at all coming from the
/// server end the connection, with an error that says so.
void main() {
  group('the keep-alive by itself', () {
    const interval = Duration(seconds: 15);

    test('a server that answers: it goes on pinging, and says nothing', () async {
      final k = _Model();
      await k.ticks(12);
      expect(k.pings, 12);
      expect(k.quiet, isEmpty);
    });

    test('it answered, and then nothing comes: after three pings it says the connection is quiet, once, and how long',
        () async {
      final k = _Model();
      await k.ticks(2);
      k.answering = false;
      await k.ticks(3);
      expect(k.quiet, isEmpty, reason: 'three pings are out, and may yet be answered');
      expect(k.pings, 5);
      await k.ticks(1);
      expect(k.quiet, [interval * 3]);
      expect(k.pings, 5, reason: 'no ping with that');
    });

    test('heard again after two pings went unanswered: the count starts over', () async {
      final k = _Model();
      await k.ticks(1);
      k.answering = false;
      await k.ticks(2);
      // Something comes that is no answer to a ping: what a program on the host prints.
      k.heard++;
      await k.ticks(3);
      expect(k.quiet, isEmpty, reason: 'two, then something came, then three more pings out');
      await k.ticks(1);
      expect(k.quiet, [interval * 3]);
    });

    test('heard at the very tick that would have given it up: it goes on', () async {
      final k = _Model();
      await k.ticks(1);
      k.answering = false;
      await k.ticks(3);
      k.heard++;
      await k.ticks(1);
      expect(k.quiet, isEmpty);
    });

    test('an answer that comes late counts: a ping answered after two more went out starts the count over', () async {
      final k = _Model();
      await k.ticks(1);
      k.answering = false;
      await k.ticks(3);
      // The answer to one of the three arrives (and with it, something is heard).
      k.answerOne();
      await Future<void>.delayed(Duration.zero);
      await k.ticks(3);
      expect(k.quiet, isEmpty);
      await k.ticks(1);
      expect(k.quiet, [interval * 3]);
    });

    test('a server that never answered a keep-alive is not judged by them: its sessions are left alone', () async {
      final k = _Model()..answering = false;
      await k.ticks(40);
      expect(k.quiet, isEmpty);
      expect(k.pings, 40, reason: 'it goes on pinging, which keeps what is on the way from forgetting the connection');
      // What it prints is heard, and changes nothing about that.
      k.heard++;
      await k.ticks(10);
      expect(k.quiet, isEmpty);
    });

    test('how many may go unanswered is whoever holds the connection\'s to say', () async {
      final one = _Model(maxUnanswered: 1);
      await one.ticks(1);
      one.answering = false;
      await one.ticks(1);
      expect(one.quiet, isEmpty);
      await one.ticks(1);
      expect(one.quiet, [interval]);

      final five = _Model(maxUnanswered: 5);
      await five.ticks(1);
      five.answering = false;
      await five.ticks(5);
      expect(five.quiet, isEmpty);
      await five.ticks(1);
      expect(five.quiet, [interval * 5]);
    });

    test('with no way to tell what came, it pings and never calls a connection quiet', () async {
      final k = _Model(hears: false);
      await k.ticks(2);
      k.answering = false;
      await k.ticks(10);
      expect(k.pings, 12);
      expect(k.quiet, isEmpty);
    });

    test('pings that fail are pings unanswered, and throw at nobody', () async {
      final uncaught = <Object>[];
      late _Model k;
      await runZonedGuarded(() async {
        k = _Model();
        await k.ticks(1);
        k.failing = true;
        await k.ticks(4);
      }, (error, stack) => uncaught.add(error));
      expect(uncaught, isEmpty);
      expect(k.quiet, [interval * 3]);
    });

    test('on its timer: started twice it is started once, it stops pinging once it called the connection quiet, '
        'and started again it starts from nothing', () async {
      // What is counted here is ticks, and what is waited for is what is
      // looked for: a machine that is busy makes a timer late, never early,
      // and a test that counts on the clock fails there for no fault.
      Future<void> until(bool Function() what) async {
        final waited = Stopwatch()..start();
        while (!what()) {
          if (waited.elapsed > const Duration(seconds: 10)) fail('waited ten seconds for it');
          await Future<void>.delayed(const Duration(milliseconds: 2));
        }
      }

      const short = Duration(milliseconds: 40);
      final k = _Model(every: short);
      final sinceStart = Stopwatch()..start();
      k.keepAlive
        ..start()
        ..start();
      // Three pings of one timer take three intervals; two timers would have sent four in two.
      await until(() => k.pings >= 3);
      expect(sinceStart.elapsed, greaterThanOrEqualTo(short * 3 - const Duration(milliseconds: 5)),
          reason: 'one timer, not two');
      final answered = k.pings;
      k.answering = false;
      // Three more pings go out, the tick after them calls it quiet, and no tick follows.
      await until(() => k.quiet.isNotEmpty);
      expect(k.pings, answered + 3);
      expect(k.quiet, [short * 3]);
      await Future<void>.delayed(short * 3);
      expect(k.pings, answered + 3, reason: 'no ping once it gave the connection up');
      expect(k.quiet, hasLength(1));
      // Started again (as on a new connection), it has yet to hear an answer: nothing is said.
      k.keepAlive.start();
      await until(() => k.pings >= answered + 3 + 4);
      expect(k.quiet, hasLength(1));
      k.keepAlive.stop();
      final stoppedAt = k.pings;
      await Future<void>.delayed(short * 4);
      expect(k.pings, stoppedAt, reason: 'stopped');
    });
  });

  // Against a real OpenSSH server (tool/test_sshd.sh, 127.0.0.1:2299)
  // through a connection that can be made to go quiet. Skipped when it is
  // not running.
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
    const interval = Duration(milliseconds: 200);

    Future<bool> serverUp() async {
      try {
        final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
        s.destroy();
        return File(keyPath).existsSync();
      } catch (_) {
        return false;
      }
    }

    Future<(SSHClient, _GatedSocket)> connect({Duration? keepAlive = interval, int? maxUnanswered}) async {
      final socket = _GatedSocket(await SSHSocket.connect(host, port));
      final identities = SSHKeyPair.fromPem(File(keyPath).readAsStringSync());
      final client = maxUnanswered == null
          ? SSHClient(socket, username: user, identities: identities, keepAliveInterval: keepAlive)
          : SSHClient(
              socket,
              username: user,
              identities: identities,
              keepAliveInterval: keepAlive,
              keepAliveMaxUnanswered: maxUnanswered,
            );
      await client.authenticated;
      return (client, socket);
    }

    /// How the connection of [client] has ended by now: null while it is
    /// there, 'closed', or what it ended with.
    Object? Function() watchEnd(SSHClient client) {
      Object? ended;
      unawaited(client.done.then<void>((_) => ended = 'closed', onError: (Object e) => ended = e));
      return () => ended;
    }

    test('a connection that goes quiet is given up after three keep-alives went unanswered, and says so', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, socket) = await connect();
      addTearDown(client.close);
      final ended = watchEnd(client);
      // (The server has answered a keep-alive or two by then.)
      await Future<void>.delayed(interval * 2 + interval ~/ 2);
      expect(ended(), isNull);
      // Nothing the server says is heard from here on.
      socket.hold = true;
      // Something asked of it meanwhile waits with it.
      Object? asked;
      unawaited(client.execute('true').then<void>((_) => asked = 'answered', onError: (Object e) => asked = e));
      await Future<void>.delayed(interval * 2);
      expect(ended(), isNull, reason: 'two keep-alives out: not given up yet');
      await Future<void>.delayed(interval * 4);
      final quiet = isA<SSHNoAnswerError>()
          .having((e) => e.unanswered, 'keep-alives unanswered', 3)
          .having((e) => e.silence, 'how long', interval * 3)
          .having((e) => e.message, 'message',
              'Nothing came from the server for 0 seconds: 3 keep-alives went unanswered');
      expect(ended(), quiet, reason: 'it was held to be connected for as long as the system held it to be');
      expect(asked, quiet, reason: 'what waited on it is told the same');
      expect(client.isClosed, isTrue);
    });

    test('a connection that answers stays, however long nothing else happens on it', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, _) = await connect(keepAlive: const Duration(milliseconds: 100));
      addTearDown(client.close);
      final ended = watchEnd(client);
      await Future<void>.delayed(const Duration(milliseconds: 1500));
      expect(ended(), isNull);
      expect(String.fromCharCodes(await client.run('echo still-here')), contains('still-here'));
    });

    test('quiet for a while and heard again: it stays, and is given up only when it goes quiet for three keep-alives',
        () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, socket) = await connect();
      addTearDown(client.close);
      final ended = watchEnd(client);
      await Future<void>.delayed(interval * 2 + interval ~/ 2);
      // What the server says is kept back, and handed over later: a network
      // that stalls and comes back.
      socket.hold = true;
      await Future<void>.delayed(interval + interval ~/ 2);
      socket.hold = false;
      await Future<void>.delayed(interval * 3);
      expect(ended(), isNull, reason: 'it came back in time');
      expect(String.fromCharCodes(await client.run('echo still-here')), contains('still-here'));
      socket.hold = true;
      await Future<void>.delayed(interval * 5);
      expect(ended(), isA<SSHNoAnswerError>());
    });

    test('a connection that goes quiet before the server has answered a keep-alive is not judged by them', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (client, socket) = await connect();
      addTearDown(client.close);
      final ended = watchEnd(client);
      socket.hold = true;
      await Future<void>.delayed(interval * 7);
      expect(ended(), isNull, reason: 'no keep-alive was answered yet: nothing is known of this server');
    });

    test('how many may go unanswered is the client\'s to say, and with keep-alives off nothing is given up', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final (patient, patientSocket) = await connect(maxUnanswered: 8);
      addTearDown(patient.close);
      final (off, offSocket) = await connect(keepAlive: null);
      addTearDown(off.close);
      final patientEnd = watchEnd(patient);
      final offEnd = watchEnd(off);
      await Future<void>.delayed(interval * 2 + interval ~/ 2);
      patientSocket.hold = true;
      offSocket.hold = true;
      await Future<void>.delayed(interval * 6);
      expect(patientEnd(), isNull, reason: 'eight may go unanswered');
      expect(offEnd(), isNull, reason: 'nothing looks for silence with keep-alives off');
      await Future<void>.delayed(interval * 4);
      expect(patientEnd(), isA<SSHNoAnswerError>().having((e) => e.unanswered, 'unanswered', 8));
      expect(offEnd(), isNull);
    });
  });
}

/// A keep-alive that is never started, with a server made up for it: the
/// test makes each tick happen by hand, and says whether the server answers.
class _Model {
  _Model({int maxUnanswered = 3, bool hears = true, Duration every = const Duration(seconds: 15)}) {
    keepAlive = SSHKeepAlive(
      interval: every,
      maxUnanswered: maxUnanswered,
      ping: () {
        pings++;
        if (failing) return Future<void>.error(SSHStateError('Transport is closed'));
        if (answering) {
          heard++;
          return Future<void>.value();
        }
        final waiting = Completer<void>();
        _waiting.add(waiting);
        return waiting.future;
      },
      heard: hears ? () => heard : null,
      onNoAnswer: quiet.add,
    );
  }

  late final SSHKeepAlive keepAlive;

  /// Whether the server answers the pings it gets (and so is heard).
  var answering = true;

  /// Whether sending a ping fails, as on a connection that has ended.
  var failing = false;

  /// How much has come from the server.
  var heard = 0;

  /// How often it pinged.
  var pings = 0;

  /// What it said of silence.
  final quiet = <Duration>[];

  final _waiting = <Completer<void>>[];

  /// The answer to the oldest ping still waiting arrives.
  void answerOne() {
    heard++;
    _waiting.removeAt(0).complete();
  }

  /// [count] ticks of its timer, one after the other.
  Future<void> ticks(int count) async {
    for (var i = 0; i < count; i++) {
      keepAlive.debugTick();
      await Future<void>.delayed(Duration.zero);
    }
  }
}

/// A real socket whose incoming data can be kept back, as on a connection
/// that has gone quiet, and handed over later, as when it comes back.
class _GatedSocket implements SSHSocket {
  _GatedSocket(this._socket) {
    _socket.stream.listen(
      (data) {
        if (_hold) {
          _kept.add(data);
        } else {
          _incoming.add(data);
        }
      },
      onError: _incoming.addError,
      onDone: _incoming.close,
    );
  }

  final SSHSocket _socket;
  final _incoming = StreamController<Uint8List>();
  final _kept = <Uint8List>[];
  var _hold = false;

  /// While true, what the server sends is kept back; set to false, what was
  /// kept is handed over, in order.
  bool get hold => _hold;
  set hold(bool value) {
    _hold = value;
    if (value) return;
    _kept
      ..forEach(_incoming.add)
      ..clear();
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
