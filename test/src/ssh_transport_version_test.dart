import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:zest_ssh_core/dartssh2.dart';
import 'package:test/test.dart';

void main() {
  group('SSH transport version exchange', () {
    test('accepts SSH-1.99 server banner', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-1.99-OpenSSH_3.6.1p2\r\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-1.99-OpenSSH_3.6.1p2');

      client.close();
    });

    test('rejects non SSH-2 compatible server banners', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(
        socket,
        username: 'demo',
      );

      socket.addIncoming('SSH-1.5-OpenSSH_1.2\r\n');

      await expectLater(
        client.authenticated,
        throwsA(
          predicate((error) {
            return error is SSHAuthAbortError &&
                error.reason is SSHHandshakeError;
          }),
        ),
      );

      client.close();
    });

    // A banner is a line of text on a stream: nothing says it arrives in one
    // read. On a slow link, or through a proxy that forwards as it reads, it
    // comes in pieces, and the client gave up at the first piece ("Version
    // exchange not terminated"): a connection that failed now and then.
    test('a banner that arrives in several reads is put together', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(socket, username: 'demo');

      socket.addIncoming('SSH-2.0-Open');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(client.remoteVersion, isNull, reason: 'the line has not ended');
      socket.addIncoming('SSH_9.6');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(client.remoteVersion, isNull);
      socket.addIncoming(' Debian-3\r');
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(client.remoteVersion, isNull, reason: 'a carriage return alone ends nothing');
      socket.addIncoming('\n');
      await _pumpUntil(() => client.remoteVersion != null);

      expect(client.remoteVersion, 'SSH-2.0-OpenSSH_9.6 Debian-3');

      client.close();
    });

    test('a banner that ends in a line feed alone is taken, in one read or in two', () async {
      for (final pieces in [
        ['SSH-2.0-dropbear_2020.81\n'],
        ['SSH-2.0-dropbear', '_2020.81\n'],
      ]) {
        final socket = _FakeSSHSocket();
        final client = SSHClient(socket, username: 'demo');
        for (final piece in pieces) {
          socket.addIncoming(piece);
          await Future<void>.delayed(const Duration(milliseconds: 10));
        }
        await _pumpUntil(() => client.remoteVersion != null);
        expect(client.remoteVersion, 'SSH-2.0-dropbear_2020.81', reason: '$pieces');
        client.close();
      }
    });

    // RFC 4253, 4.2: "The server MAY send other lines of data before sending
    // the version string." They were taken for the version and refused.
    test('lines a server sends before its banner are passed over', () async {
      for (final pieces in [
        ['Authorized use only.\r\nAll activity is logged.\r\nSSH-2.0-OpenSSH_9.6\r\n'],
        ['Authorized use on', 'ly.\r\nAll activity is logged.\r', '\nSSH-2.0-Open', 'SSH_9.6\r\n'],
        ['\r\n\r\nSSH-2.0-OpenSSH_9.6\r\n'],
        // (A line that is a line feed and nothing else, first of all.)
        ['\nSSH-2.0-OpenSSH_9.6\r\n'],
      ]) {
        final socket = _FakeSSHSocket();
        final client = SSHClient(socket, username: 'demo');
        for (final piece in pieces) {
          socket.addIncoming(piece);
          await Future<void>.delayed(const Duration(milliseconds: 10));
        }
        await _pumpUntil(() => client.remoteVersion != null);
        expect(client.remoteVersion, 'SSH-2.0-OpenSSH_9.6', reason: '$pieces');
        client.close();
      }
    });

    test('a line before the banner does not make an older protocol acceptable', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(socket, username: 'demo');

      socket.addIncoming('Welcome\r\nSSH-1.5-OpenSSH_1.2\r\n');

      await expectLater(
        client.authenticated,
        throwsA(predicate((error) => error is SSHAuthAbortError && error.reason is SSHHandshakeError)),
      );
      expect(client.remoteVersion, isNull);
      client.close();
    });

    test('a line that never ends, and lines without end, are given up on', () async {
      // One line, longer than any banner.
      var socket = _FakeSSHSocket();
      var client = SSHClient(socket, username: 'demo');
      socket.addIncoming('SSH-2.0-${'x' * 6000}');
      await Future<void>.delayed(const Duration(milliseconds: 10));
      socket.addIncoming('x' * 6000);
      await expectLater(
        client.authenticated,
        throwsA(predicate((error) => error is SSHAuthAbortError && error.reason is SSHHandshakeError)),
      );
      client.close();

      // One line that does end, and is longer than any banner.
      socket = _FakeSSHSocket();
      client = SSHClient(socket, username: 'demo');
      socket.addIncoming('SSH-2.0-${'x' * 12000}\r\n');
      await expectLater(
        client.authenticated,
        throwsA(predicate((error) => error is SSHAuthAbortError && error.reason is SSHHandshakeError)),
      );
      expect(client.remoteVersion, isNull);
      client.close();

      // Line after line that is no banner.
      socket = _FakeSSHSocket();
      client = SSHClient(socket, username: 'demo');
      // (Thirty thousand bytes of them are taken, as the next test holds;
      // these are forty thousand.)
      socket.addIncoming('${'no banner here '.padRight(998, '.')}\r\n' * 20);
      await Future<void>.delayed(const Duration(milliseconds: 5));
      socket.addIncoming('${'no banner here '.padRight(998, '.')}\r\n' * 20);
      await expectLater(
        client.authenticated,
        throwsA(predicate((error) => error is SSHAuthAbortError && error.reason is SSHHandshakeError)),
      );
      expect(client.remoteVersion, isNull);
      client.close();
    });

    test('a few lines before the banner, well under the bound, are no reason to give up', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(socket, username: 'demo');
      socket.addIncoming('${'a notice '.padRight(998, '.')}\r\n' * 30);
      await Future<void>.delayed(const Duration(milliseconds: 10));
      socket.addIncoming('SSH-2.0-OpenSSH_9.6\r\n');
      await _pumpUntil(() => client.remoteVersion != null);
      expect(client.remoteVersion, 'SSH-2.0-OpenSSH_9.6');
      client.close();
    });

    test('a server that closes with half a banner sent ends the handshake', () async {
      final socket = _FakeSSHSocket();
      final client = SSHClient(socket, username: 'demo');

      socket.addIncoming('SSH-2.0-Open');
      await Future<void>.delayed(const Duration(milliseconds: 10));
      await socket.close();

      await expectLater(client.authenticated, throwsA(isA<SSHAuthAbortError>()));
      expect(client.remoteVersion, isNull);
    });
  });
}

Future<void> _pumpUntil(bool Function() condition) async {
  for (var i = 0; i < 50; i++) {
    if (condition()) {
      return;
    }
    await Future<void>.delayed(const Duration(milliseconds: 10));
  }
  fail('Timed out waiting for condition');
}

class _FakeSSHSocket implements SSHSocket {
  @override
  Future<void> flush() async {}

  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();
  final _sink = _RecordingSink();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  Future<void> get done => _doneCompleter.future;

  void addIncoming(String data) {
    _inputController.add(Uint8List.fromList(latin1.encode(data)));
  }

  @override
  Future<void> close() async {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    await _inputController.close();
  }

  @override
  void destroy() {
    if (!_doneCompleter.isCompleted) {
      _doneCompleter.complete();
    }
    unawaited(_inputController.close());
  }
}

class _RecordingSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {
    // SSHTransport writes protocol lines and packets to the sink.
    latin1.decode(data);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final data in stream) {
      add(data);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
