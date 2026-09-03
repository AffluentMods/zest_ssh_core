import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:test/test.dart';

void main() {
  group('SSHClient.forwardDynamic', () {
    test('waits for authentication before starting', () async {
      final client = SSHClient(
        _FakeSSHSocket(),
        username: 'demo',
        keepAliveInterval: null,
      );

      // A real connection only reaches USERAUTH_SUCCESS after the client has
      // actually begun authentication (KEX → SERVICE_ACCEPT → first
      // USERAUTH_REQUEST). The client now correctly IGNORES an unsolicited
      // SUCCESS that arrives before auth has started - otherwise a server or
      // MITM could assert "you're authenticated" before any credential was
      // offered. Model that precondition here (this test injects SUCCESS
      // directly rather than driving a full mock handshake).
      final clientLibrary = reflectClass(SSHClient).owner as LibraryMirror;
      reflect(client).setField(
        MirrorSystem.getSymbol('_authenticationStarted', clientLibrary),
        true,
      );

      // Simulate server auth success so forwardDynamic can proceed.
      scheduleMicrotask(() {
        client.handlePacket(SSH_Message_Userauth_Success().encode());
      });

      final dynamicForward = await client.forwardDynamic(
        bindHost: '127.0.0.1',
        bindPort: 0,
      );

      expect(dynamicForward.port, greaterThan(0));
      expect(dynamicForward.isClosed, isFalse);

      await dynamicForward.close();
      expect(dynamicForward.isClosed, isTrue);

      client.close();
      await client.done;
    });
  });
}

class _FakeSSHSocket implements SSHSocket {
  @override
  Future<void> flush() async {}

  final _inputController = StreamController<Uint8List>();
  final _doneCompleter = Completer<void>();

  @override
  Stream<Uint8List> get stream => _inputController.stream;

  @override
  StreamSink<List<int>> get sink => _NoopSink();

  @override
  Future<void> get done => _doneCompleter.future;

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

class _NoopSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final _ in stream) {}
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
