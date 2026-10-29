// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:zest_ssh_core/dartssh2.dart';
import 'package:test/test.dart';

/// A server that sends its version and then no proposal for the key
/// exchange, as the SSH inspection of a SonicWall firewall did to the
/// client's offer (28 October 2026): the client ends the connection once
/// [SSHClient.kexInitPatience] is over, with an error that says so, and not
/// a sign-in that runs out of time later.
void main() {
  test('a server that sends its version and no KEXINIT ends the connection, said as that', () async {
    final socket = _QuietServerSocket();
    final client = SSHClient(
      socket,
      username: 'demo',
      kexInitPatience: const Duration(milliseconds: 200),
    );
    socket.say('SSH-2.0-libssh_0.9.0\r\n');

    final watch = Stopwatch()..start();
    await expectLater(
      client.authenticated,
      throwsA(predicate((Object? e) {
        final reason = e is SSHAuthAbortError ? e.reason : e;
        return reason is SSHHandshakeError &&
            reason.kexUnanswered &&
            !reason.nothingInCommon &&
            !reason.strictOrderBroken &&
            reason.message.contains('SSH-2.0-libssh_0.9.0');
      })),
    );
    expect(watch.elapsed, lessThan(const Duration(seconds: 5)));
    expect(socket.destroyed, isTrue);
    client.close();
  });

  test('no wait runs before the server has sent its version', () async {
    final socket = _QuietServerSocket();
    final client = SSHClient(
      socket,
      username: 'demo',
      kexInitPatience: const Duration(milliseconds: 100),
    );
    final ended = client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
    await Future<void>.delayed(const Duration(milliseconds: 400));
    expect(socket.destroyed, isFalse);
    client.close();
    final error = await ended;
    expect(error is SSHHandshakeError && error.kexUnanswered, isFalse);
  });

  test('a server that closes before its KEXINIT is not said to have gone quiet', () async {
    final socket = _QuietServerSocket();
    final client = SSHClient(
      socket,
      username: 'demo',
      kexInitPatience: const Duration(milliseconds: 300),
    );
    socket.say('SSH-2.0-OpenSSH_9.6\r\n');
    await Future<void>.delayed(const Duration(milliseconds: 50));
    await socket.close();
    final error = await client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
    final reason = error is SSHAuthAbortError ? error.reason : error;
    expect(reason is SSHHandshakeError && reason.kexUnanswered, isFalse);
    // The wait was stopped with the connection: nothing fires after it.
    await Future<void>.delayed(const Duration(milliseconds: 500));
    client.close();
  });

  test('the wait is ten seconds where nothing is said', () {
    expect(SSHTransport.defaultKexInitPatience, const Duration(seconds: 10));
  });
}

class _QuietServerSocket implements SSHSocket {
  final _input = StreamController<Uint8List>();
  final _done = Completer<void>();
  bool destroyed = false;

  void say(String text) => _input.add(Uint8List.fromList(latin1.encode(text)));

  @override
  Future<void> flush() async {}

  @override
  Stream<Uint8List> get stream => _input.stream;

  @override
  StreamSink<List<int>> get sink => _DroppingSink();

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _input.close();
  }

  @override
  void destroy() {
    destroyed = true;
    if (!_done.isCompleted) _done.complete();
    unawaited(_input.close());
  }
}

class _DroppingSink implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) => stream.drain<void>();

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
