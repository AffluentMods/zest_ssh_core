import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/socket/ssh_socket.dart';
import 'package:zest_ssh_core/src/ssh_transport.dart';

/// `SSHTransport.drainSocket` is the upload loop's backpressure hook: it waits
/// for the socket's `flush()` while other channels keep writing. dart:io's
/// IOSink throws for an add() during a flush(), so the transport must park
/// those writes and replay them, in order, once the flush completes. These
/// tests pin that contract with a socket whose flush completes on demand.
void main() {
  Symbol private(String name) =>
      MirrorSystem.getSymbol(name, reflectClass(SSHTransport).owner as LibraryMirror);

  void write(SSHTransport t, List<int> bytes) =>
      reflect(t).invoke(private('_writeToSocket'), [bytes]);

  Uint8List b(int v) => Uint8List.fromList([v]);

  group('SSHTransport.drainSocket', () {
    test('writes during a drain are parked and replayed in order', () async {
      final socket = _FlushControlledSocket();
      final transport = SSHTransport(socket);
      final base = socket.packets.length; // whatever the constructor wrote

      write(transport, b(1));
      final drain = transport.drainSocket();
      expect(socket.flushCalls, 1);

      // Another channel writes while the flush is outstanding.
      write(transport, b(2));
      write(transport, b(3));
      await Future<void>.delayed(Duration.zero);
      expect(socket.packets.length, base + 1,
          reason: 'nothing may reach the sink while the flush is pending');

      socket.completeFlush();
      await drain;
      expect(socket.packets.skip(base).map((p) => p.first).toList(), [1, 2, 3],
          reason: 'parked writes replay after the flush, original order kept');

      // Ordinary writes go straight through again afterwards.
      write(transport, b(4));
      expect(socket.packets.last.first, 4);
      transport.close();
    });

    test('concurrent drains share a single flush', () async {
      final socket = _FlushControlledSocket();
      final transport = SSHTransport(socket);

      final d1 = transport.drainSocket();
      final d2 = transport.drainSocket();
      expect(socket.flushCalls, 1);
      expect(identical(d1, d2), isTrue);

      socket.completeFlush();
      await Future.wait([d1, d2]);

      // A later drain starts a fresh flush.
      final d3 = transport.drainSocket();
      expect(socket.flushCalls, 2);
      socket.completeFlush();
      await d3;
      transport.close();
    });

    test('a failing flush resolves the drain and unparks the writes', () async {
      final socket = _FlushControlledSocket();
      final transport = SSHTransport(socket);
      final base = socket.packets.length;

      final drain = transport.drainSocket();
      write(transport, b(7));
      socket.failFlush(StateError('socket gone'));
      await drain; // must not throw: the transport's error path owns teardown
      expect(socket.packets.skip(base).map((p) => p.first).toList(), [7]);
      transport.close();
    });
  });
}

class _FlushControlledSocket implements SSHSocket {
  final _input = StreamController<Uint8List>();
  final _done = Completer<void>();
  final packets = <Uint8List>[];
  Completer<void>? _flush;
  int flushCalls = 0;

  void completeFlush() => _flush!.complete();
  void failFlush(Object error) => _flush!.completeError(error);

  @override
  Future<void> flush() {
    flushCalls++;
    final c = Completer<void>();
    _flush = c;
    return c.future;
  }

  @override
  Stream<Uint8List> get stream => _input.stream;

  @override
  StreamSink<List<int>> get sink => _Sink(packets);

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _input.close();
  }

  @override
  void destroy() {
    if (!_done.isCompleted) _done.complete();
    unawaited(_input.close());
  }
}

class _Sink implements StreamSink<List<int>> {
  _Sink(this._packets);
  final List<Uint8List> _packets;
  final _done = Completer<void>();

  @override
  void add(List<int> event) => _packets.add(Uint8List.fromList(event));

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
  }

  @override
  Future<void> get done => _done.future;
}
