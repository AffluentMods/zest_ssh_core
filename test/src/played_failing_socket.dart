// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/dartssh2.dart';

/// A socket whose writes fail from the write numbered [from] on, as on a
/// connection that has gone and of which nothing has said so yet:
/// everything else is the socket it stands for.
///
/// (A client writes its version, its proposal and its start of a key
/// exchange; its fourth write is its NEWKEYS.)
class WritesFail implements SSHSocket {
  WritesFail(this._socket, {required int from}) : _sink = _FailingSink(_socket.sink, from);

  final SSHSocket _socket;
  final _FailingSink _sink;

  /// What a write fails with.
  static const said = 'the socket has gone';

  @override
  Stream<Uint8List> get stream => _socket.stream;

  @override
  StreamSink<List<int>> get sink => _sink;

  @override
  Future<void> get done => _socket.done;

  @override
  Future<void> flush() => _socket.flush();

  @override
  Future<void> close() => _socket.close();

  @override
  void destroy() => _socket.destroy();
}

class _FailingSink implements StreamSink<List<int>> {
  _FailingSink(this._sink, this._from);

  final StreamSink<List<int>> _sink;
  final int _from;
  var _writes = 0;

  @override
  void add(List<int> event) {
    if (++_writes >= _from) throw StateError(WritesFail.said);
    _sink.add(event);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) => _sink.addError(error, stackTrace);

  @override
  Future<void> addStream(Stream<List<int>> stream) => _sink.addStream(stream);

  @override
  Future<void> close() => _sink.close();

  @override
  Future<void> get done => _sink.done;
}

/// A socket that is watched: what was done to it, in order. A flush of it
/// can be held back, and its writes made to fail, as a test says.
/// Everything else is the socket it stands for.
class WatchedSocket implements SSHSocket {
  WatchedSocket(this._socket);

  final SSHSocket _socket;

  /// What was done to it, in order: 'write', 'flush' when a flush began and
  /// 'flushed' when it ended, and 'destroy'.
  final did = <String>[];

  /// A flush that begins waits for this where a test has put one here, and
  /// ends at once where there is none.
  Completer<void>? held;

  /// Whether a write fails from now on.
  var writesFail = false;

  bool get destroyed => did.contains('destroy');

  @override
  Stream<Uint8List> get stream => _socket.stream;

  @override
  late final StreamSink<List<int>> sink = _WatchedSink(this, _socket.sink);

  @override
  Future<void> get done => _socket.done;

  @override
  Future<void> flush() async {
    did.add('flush');
    await held?.future;
    did.add('flushed');
  }

  @override
  Future<void> close() => _socket.close();

  @override
  void destroy() {
    did.add('destroy');
    _socket.destroy();
  }
}

class _WatchedSink implements StreamSink<List<int>> {
  _WatchedSink(this._watched, this._sink);

  final WatchedSocket _watched;
  final StreamSink<List<int>> _sink;

  @override
  void add(List<int> event) {
    if (_watched.writesFail) throw StateError(WritesFail.said);
    _watched.did.add('write');
    _sink.add(event);
  }

  @override
  void addError(Object error, [StackTrace? stackTrace]) => _sink.addError(error, stackTrace);

  @override
  Future<void> addStream(Stream<List<int>> stream) => _sink.addStream(stream);

  @override
  Future<void> close() => _sink.close();

  @override
  Future<void> get done => _sink.done;
}
