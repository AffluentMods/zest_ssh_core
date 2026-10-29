// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'played_server.dart';

/// A place on the loopback address where a played server waits for whoever
/// dials it: a program that makes its own connection (the OpenSSH client of
/// the machine, an application's code that is given an address and a port
/// and nothing else).
///
/// One connection for each listener: the first that comes is the line the
/// played server is put on, and nothing else is let in.
class PlayedListener {
  PlayedListener._(this._listener);

  final ServerSocket _listener;

  /// Starts listening on a port that is free.
  static Future<PlayedListener> bind() async =>
      PlayedListener._(await ServerSocket.bind(InternetAddress.loopbackIPv4, 0));

  /// The address to dial.
  String get host => InternetAddress.loopbackIPv4.address;

  /// The port to dial.
  int get port => _listener.port;

  /// The connection that comes, as a line a played server holds; then
  /// nothing more is let in. Fails when nobody has dialled within
  /// [PlayedServer.patience].
  Future<PlayedSocketLine> line() async {
    try {
      return PlayedSocketLine(await _listener.first.timeout(PlayedServer.patience));
    } finally {
      await _listener.close();
    }
  }

  /// Stops listening, where nobody came.
  Future<void> close() => _listener.close();
}

/// A connection from a program, as a played server holds it. What the
/// program writes comes as the network hands it over: a packet can come in
/// pieces.
class PlayedSocketLine implements PlayedLine {
  PlayedSocketLine(this._socket) {
    _socket.listen(_written.add, onError: (Object _) => _gone = true, onDone: () => _gone = true, cancelOnError: false);
  }

  final Socket _socket;
  final _written = BytesBuilder(copy: true);
  var _gone = false;

  @override
  bool get clientGone => _gone;

  @override
  void feed(List<int> bytes) {
    try {
      _socket.add(bytes);
    } on StateError {
      // The client has gone: what the server sends goes nowhere, as it would.
    }
  }

  @override
  Uint8List takeOutput() => _written.takeBytes();

  /// Ends the server's side. What was fed before goes out first, and the
  /// write side is closed before the socket is let go: a socket destroyed
  /// with bytes still in its buffer drops them, so a server that says
  /// something and hangs up met a client that never heard it. (Seen on 11
  /// October 2026: under a loaded machine, a test whose jump host says why it
  /// ends the connection got "closed by the host" two times in three.)
  @override
  void end() {
    if (_ending) return;
    _ending = true;
    unawaited(() async {
      try {
        await _socket.flush();
        await _socket.close();
      } catch (_) {
        // The client went first: nothing is left to send.
      }
      _socket.destroy();
    }());
  }

  var _ending = false;

  @override
  bool get wholePackets => false;
}
