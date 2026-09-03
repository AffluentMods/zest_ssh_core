import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/socket/ssh_socket.dart';

Future<SSHSocket> connectNativeSocket(
  String host,
  int port, {
  Duration? timeout,
}) async {
  final socket = await Socket.connect(host, port, timeout: timeout);
  // Disable Nagle's algorithm. SSH multiplexes request/response traffic
  // (interactive keystrokes, SFTP WRITE/STATUS) over one connection, and with
  // Nagle on, the sub-MSS tail of each burst waits for the peer's delayed ACK
  // (up to ~200ms) before the next small segment leaves. That is invisible on
  // loopback but throttles a real link to a fraction of its capacity and makes
  // a bulk transfer "fast then crawl" once the initial window drains. Every
  // serious SSH client (OpenSSH included) sets TCP_NODELAY for this reason.
  try {
    socket.setOption(SocketOption.tcpNoDelay, true);
  } catch (_) {
    // A platform or a test double that rejects the option just keeps Nagle on;
    // correctness is unaffected, only throughput.
  }
  return _SSHNativeSocket._(socket);
}

class _SSHNativeSocket implements SSHSocket {
  final Socket _socket;

  _SSHNativeSocket._(this._socket);

  @override
  Stream<Uint8List> get stream => _socket;

  @override
  StreamSink<List<int>> get sink => _socket;

  @override
  Future<void> flush() => _socket.flush();

  @override
  Future<void> close() async {
    await _socket.close();
  }

  @override
  Future<void> get done => _socket.done;

  @override
  void destroy() {
    _socket.destroy();
  }

  @override
  String toString() {
    final address = '${_socket.remoteAddress.host}:${_socket.remotePort}';
    return '_SSHNativeSocket($address)';
  }
}
