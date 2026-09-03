import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/socket/ssh_socket_js.dart'
    if (dart.library.io) 'package:zest_ssh_core/src/socket/ssh_socket_io.dart';

abstract class SSHSocket {
  /// Connects using the platform native socket transport.
  ///
  /// On web platforms this throws [UnsupportedError] because browsers do not
  /// provide raw TCP sockets.
  static Future<SSHSocket> connect(
    String host,
    int port, {
    Duration? timeout,
  }) async {
    return await connectNativeSocket(host, port, timeout: timeout);
  }

  Stream<Uint8List> get stream;

  StreamSink<List<int>> get sink;

  /// A future that will complete when the consumer closes, or when an error occurs.
  Future<void> get done;

  /// Completes once every byte previously added to [sink] has been accepted
  /// by the underlying platform (for a TCP socket: handed to the OS send
  /// buffer). Bulk senders use it as backpressure so a slow link does not pile
  /// megabytes of queued packets ahead of interactive traffic on the same
  /// connection. Implementations without a meaningful buffer complete at once.
  ///
  /// Callers must not `add` to [sink] while a flush is in progress (dart:io
  /// throws for that); [SSHTransport] serialises its writes around it.
  ///
  /// Defaults to a no-op so an implementation with no platform send buffer,
  /// and any external implementer of this public interface, keeps compiling
  /// and simply offers no send-backpressure signal. This is a concrete method,
  /// not an abstract one, so adding it did not break `implements SSHSocket`.
  Future<void> flush() async {}

  /// Closes the socket, returning the same future as [done].
  Future<void> close();

  void destroy();
}
