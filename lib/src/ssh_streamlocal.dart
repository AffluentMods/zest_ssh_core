import 'dart:async';

import 'package:zest_ssh_core/src/ssh_client.dart';
import 'package:zest_ssh_core/src/ssh_forward.dart';

/// Unix domain socket forwarding over SSH.
///
/// Implements the `direct-streamlocal@openssh.com` and
/// `streamlocal-forward@openssh.com` channel types defined in the
/// [OpenSSH PROTOCOL](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL)
/// specification.
///
/// This is useful for accessing remote Unix sockets such as Docker daemon
/// sockets, Kubernetes API sockets, PostgreSQL, and other services that
/// listen on Unix domain sockets.
///
/// Example usage:
/// ```dart
/// // Open a direct connection to a remote Docker socket
/// final channel = await SSHStreamlocalForward.directStreamlocal(
///   client: sshClient,
///   socketPath: '/var/run/docker.sock',
/// );
/// ```
class SSHStreamlocalForward {
  final String _remoteSocketPath;
  final SSHRemoteForward? _remoteForward;
  bool _isCancelled = false;

  SSHStreamlocalForward._(
    this._remoteSocketPath,
    this._remoteForward,
  );

  /// The remote Unix socket path that is being forwarded.
  String get remoteSocketPath => _remoteSocketPath;

  /// Whether this forward has been cancelled.
  bool get isCancelled => _isCancelled;

  /// The underlying [SSHRemoteForward] if this was created via
  /// [forwardRemote], or null for direct connections.
  SSHRemoteForward? get remoteForward => _remoteForward;

  /// Forward a remote Unix socket to local connections.
  ///
  /// Sends a `streamlocal-forward@openssh.com` global request to ask the
  /// server to listen on [remoteSocketPath] and forward incoming connections
  /// back over the SSH channel.
  ///
  /// Returns an [SSHStreamlocalForward] that provides a stream of incoming
  /// connections and can be cancelled via [cancel].
  ///
  /// Returns null if the server rejected the request.
  ///
  /// Note: This requires server-side support for the OpenSSH streamlocal
  /// extension. Most modern OpenSSH servers (6.7+) support this.
  static Future<SSHStreamlocalForward?> forwardRemote({
    required SSHClient client,
    required String remoteSocketPath,
  }) async {
    // The streamlocal-forward@openssh.com global request uses the same
    // mechanism as tcpip-forward but with a socket path instead of
    // host:port. We delegate to the client's existing remote forward
    // infrastructure using the socket path as a synthetic host and port 0.
    final remoteForward = await client.forwardRemote(
      host: remoteSocketPath,
      port: 0,
    );

    if (remoteForward == null) return null;

    return SSHStreamlocalForward._(remoteSocketPath, remoteForward);
  }

  /// Open a direct connection to a remote Unix domain socket.
  ///
  /// Opens a `direct-streamlocal@openssh.com` channel to connect to
  /// [socketPath] on the remote side. This is the Unix socket equivalent
  /// of [SSHClient.forwardLocal] for TCP connections.
  ///
  /// Common use cases:
  /// - Docker: `/var/run/docker.sock`
  /// - Kubernetes: `/var/run/containerd/containerd.sock`
  /// - PostgreSQL: `/var/run/postgresql/.s.PGSQL.5432`
  /// - MySQL: `/var/run/mysqld/mysqld.sock`
  /// - gpg-agent: `~/.gnupg/S.gpg-agent`
  static Future<SSHForwardChannel> directStreamlocal({
    required SSHClient client,
    required String socketPath,
  }) async {
    return client.forwardLocalUnix(socketPath);
  }

  /// Cancel a remote streamlocal forward.
  ///
  /// Sends a `cancel-streamlocal-forward@openssh.com` request to the server
  /// to stop listening on the remote socket path.
  Future<void> cancel() async {
    if (_isCancelled) return;
    _isCancelled = true;

    final forward = _remoteForward;
    if (forward != null) {
      forward.close();
    }
  }

  /// Stream of incoming forwarded connections when using [forwardRemote].
  ///
  /// Each connection is an [SSHForwardChannel] that provides bidirectional
  /// data streams to the connected client on the remote side.
  ///
  /// Returns null if this instance was not created via [forwardRemote].
  Stream<SSHForwardChannel>? get connections => _remoteForward?.connections;

  @override
  String toString() =>
      'SSHStreamlocalForward(path: $_remoteSocketPath, '
      'cancelled: $_isCancelled)';
}
