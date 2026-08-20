/// Per-phase timeout configuration for SSH connections.
///
/// Each field controls how long the client will wait for a specific phase of
/// the SSH handshake or session to complete before raising a timeout error.
///
/// Three convenience presets are provided:
///
///  * [SSHTimeouts.openssh] -- sensible defaults modelled after OpenSSH.
///  * [SSHTimeouts.fast] -- aggressive timeouts for LAN or known-fast hosts.
///  * [SSHTimeouts.patient] -- generous timeouts for high-latency links.
class SSHTimeouts {
  /// Maximum time to establish the TCP socket connection.
  final Duration connect;

  /// Maximum time for the SSH version-string exchange after TCP connect.
  final Duration versionExchange;

  /// Maximum time for the key-exchange (KEX) phase.
  final Duration keyExchange;

  /// Maximum time for the authentication phase (all attempts combined).
  final Duration authentication;

  /// Maximum time to open a new channel after authentication.
  final Duration channelOpen;

  /// Interval between keep-alive probes.
  final Duration keepAliveInterval;

  /// Number of missed keep-alive responses before the connection is considered
  /// dead.
  final int keepAliveCountMax;

  const SSHTimeouts({
    this.connect = const Duration(seconds: 30),
    this.versionExchange = const Duration(seconds: 10),
    this.keyExchange = const Duration(seconds: 30),
    this.authentication = const Duration(seconds: 60),
    this.channelOpen = const Duration(seconds: 15),
    this.keepAliveInterval = const Duration(seconds: 30),
    this.keepAliveCountMax = 3,
  });

  /// Sensible defaults modelled after OpenSSH behaviour.
  static const openssh = SSHTimeouts();

  /// Aggressive timeouts for LAN or known-fast hosts.
  static const fast = SSHTimeouts(
    connect: Duration(seconds: 10),
    authentication: Duration(seconds: 15),
  );

  /// Generous timeouts for satellite links or high-latency connections.
  static const patient = SSHTimeouts(
    connect: Duration(seconds: 60),
    authentication: Duration(seconds: 120),
  );
}
