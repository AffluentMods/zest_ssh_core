import 'dart:async';

/// Policy controlling when an SSH transport session should re-key.
///
/// Re-keying refreshes the session keys to limit the amount of data encrypted
/// under a single key, reducing exposure if a key is compromised.
///
/// Three presets are provided:
///
///  * [SSHRekeyPolicy.openssh] -- matches OpenSSH defaults (1 GiB / 1 hour).
///  * [SSHRekeyPolicy.strict] -- more aggressive for sensitive sessions.
///  * [SSHRekeyPolicy.disabled] -- never triggers automatic re-key.
class SSHRekeyPolicy {
  /// Maximum bytes transferred (sent + received) before re-keying.
  ///
  /// Default: 1 GiB (1073741824 bytes).
  final int byteThreshold;

  /// Maximum elapsed time since last key exchange before re-keying.
  ///
  /// Default: 1 hour.
  final Duration timeThreshold;

  /// Maximum number of packets sent before re-keying.
  ///
  /// Default: 2^31 (~2.1 billion packets).
  final int packetThreshold;

  /// Whether the client is allowed to initiate re-keying.
  ///
  /// When `false`, re-keying will only happen if the server initiates it.
  final bool clientInitiatedAllowed;

  const SSHRekeyPolicy({
    this.byteThreshold = 1073741824, // 1 GiB
    this.timeThreshold = const Duration(hours: 1),
    this.packetThreshold = 2147483648, // 2^31
    this.clientInitiatedAllowed = true,
  });

  /// Matches OpenSSH defaults: 1 GiB data or 1 hour elapsed.
  static const openssh = SSHRekeyPolicy();

  /// More aggressive re-keying: 256 MiB data, 15 minutes, 2^28 packets.
  static const strict = SSHRekeyPolicy(
    byteThreshold: 268435456, // 256 MiB
    timeThreshold: Duration(minutes: 15),
    packetThreshold: 268435456, // 2^28
  );

  /// Never triggers automatic re-keying (server-initiated still honoured).
  static const disabled = SSHRekeyPolicy(
    byteThreshold: 0,
    timeThreshold: Duration.zero,
    packetThreshold: 0,
    clientInitiatedAllowed: false,
  );
}

/// Tracks transport-level counters and triggers re-keying when any threshold
/// in [policy] is exceeded.
///
/// The caller supplies a [triggerRekey] callback that initiates the actual
/// key-exchange. After a successful re-key the caller must call [reset] to
/// zero the counters and restart the clock.
///
/// ```dart
/// final manager = SSHRekeyManager(
///   policy: SSHRekeyPolicy.openssh,
///   triggerRekey: () => transport.startKeyExchange(),
/// );
///
/// // After every packet:
/// manager.recordSent(packetBytes.length);
/// manager.recordReceived(packetBytes.length);
///
/// // After successful re-key:
/// manager.reset();
/// ```
class SSHRekeyManager {
  /// The policy governing when to re-key.
  final SSHRekeyPolicy policy;

  /// Callback invoked when a threshold is exceeded. It should initiate a
  /// key-exchange on the transport layer.
  final Future<void> Function() triggerRekey;

  int _bytesSent = 0;
  int _bytesReceived = 0;
  int _packetsSent = 0;
  int _packetsReceived = 0;
  DateTime _lastRekeyTime = DateTime.now();
  bool _rekeyInProgress = false;

  SSHRekeyManager({
    required this.policy,
    required this.triggerRekey,
  });

  // ---- Counters -----------------------------------------------------------

  /// Total bytes sent since the last re-key.
  int get bytesSent => _bytesSent;

  /// Total bytes received since the last re-key.
  int get bytesReceived => _bytesReceived;

  /// Total packets sent since the last re-key.
  int get packetsSent => _packetsSent;

  /// Total packets received since the last re-key.
  int get packetsReceived => _packetsReceived;

  /// Time of the last re-key (or construction, for the first key exchange).
  DateTime get lastRekeyTime => _lastRekeyTime;

  /// Whether a re-key is currently in progress.
  bool get isRekeyInProgress => _rekeyInProgress;

  // ---- Recording ----------------------------------------------------------

  /// Record [bytes] bytes sent and check thresholds.
  void recordSent(int bytes) {
    _bytesSent += bytes;
    _packetsSent++;
    _checkThresholds();
  }

  /// Record [bytes] bytes received and check thresholds.
  void recordReceived(int bytes) {
    _bytesReceived += bytes;
    _packetsReceived++;
    _checkThresholds();
  }

  // ---- Lifecycle ----------------------------------------------------------

  /// Reset all counters and restart the timer. Call this after a successful
  /// re-key completes.
  void reset() {
    _bytesSent = 0;
    _bytesReceived = 0;
    _packetsSent = 0;
    _packetsReceived = 0;
    _lastRekeyTime = DateTime.now();
    _rekeyInProgress = false;
  }

  // ---- Internals ----------------------------------------------------------

  void _checkThresholds() {
    if (_rekeyInProgress) return;
    if (!policy.clientInitiatedAllowed) return;
    if (_isDisabled()) return;

    final totalBytes = _bytesSent + _bytesReceived;
    final totalPackets = _packetsSent + _packetsReceived;
    final elapsed = DateTime.now().difference(_lastRekeyTime);

    final byteExceeded =
        policy.byteThreshold > 0 && totalBytes >= policy.byteThreshold;
    final timeExceeded = policy.timeThreshold > Duration.zero &&
        elapsed >= policy.timeThreshold;
    final packetExceeded =
        policy.packetThreshold > 0 && totalPackets >= policy.packetThreshold;

    if (byteExceeded || timeExceeded || packetExceeded) {
      _rekeyInProgress = true;
      unawaited(triggerRekey().whenComplete(() {
        // The caller is responsible for calling reset() after a successful
        // re-key. If the re-key fails the flag stays set so we don't
        // spin-loop retrying.
      }));
    }
  }

  bool _isDisabled() {
    return policy.byteThreshold == 0 &&
        policy.timeThreshold == Duration.zero &&
        policy.packetThreshold == 0;
  }
}
