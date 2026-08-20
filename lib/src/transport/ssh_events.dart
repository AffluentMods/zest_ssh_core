/// Sealed hierarchy of events emitted during an SSH connection lifecycle.
///
/// These events provide fine-grained observability into every phase of the
/// SSH protocol: connection, key exchange, authentication, channel management,
/// and disconnection.
abstract class SSHEvent {
  const SSHEvent();
}

/// Emitted when the client begins connecting to the remote host.
class SSHEventConnecting extends SSHEvent {
  final String host;
  final int port;

  const SSHEventConnecting({required this.host, required this.port});

  @override
  String toString() => 'SSHEventConnecting(host: $host, port: $port)';
}

/// Emitted when the TCP socket connection has been established.
class SSHEventSocketConnected extends SSHEvent {
  const SSHEventSocketConnected();

  @override
  String toString() => 'SSHEventSocketConnected()';
}

/// Emitted when SSH version strings have been exchanged.
class SSHEventVersionExchange extends SSHEvent {
  final String localVersion;
  final String remoteVersion;

  const SSHEventVersionExchange({
    required this.localVersion,
    required this.remoteVersion,
  });

  @override
  String toString() =>
      'SSHEventVersionExchange(local: $localVersion, remote: $remoteVersion)';
}

/// Emitted when key exchange negotiation has started.
class SSHEventKexStarted extends SSHEvent {
  final String kexAlgorithm;
  final String cipher;
  final String mac;
  final String hostKeyAlgorithm;

  const SSHEventKexStarted({
    required this.kexAlgorithm,
    required this.cipher,
    required this.mac,
    required this.hostKeyAlgorithm,
  });

  @override
  String toString() =>
      'SSHEventKexStarted(kex: $kexAlgorithm, cipher: $cipher, '
      'mac: $mac, hostKey: $hostKeyAlgorithm)';
}

/// Emitted when key exchange has completed successfully.
class SSHEventKexCompleted extends SSHEvent {
  final Duration duration;

  const SSHEventKexCompleted({required this.duration});

  @override
  String toString() =>
      'SSHEventKexCompleted(duration: ${duration.inMilliseconds}ms)';
}

/// Emitted when the server's host key has been received.
class SSHEventHostKeyReceived extends SSHEvent {
  final String keyType;
  final String fingerprint;

  const SSHEventHostKeyReceived({
    required this.keyType,
    required this.fingerprint,
  });

  @override
  String toString() =>
      'SSHEventHostKeyReceived(keyType: $keyType, fingerprint: $fingerprint)';
}

/// Emitted when the authentication phase begins with the available methods.
class SSHEventAuthStarted extends SSHEvent {
  final List<String> availableMethods;

  const SSHEventAuthStarted({required this.availableMethods});

  @override
  String toString() =>
      'SSHEventAuthStarted(availableMethods: $availableMethods)';
}

/// Emitted when an authentication method is being attempted.
class SSHEventAuthMethodAttempted extends SSHEvent {
  final String method;
  final String? identityHint;

  const SSHEventAuthMethodAttempted({
    required this.method,
    this.identityHint,
  });

  @override
  String toString() =>
      'SSHEventAuthMethodAttempted(method: $method, hint: $identityHint)';
}

/// Emitted when an authentication method succeeds.
class SSHEventAuthMethodSucceeded extends SSHEvent {
  final String method;

  const SSHEventAuthMethodSucceeded({required this.method});

  @override
  String toString() => 'SSHEventAuthMethodSucceeded(method: $method)';
}

/// Emitted when an authentication method fails.
class SSHEventAuthMethodFailed extends SSHEvent {
  final String method;
  final String? reason;

  const SSHEventAuthMethodFailed({
    required this.method,
    this.reason,
  });

  @override
  String toString() =>
      'SSHEventAuthMethodFailed(method: $method, reason: $reason)';
}

/// Emitted when authentication is fully complete.
class SSHEventAuthenticated extends SSHEvent {
  const SSHEventAuthenticated();

  @override
  String toString() => 'SSHEventAuthenticated()';
}

/// Emitted when a re-key operation starts.
class SSHEventRekeyStarted extends SSHEvent {
  final String? reason;

  const SSHEventRekeyStarted({this.reason});

  @override
  String toString() => 'SSHEventRekeyStarted(reason: $reason)';
}

/// Emitted when a re-key operation completes.
class SSHEventRekeyCompleted extends SSHEvent {
  final Duration duration;

  const SSHEventRekeyCompleted({required this.duration});

  @override
  String toString() =>
      'SSHEventRekeyCompleted(duration: ${duration.inMilliseconds}ms)';
}

/// Emitted when an SSH channel is opened.
class SSHEventChannelOpened extends SSHEvent {
  final String channelType;
  final int channelId;

  const SSHEventChannelOpened({
    required this.channelType,
    required this.channelId,
  });

  @override
  String toString() =>
      'SSHEventChannelOpened(type: $channelType, id: $channelId)';
}

/// Emitted when an SSH channel is closed.
class SSHEventChannelClosed extends SSHEvent {
  final int channelId;

  const SSHEventChannelClosed({required this.channelId});

  @override
  String toString() => 'SSHEventChannelClosed(id: $channelId)';
}

/// Emitted when the SSH connection is being disconnected.
class SSHEventDisconnect extends SSHEvent {
  final int reasonCode;
  final String? description;

  const SSHEventDisconnect({
    required this.reasonCode,
    this.description,
  });

  @override
  String toString() =>
      'SSHEventDisconnect(reasonCode: $reasonCode, '
      'description: $description)';
}
