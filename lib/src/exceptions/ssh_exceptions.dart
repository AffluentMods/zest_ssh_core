/// Complete SSH exception hierarchy for ZestSSH.
///
/// Every exception carries a human-readable [message] and an optional [cause]
/// for exception chaining.

// ---------------------------------------------------------------------------
// Base
// ---------------------------------------------------------------------------

/// Root of the SSH exception hierarchy.
abstract class SSHException implements Exception {
  /// Human-readable description of the failure.
  String get message;

  /// Optional underlying cause for exception chaining.
  Object? get cause;

  @override
  String toString() {
    final buffer = StringBuffer('$runtimeType: $message');
    if (cause != null) {
      buffer.write(' (cause: $cause)');
    }
    return buffer.toString();
  }
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Failures that occur while establishing a TCP connection.
abstract class SSHConnectionException extends SSHException {
  /// The host that was being connected to.
  final String host;

  /// The port that was being connected to.
  final int port;

  @override
  final Object? cause;

  SSHConnectionException({
    required this.host,
    required this.port,
    this.cause,
  });
}

/// The remote host actively refused the connection.
class SSHConnectionRefusedException extends SSHConnectionException {
  @override
  String get message => 'Connection refused by $host:$port';

  SSHConnectionRefusedException({
    required super.host,
    required super.port,
    super.cause,
  });
}

/// The connection attempt timed out.
class SSHConnectionTimedOutException extends SSHConnectionException {
  /// How long we waited before giving up.
  final Duration timeout;

  @override
  String get message =>
      'Connection to $host:$port timed out after ${timeout.inSeconds}s';

  SSHConnectionTimedOutException({
    required super.host,
    required super.port,
    required this.timeout,
    super.cause,
  });
}

/// The connection was reset by the remote host.
class SSHConnectionResetException extends SSHConnectionException {
  @override
  String get message => 'Connection to $host:$port was reset';

  SSHConnectionResetException({
    required super.host,
    required super.port,
    super.cause,
  });
}

/// The network is unreachable.
class SSHNetworkUnreachableException extends SSHConnectionException {
  @override
  String get message => 'Network unreachable while connecting to $host:$port';

  SSHNetworkUnreachableException({
    required super.host,
    required super.port,
    super.cause,
  });
}

/// DNS resolution failed for the target host.
class SSHDnsResolutionException extends SSHConnectionException {
  @override
  String get message => 'Failed to resolve hostname "$host"';

  SSHDnsResolutionException({
    required super.host,
    super.port = 22,
    super.cause,
  });
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// Failures during the SSH handshake (key exchange, algorithm negotiation).
abstract class SSHHandshakeException extends SSHException {
  @override
  final Object? cause;

  SSHHandshakeException({this.cause});
}

/// The server's SSH version string is incompatible.
class SSHVersionMismatchException extends SSHHandshakeException {
  /// The version string the server presented.
  final String serverVersion;

  @override
  String get message =>
      'SSH version mismatch: server reported "$serverVersion"';

  SSHVersionMismatchException({
    required this.serverVersion,
    super.cause,
  });
}

/// No cipher algorithm acceptable to both sides.
class SSHNoMatchingCipherException extends SSHHandshakeException {
  final List<String> clientCiphers;
  final List<String> serverCiphers;

  @override
  String get message =>
      'No matching cipher found. Client offered: ${clientCiphers.join(", ")}; '
      'server offered: ${serverCiphers.join(", ")}';

  SSHNoMatchingCipherException({
    required this.clientCiphers,
    required this.serverCiphers,
    super.cause,
  });
}

/// No key-exchange algorithm acceptable to both sides.
class SSHNoMatchingKexException extends SSHHandshakeException {
  final List<String> clientKex;
  final List<String> serverKex;

  @override
  String get message =>
      'No matching key exchange algorithm found. Client offered: '
      '${clientKex.join(", ")}; server offered: ${serverKex.join(", ")}';

  SSHNoMatchingKexException({
    required this.clientKex,
    required this.serverKex,
    super.cause,
  });
}

/// No MAC algorithm acceptable to both sides.
class SSHNoMatchingMacException extends SSHHandshakeException {
  final List<String> clientMacs;
  final List<String> serverMacs;

  @override
  String get message =>
      'No matching MAC algorithm found. Client offered: '
      '${clientMacs.join(", ")}; server offered: ${serverMacs.join(", ")}';

  SSHNoMatchingMacException({
    required this.clientMacs,
    required this.serverMacs,
    super.cause,
  });
}

/// No host-key algorithm acceptable to both sides.
class SSHNoMatchingHostKeyException extends SSHHandshakeException {
  final List<String> clientHostKeys;
  final List<String> serverHostKeys;

  @override
  String get message =>
      'No matching host key algorithm found. Client offered: '
      '${clientHostKeys.join(", ")}; server offered: '
      '${serverHostKeys.join(", ")}';

  SSHNoMatchingHostKeyException({
    required this.clientHostKeys,
    required this.serverHostKeys,
    super.cause,
  });
}

// ---------------------------------------------------------------------------
// Host key verification
// ---------------------------------------------------------------------------

/// Failures when verifying the server's host key.
abstract class SSHHostKeyException extends SSHException {
  /// The host whose key was being verified.
  final String host;

  /// The port connected to.
  final int port;

  /// Algorithm of the key in question (e.g. "ssh-ed25519").
  final String keyType;

  /// Fingerprint of the key (e.g. SHA-256 hash).
  final String fingerprint;

  @override
  final Object? cause;

  SSHHostKeyException({
    required this.host,
    required this.port,
    required this.keyType,
    required this.fingerprint,
    this.cause,
  });
}

/// The host key is not in the known-hosts store.
class SSHHostKeyUnknownException extends SSHHostKeyException {
  @override
  String get message =>
      'Unknown host key for $host:$port ($keyType $fingerprint)';

  SSHHostKeyUnknownException({
    required super.host,
    required super.port,
    required super.keyType,
    required super.fingerprint,
    super.cause,
  });
}

/// The host key differs from the one stored previously.
class SSHHostKeyChangedException extends SSHHostKeyException {
  /// The fingerprint that was previously recorded.
  final String previousFingerprint;

  @override
  String get message =>
      'Host key for $host:$port has CHANGED from $previousFingerprint '
      'to $fingerprint ($keyType). Possible MITM attack.';

  SSHHostKeyChangedException({
    required super.host,
    required super.port,
    required super.keyType,
    required super.fingerprint,
    required this.previousFingerprint,
    super.cause,
  });
}

/// The host key failed cryptographic verification.
class SSHHostKeyVerificationFailedException extends SSHHostKeyException {
  @override
  String get message =>
      'Host key verification failed for $host:$port ($keyType $fingerprint)';

  SSHHostKeyVerificationFailedException({
    required super.host,
    required super.port,
    required super.keyType,
    required super.fingerprint,
    super.cause,
  });
}

/// The host key has been explicitly revoked.
class SSHHostKeyRevokedException extends SSHHostKeyException {
  @override
  String get message =>
      'Host key for $host:$port has been revoked ($keyType $fingerprint)';

  SSHHostKeyRevokedException({
    required super.host,
    required super.port,
    required super.keyType,
    required super.fingerprint,
    super.cause,
  });
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// Failures during user authentication.
abstract class SSHAuthException extends SSHException {
  @override
  final Object? cause;

  SSHAuthException({this.cause});
}

/// All configured authentication methods have been tried and failed.
class SSHAuthAllMethodsFailedException extends SSHAuthException {
  /// Methods that were attempted.
  final List<String> attemptedMethods;

  @override
  String get message =>
      'All authentication methods failed. '
      'Tried: ${attemptedMethods.join(", ")}';

  SSHAuthAllMethodsFailedException({
    required this.attemptedMethods,
    super.cause,
  });
}

/// Password was rejected by the server.
class SSHPasswordIncorrectException extends SSHAuthException {
  @override
  String get message => 'Password authentication failed: incorrect password';

  SSHPasswordIncorrectException({super.cause});
}

/// The server reports the password has expired.
class SSHPasswordExpiredException extends SSHAuthException {
  /// Optional prompt from the server for a new password.
  final String? prompt;

  @override
  String get message =>
      'Password has expired${prompt != null ? ": $prompt" : ""}';

  SSHPasswordExpiredException({this.prompt, super.cause});
}

/// Public key was rejected by the server.
class SSHKeyRejectedException extends SSHAuthException {
  /// The key type that was rejected (e.g. "ssh-ed25519").
  final String? keyType;

  @override
  String get message =>
      'Public key authentication failed'
      '${keyType != null ? " (key type: $keyType)" : ""}';

  SSHKeyRejectedException({this.keyType, super.cause});
}

/// None of the available keys matched what the server will accept.
class SSHNoMatchingKeyException extends SSHAuthException {
  final List<String> availableKeyTypes;

  @override
  String get message =>
      'No matching key for server. Available: '
      '${availableKeyTypes.join(", ")}';

  SSHNoMatchingKeyException({
    required this.availableKeyTypes,
    super.cause,
  });
}

/// Failed to decrypt a private key (wrong passphrase, corrupt file, etc.).
class SSHKeyDecryptionException extends SSHAuthException {
  /// Path or identifier of the key that could not be decrypted.
  final String? keyIdentifier;

  @override
  String get message =>
      'Failed to decrypt private key'
      '${keyIdentifier != null ? " ($keyIdentifier)" : ""}';

  SSHKeyDecryptionException({this.keyIdentifier, super.cause});
}

/// The username is not recognized by the server.
class SSHUserUnknownException extends SSHAuthException {
  final String username;

  @override
  String get message => 'User "$username" is not recognized by the server';

  SSHUserUnknownException({required this.username, super.cause});
}

/// Keyboard-interactive authentication was cancelled by the user.
class SSHInteractiveCancelledException extends SSHAuthException {
  @override
  String get message => 'Keyboard-interactive authentication cancelled';

  SSHInteractiveCancelledException({super.cause});
}

/// Too many authentication attempts; the server will not accept more.
class SSHTooManyAttemptsException extends SSHAuthException {
  /// Number of attempts that were made, if known.
  final int? attempts;

  @override
  String get message =>
      'Too many authentication attempts'
      '${attempts != null ? " ($attempts)" : ""}';

  SSHTooManyAttemptsException({this.attempts, super.cause});
}

// ---------------------------------------------------------------------------
// Disconnect (RFC 4253 section 11.1)
// ---------------------------------------------------------------------------

/// The remote side sent an SSH_MSG_DISCONNECT.
class SSHDisconnectException extends SSHException {
  /// RFC 4254 reason code.
  final int reasonCode;

  /// Description sent by the remote side.
  final String description;

  @override
  final Object? cause;

  @override
  String get message => 'Disconnected (reason $reasonCode): $description';

  SSHDisconnectException({
    required this.reasonCode,
    required this.description,
    this.cause,
  });

  // -- RFC 4253 section 11.1 reason codes ------------------------------------

  /// SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT
  static const int hostNotAllowedToConnect = 1;

  /// SSH_DISCONNECT_PROTOCOL_ERROR
  static const int protocolError = 2;

  /// SSH_DISCONNECT_KEY_EXCHANGE_FAILED
  static const int keyExchangeFailed = 3;

  /// SSH_DISCONNECT_RESERVED
  static const int reserved = 4;

  /// SSH_DISCONNECT_MAC_ERROR
  static const int macError = 5;

  /// SSH_DISCONNECT_COMPRESSION_ERROR
  static const int compressionError = 6;

  /// SSH_DISCONNECT_SERVICE_NOT_AVAILABLE
  static const int serviceNotAvailable = 7;

  /// SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED
  static const int protocolVersionNotSupported = 8;

  /// SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE
  static const int hostKeyNotVerifiable = 9;

  /// SSH_DISCONNECT_CONNECTION_LOST
  static const int connectionLost = 10;

  /// SSH_DISCONNECT_BY_APPLICATION
  static const int byApplication = 11;

  /// SSH_DISCONNECT_TOO_MANY_CONNECTIONS
  static const int tooManyConnections = 12;

  /// SSH_DISCONNECT_AUTH_CANCELLED_BY_USER
  static const int authCancelledByUser = 13;

  /// SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE
  static const int noMoreAuthMethodsAvailable = 14;

  /// SSH_DISCONNECT_ILLEGAL_USER_NAME
  static const int illegalUserName = 15;
}

// ---------------------------------------------------------------------------
// Channel
// ---------------------------------------------------------------------------

/// Failures related to SSH channels.
abstract class SSHChannelException extends SSHException {
  @override
  final Object? cause;

  SSHChannelException({this.cause});
}

/// Failed to open a channel.
class SSHChannelOpenException extends SSHChannelException {
  /// The reason code returned by the server.
  final int code;

  /// The server's textual description.
  final String description;

  @override
  String get message => 'Channel open failed ($code): $description';

  SSHChannelOpenException({
    required this.code,
    required this.description,
    super.cause,
  });
}

/// An operation was attempted on a closed channel.
class SSHChannelClosedException extends SSHChannelException {
  /// Identifier of the channel, if available.
  final int? channelId;

  @override
  String get message =>
      'Channel${channelId != null ? " $channelId" : ""} is closed';

  SSHChannelClosedException({this.channelId, super.cause});
}

/// A channel request (e.g. "exec", "pty-req") was rejected by the server.
class SSHChannelRequestFailedException extends SSHChannelException {
  /// The request type that failed.
  final String requestType;

  @override
  String get message => 'Channel request "$requestType" failed';

  SSHChannelRequestFailedException({
    required this.requestType,
    super.cause,
  });
}

// ---------------------------------------------------------------------------
// Protocol
// ---------------------------------------------------------------------------

/// Low-level protocol violations.
abstract class SSHProtocolException extends SSHException {
  @override
  final Object? cause;

  SSHProtocolException({this.cause});
}

/// A generic protocol violation that does not fit a more specific subtype.
class SSHProtocolViolationException extends SSHProtocolException {
  @override
  final String message;

  SSHProtocolViolationException(this.message, {super.cause});
}

/// A packet exceeded the maximum allowed size.
class SSHPacketTooLargeException extends SSHProtocolException {
  /// Size of the packet that was received.
  final int packetSize;

  /// Maximum allowed size.
  final int maxSize;

  @override
  String get message =>
      'Packet too large: $packetSize bytes (max $maxSize)';

  SSHPacketTooLargeException({
    required this.packetSize,
    required this.maxSize,
    super.cause,
  });
}

/// A packet was malformed or could not be parsed.
class SSHInvalidPacketException extends SSHProtocolException {
  @override
  final String message;

  SSHInvalidPacketException(this.message, {super.cause});
}

/// MAC verification failed on a received packet.
class SSHMacMismatchException extends SSHProtocolException {
  @override
  String get message => 'MAC verification failed on received packet';

  SSHMacMismatchException({super.cause});
}

/// A packet could not be decrypted.
class SSHDecryptionException extends SSHProtocolException {
  @override
  String get message => 'Failed to decrypt packet';

  SSHDecryptionException({super.cause});
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// The operation was cancelled by the caller (e.g. user tapped "Cancel").
class SSHCancelledException extends SSHException {
  @override
  final String message;

  @override
  final Object? cause;

  SSHCancelledException([this.message = 'Operation cancelled', this.cause]);
}
