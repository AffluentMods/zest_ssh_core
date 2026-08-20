/// Collects timing and negotiation data across the SSH connection lifecycle.
///
/// Tracks timestamps for each connection phase (socket connect, version
/// exchange, key exchange, authentication) and records the negotiated
/// algorithms, authentication methods tried, and server extensions.
class SSHConnectionDiagnostics {
  /// When the connection attempt began.
  final DateTime connectStarted;

  /// When the TCP socket connected.
  DateTime? socketConnected;

  /// When the SSH version exchange completed.
  DateTime? versionExchanged;

  /// When key exchange completed.
  DateTime? kexCompleted;

  /// When authentication completed.
  DateTime? authenticated;

  /// The cipher algorithm negotiated during key exchange.
  String? negotiatedCipher;

  /// The MAC algorithm negotiated during key exchange.
  String? negotiatedMac;

  /// The key exchange algorithm negotiated.
  String? negotiatedKex;

  /// The host key algorithm negotiated.
  String? negotiatedHostKey;

  /// The authentication methods that were attempted, in order.
  List<String> authMethodsTried = [];

  /// The authentication method that ultimately succeeded.
  String? authMethodSucceeded;

  /// Extensions advertised by the server.
  List<String> serverExtensions = [];

  SSHConnectionDiagnostics({DateTime? connectStarted})
      : connectStarted = connectStarted ?? DateTime.now();

  /// Time elapsed from connection start to TCP socket connected.
  Duration? get socketConnectTime {
    final sc = socketConnected;
    if (sc == null) return null;
    return sc.difference(connectStarted);
  }

  /// Time elapsed from socket connected to key exchange completed.
  Duration? get kexTime {
    final sc = socketConnected;
    final kc = kexCompleted;
    if (sc == null || kc == null) return null;
    return kc.difference(sc);
  }

  /// Time elapsed from key exchange completed to authentication completed.
  Duration? get authTime {
    final kc = kexCompleted;
    final auth = authenticated;
    if (kc == null || auth == null) return null;
    return auth.difference(kc);
  }

  /// Total time from connection start to authentication completed.
  Duration? get totalConnectTime {
    final auth = authenticated;
    if (auth == null) return null;
    return auth.difference(connectStarted);
  }

  @override
  String toString() {
    final buf = StringBuffer('SSHConnectionDiagnostics(\n');
    buf.writeln('  socketConnect: ${_fmtDuration(socketConnectTime)},');
    buf.writeln('  kex: ${_fmtDuration(kexTime)},');
    buf.writeln('  auth: ${_fmtDuration(authTime)},');
    buf.writeln('  total: ${_fmtDuration(totalConnectTime)},');
    buf.writeln('  cipher: $negotiatedCipher,');
    buf.writeln('  mac: $negotiatedMac,');
    buf.writeln('  kex: $negotiatedKex,');
    buf.writeln('  hostKey: $negotiatedHostKey,');
    buf.writeln('  authTried: $authMethodsTried,');
    buf.writeln('  authSucceeded: $authMethodSucceeded,');
    buf.writeln('  extensions: $serverExtensions,');
    buf.write(')');
    return buf.toString();
  }

  static String _fmtDuration(Duration? d) {
    if (d == null) return 'null';
    return '${d.inMilliseconds}ms';
  }
}
