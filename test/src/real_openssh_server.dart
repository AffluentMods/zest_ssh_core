import 'dart:convert';
import 'dart:io';

/// The OpenSSH server of tool/test_sshd.sh (127.0.0.1:2299 unless the
/// environment says otherwise), for a test that wants what a real server
/// does, and what it writes of a connection in its own log.
///
/// It takes the keys at [keyPath] and [rsaKeyPath] for the account [user],
/// and nothing else. A test asks [unavailable] first, and skips itself
/// where the server is not running.
///
/// The script starts two more that take what the first takes, but of the
/// signatures an RSA key makes one kind only: [sha512Only] and [sha1Only],
/// and one whose only ciphers are the two AES-GCM ones: [gcmOnly].
class RealOpenSshServer {
  RealOpenSshServer._(this.host, this.port, this.user, this.dir, this._logDir);

  /// The first server, which takes every kind of signature a current
  /// OpenSSH takes.
  factory RealOpenSshServer.fromEnvironment() => RealOpenSshServer._at('ZESTSSH_TEST_SSHD_PORT', 2299, '');

  /// The one that takes from an RSA key only signatures with SHA-512.
  factory RealOpenSshServer.sha512Only() => RealOpenSshServer._at('ZESTSSH_TEST_SHA512_SSHD_PORT', 2291, '/sha512');

  /// The one that takes from an RSA key only the first kind of signature,
  /// with SHA-1 ("ssh-rsa"), as a server older than OpenSSH 7.2 does.
  factory RealOpenSshServer.sha1Only() => RealOpenSshServer._at('ZESTSSH_TEST_SHA1_SSHD_PORT', 2285, '/sha1');

  /// The one whose only ciphers are aes256-gcm@openssh.com and
  /// aes128-gcm@openssh.com, as a server that is set up strictly may have it.
  factory RealOpenSshServer.gcmOnly() => RealOpenSshServer._at('ZESTSSH_TEST_GCM_SSHD_PORT', 2289, '/gcm');

  factory RealOpenSshServer._at(String portVariable, int port, String folder) {
    final env = Platform.environment;
    final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
    final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
        (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
    return RealOpenSshServer._(
      env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1',
      int.tryParse(env[portVariable] ?? '') ?? port,
      user,
      dir,
      '$dir$folder',
    );
  }

  final String host;
  final int port;

  /// The account the server lets in, which is this machine's own: nothing
  /// that is shown of a test names it ([logged] writes USER for it).
  final String user;

  /// Where the servers keep the keys for a client.
  final String dir;

  /// Where this server keeps its log.
  final String _logDir;

  /// The key the server takes.
  String get keyPath => '$dir/client_ed25519';

  /// The RSA key the server takes, where it takes the kind of signature the
  /// key signs in with.
  String get rsaKeyPath => '$dir/client_bare_rsa';

  /// Why the server cannot be used, for a test to skip itself with, or null
  /// where it can.
  Future<String?> unavailable() async {
    try {
      final socket = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      socket.destroy();
    } catch (_) {
      return 'the test OpenSSH server is not running';
    }
    if (!File(keyPath).existsSync() || !File(rsaKeyPath).existsSync() || !File('$_logDir/sshd.log').existsSync()) {
      return 'a test key or the server\'s log is not there';
    }
    return null;
  }

  /// What the server wrote of the connection that came from [localPort],
  /// once it has written of its end, without the name of the account and
  /// without its own stamp of time. Nothing where it writes of no end.
  Future<List<String>> logged(int localPort) async {
    final log = File('$_logDir/sshd.log');
    for (var tries = 0; tries < 40; tries++) {
      await Future<void>.delayed(const Duration(milliseconds: 150));
      final file = await log.open();
      try {
        final length = await file.length();
        const tail = 256 * 1024;
        await file.setPosition(length > tail ? length - tail : 0);
        final lines = const LineSplitter()
            .convert(utf8.decode(await file.read(tail), allowMalformed: true))
            .where((line) => line.contains('port $localPort'))
            .map((line) => line.replaceAll(user, 'USER').replaceFirst(RegExp(r'^.*sshd\[\d+\]: '), ''))
            .toList();
        if (lines.any((line) => line.contains('isconnect') || line.contains('closed') || line.contains('reset'))) {
          return lines;
        }
      } finally {
        await file.close();
      }
    }
    return const [];
  }
}
