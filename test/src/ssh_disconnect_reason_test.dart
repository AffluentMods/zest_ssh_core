// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// A server that ends the connection and says why. Before it closes a
/// connection of its own accord, a server sends a message that says so,
/// with a reason in words ("Too many authentication failures", an idle
/// limit, an administrator's notice). The client dropped that message
/// unread: the connection then just ended, and whoever held it was told
/// "closed", never why.
///
/// Whose words they are is said with them. The message may come at any
/// time, before any keys as well, where anybody on the way can have written
/// it: only under keys whose host key was approved is it the server's own.
/// (Each state of a key exchange it can come in is played in
/// ssh_transport_kex_reply_test.dart.)
void main() {
  group('a server made up by hand', () {
    /// A client on a connection whose other side is the test: it has sent
    /// its version, and whatever is added comes in as the server's bytes.
    (SSHClient, _HandFed) client() {
      final socket = _HandFed();
      final client = SSHClient(socket, username: 'deploy');
      addTearDown(client.close);
      socket.add(Uint8List.fromList('SSH-2.0-TestServer\r\n'.codeUnits));
      return (client, socket);
    }

    /// A packet with [payload], as it is sent before any keys.
    Uint8List packet(Uint8List payload) {
      var padding = 8 - ((5 + payload.length) % 8);
      if (padding < 4) padding += 8;
      return (SSHMessageWriter()
            ..writeUint32(1 + payload.length + padding)
            ..writeUint8(padding)
            ..writeBytes(payload)
            ..writeBytes(Uint8List(padding)))
          .takeBytes();
    }

    /// The server's message that it ends the connection, as a packet sent
    /// before any keys (which a server may do).
    Uint8List disconnect(int code, List<int> words, {bool languageTag = true}) {
      final writer = SSHMessageWriter()
        ..writeUint8(1)
        ..writeUint32(code)
        ..writeString(Uint8List.fromList(words));
      if (languageTag) writer.writeString(Uint8List(0));
      return packet(writer.takeBytes());
    }

    /// What signing in and the connection ended with.
    Future<(Object?, Object?)> endOf(SSHClient client) async {
      Object? signIn;
      Object? connection;
      try {
        await client.authenticated.timeout(const Duration(seconds: 5));
      } catch (e) {
        signIn = e;
      }
      try {
        await client.done.timeout(const Duration(seconds: 5));
      } catch (e) {
        connection = e;
      }
      return (signIn, connection);
    }

    test('it says why it ends the connection: signing in fails with that, and so does the connection', () async {
      final (c, socket) = client();
      socket.add(disconnect(12, 'Too many connections from this address'.codeUnits));
      final (signIn, connection) = await endOf(c);
      // Before any keys: what was said, and that it is not known to be the server's.
      final said = isA<SSHDisconnectError>()
          .having((e) => e.reasonCode, 'reason code', 12)
          .having((e) => e.description, 'its words', 'Too many connections from this address')
          .having((e) => e.authentic, 'the server\'s own', isFalse)
          .having(
              (e) => e.message,
              'message',
              'The connection was ended before the server was verified, with: Too many connections from this '
                  'address (reason code 12)');
      expect(connection, said);
      expect(signIn, isA<SSHAuthAbortError>().having((e) => e.reason, 'reason', said));
      expect(c.isClosed, isTrue);
    });

    test('a reason code and no words', () async {
      final (c, socket) = client();
      socket.add(disconnect(11, const []));
      final (_, connection) = await endOf(c);
      expect(
        connection,
        isA<SSHDisconnectError>()
            .having((e) => e.description, 'its words', '')
            .having((e) => e.message, 'message',
                'The connection was ended before the server was verified (reason code 11)'),
      );
    });

    test('the language tag left out, as some servers send it: read all the same', () async {
      final (c, socket) = client();
      socket.add(disconnect(2, 'Too many authentication failures'.codeUnits, languageTag: false));
      final (_, connection) = await endOf(c);
      expect(
        connection,
        isA<SSHDisconnectError>()
            .having((e) => e.reasonCode, 'reason code', 2)
            .having((e) => e.description, 'its words', 'Too many authentication failures'),
      );
    });

    test('cut short before its words: a packet that cannot be read, as any other', () async {
      final (c, socket) = client();
      socket.add(packet((SSHMessageWriter()
            ..writeUint8(1)
            ..writeUint32(2))
          .takeBytes()));
      final (_, connection) = await endOf(c);
      expect(connection, isA<SSHPacketError>());
      expect(c.isClosed, isTrue);
    });

    test('what the error says of itself, by whose words they are', () {
      expect(SSHDisconnectError(2, 'Too many tries', authentic: true).message,
          'The server ended the connection: Too many tries (reason code 2)');
      expect(SSHDisconnectError(11, '', authentic: true).message, 'The server ended the connection (reason code 11)');
      expect(SSHDisconnectError(2, 'Too many tries', authentic: false).message,
          'The connection was ended before the server was verified, with: Too many tries (reason code 2)');
      expect(SSHDisconnectError(11, '', authentic: false).message,
          'The connection was ended before the server was verified (reason code 11)');
    });

    test('words with a byte that is no UTF-8 are read as far as they can be', () async {
      final (c, socket) = client();
      // "Zugang gesperrt, zu viele Versuche fuer ..." with a u with two dots as ISO 8859-1 writes it.
      socket.add(disconnect(2, [...'Zu viele Versuche f'.codeUnits, 0xfc, ...'r deploy'.codeUnits]));
      final (_, connection) = await endOf(c);
      final mark = String.fromCharCode(0xfffd);
      expect(connection,
          isA<SSHDisconnectError>().having((e) => e.description, 'its words', 'Zu viele Versuche f${mark}r deploy'));
    });

    test('the message in two reads is still the message', () async {
      final (c, socket) = client();
      final packet = disconnect(12, 'Too many connections'.codeUnits);
      socket.add(Uint8List.sublistView(packet, 0, 9));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(c.isClosed, isFalse);
      socket.add(Uint8List.sublistView(packet, 9));
      final (_, connection) = await endOf(c);
      expect(connection, isA<SSHDisconnectError>().having((e) => e.description, 'its words', 'Too many connections'));
    });
  });

  // Against a real OpenSSH server (tool/test_sshd.sh, 127.0.0.1:2299), which
  // lets a connection try six keys and ends it at the sixth it does not
  // know. Skipped when it is not running.
  group('a real server', () {
    final env = Platform.environment;
    final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
    final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
    final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';

    Future<bool> serverUp() async {
      try {
        final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
        s.destroy();
        return true;
      } catch (_) {
        return false;
      }
    }

    /// A key made here and now, which no server knows.
    SSHKeyPair unknownKey(int n) {
      final seed = Uint8List.fromList(List.generate(32, (i) => (i * 7 + n * 31 + 1) & 0xff));
      final signing = nacl.SigningKey(seed: seed);
      return OpenSSHEd25519KeyPair(
        Uint8List.fromList(signing.verifyKey.asTypedList),
        Uint8List.fromList(signing.asTypedList),
        'unknown-$n',
      );
    }

    test('more keys than the server lets a connection try: it ends the connection, and its reason reaches whoever '
        'was signing in', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final client = SSHClient(
        await SSHSocket.connect(host, port),
        username: user,
        identities: [for (var n = 0; n < 8; n++) unknownKey(n)],
      );
      addTearDown(client.close);
      Object? failure;
      try {
        await client.authenticated.timeout(const Duration(seconds: 20));
      } catch (e) {
        failure = e;
      }
      expect(failure, isA<SSHAuthAbortError>());
      final reason = (failure! as SSHAuthAbortError).reason;
      expect(reason, isNotNull, reason: 'the connection ended, and nothing said why');
      expect(
        reason,
        isA<SSHDisconnectError>()
            .having((e) => e.description, 'its words', 'Too many authentication failures')
            .having((e) => e.reasonCode, 'reason code', 2)
            // Signing in comes after the keys and the host key: the server's own.
            .having((e) => e.authentic, 'the server\'s own', isTrue)
            .having((e) => e.message, 'message',
                'The server ended the connection: Too many authentication failures (reason code 2)'),
      );
    });

    test('a key the server knows among a few it does not: signed in, as before', () async {
      if (!await serverUp()) {
        markTestSkipped('the test OpenSSH server is not running');
        return;
      }
      final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
          (Platform.isWindows
              ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test'
              : '${env['HOME']}/zestssh-sshd-test');
      final known = File(env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519');
      if (!known.existsSync()) {
        markTestSkipped('the test key is not there');
        return;
      }
      final client = SSHClient(
        await SSHSocket.connect(host, port),
        username: user,
        identities: [unknownKey(0), unknownKey(1), ...SSHKeyPair.fromPem(known.readAsStringSync())],
      );
      addTearDown(client.close);
      await client.authenticated.timeout(const Duration(seconds: 20));
      expect(String.fromCharCodes(await client.run('echo signed-in')), contains('signed-in'));
    });

    // The fourth test server (127.0.0.1:2293) allows one failed sign-in
    // (MaxAuthTries 1): what a person with one wrong key meets at a server
    // set up that way.
    test('a server that allows one failed sign-in: a single key it does not know, and it ends the connection saying '
        'why; the key it knows signs in there', () async {
      final oneTryPort = int.tryParse(env['ZESTSSH_TEST_ONETRY_SSHD_PORT'] ?? '') ?? 2293;
      final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
          (Platform.isWindows
              ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test'
              : '${env['HOME']}/zestssh-sshd-test');
      final known = File(env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519');
      try {
        (await Socket.connect(host, oneTryPort, timeout: const Duration(seconds: 2))).destroy();
      } catch (_) {
        markTestSkipped('the test OpenSSH server that allows one failed sign-in is not running');
        return;
      }
      if (!known.existsSync()) {
        markTestSkipped('the test key is not there');
        return;
      }
      final stranger = SSHClient(await SSHSocket.connect(host, oneTryPort), username: user, identities: [unknownKey(0)]);
      addTearDown(stranger.close);
      Object? failure;
      try {
        await stranger.authenticated.timeout(const Duration(seconds: 20));
      } catch (e) {
        failure = e;
      }
      expect(failure, isA<SSHAuthAbortError>(), reason: '$failure');
      expect(
        (failure! as SSHAuthAbortError).reason,
        isA<SSHDisconnectError>()
            .having((e) => e.description, 'its words', 'Too many authentication failures')
            .having((e) => e.authentic, 'the server\'s own', isTrue),
      );

      final client = SSHClient(
        await SSHSocket.connect(host, oneTryPort),
        username: user,
        identities: SSHKeyPair.fromPem(known.readAsStringSync()),
      );
      addTearDown(client.close);
      await client.authenticated.timeout(const Duration(seconds: 20));
      expect(String.fromCharCodes(await client.run('echo signed-in')), contains('signed-in'));
    });
  });
}

/// A connection whose other side is the test.
class _HandFed implements SSHSocket {
  final _incoming = StreamController<Uint8List>();
  final _done = Completer<void>();

  /// Bytes from the server.
  void add(Uint8List bytes) => _incoming.add(bytes);

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _Nowhere();

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> flush() async {}

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _incoming.close();
  }

  @override
  void destroy() {
    if (!_done.isCompleted) _done.complete();
    unawaited(_incoming.close());
  }
}

/// What the client sends goes nowhere.
class _Nowhere implements StreamSink<List<int>> {
  @override
  void add(List<int> data) {}

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final _ in stream) {}
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
