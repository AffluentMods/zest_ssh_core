import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// Putting a file in the place of another in one step, and making a file
/// with the permissions it is to have: what an upload needs to replace a
/// file on a host without a moment in which there is none, and without the
/// new one being readable by more people than the old one at any time.
/// SFTP's own rename is refused for a name that is taken by most servers,
/// so a file could only be replaced by removing it first; OpenSSH has
/// rename(2) as an extension (posix-rename@openssh.com).
///
/// With a server played here, and against a real OpenSSH server (the second
/// one tool/test_sshd.sh starts, 127.0.0.1:2297, with SFTP; those are
/// skipped when it is not running).
void main() {
  group('a server played by the test', () {
    test('a server that has it: the request names both paths, and its answer is the end of it', () async {
      final harness = _Harness(extensions: {'posix-rename@openssh.com': '1'});
      addTearDown(harness.dispose);
      expect(await harness.client.canPosixRename, isTrue);

      final renamed = harness.client.posixRename('/srv/site.zestpart', '/srv/site');
      final request = SftpExtendedPacket.decode(await harness.next());
      final reader = SSHMessageReader(request.payload);
      expect(reader.readUtf8(), 'posix-rename@openssh.com');
      expect(reader.readUtf8(), '/srv/site.zestpart');
      expect(reader.readUtf8(), '/srv/site');
      expect(reader.isDone, isTrue);
      harness.reply(SftpStatusPacket(requestId: request.requestId, code: SftpStatusCode.ok, message: 'ok'));
      await renamed;

      // Its no is the request's failure.
      final refused = harness.client.posixRename('/srv/a.zestpart', '/srv/a');
      final second = SftpExtendedPacket.decode(await harness.next());
      harness.reply(SftpStatusPacket(
          requestId: second.requestId, code: SftpStatusCode.permissionDenied, message: 'Permission denied'));
      await expectLater(
          refused, throwsA(isA<SftpStatusError>().having((e) => e.code, 'code', SftpStatusCode.permissionDenied)));
    });

    test('a server that has it not, or another version of it: said before anything is sent', () async {
      for (final extensions in [<String, String>{}, {'posix-rename@openssh.com': '2'}]) {
        final harness = _Harness(extensions: extensions);
        addTearDown(harness.dispose);
        expect(await harness.client.canPosixRename, isFalse, reason: '$extensions');
        await expectLater(harness.client.posixRename('/srv/a.zestpart', '/srv/a'), throwsA(isA<SftpExtensionError>()));
        expect(harness.waiting, isEmpty, reason: 'nothing was asked of the server');
      }
    });

    test('a file is opened with the attributes it is to be made with, and with none where none are given', () async {
      final harness = _Harness();
      addTearDown(harness.dispose);
      final opening = harness.client.open(
        '/srv/key.zestpart',
        mode: SftpFileOpenMode.create | SftpFileOpenMode.write,
        attrs: SftpFileAttrs(mode: const SftpFileMode.value(384)),
      );
      final open = SftpOpenPacket.decode(await harness.next());
      expect(open.attrs.mode?.value, 384, reason: 'rw for its owner and nobody else');
      harness.reply(SftpHandlePacket(open.requestId, Uint8List.fromList([1])));
      await opening;

      final plain = harness.client.open('/srv/notes.txt');
      final second = SftpOpenPacket.decode(await harness.next());
      expect(second.attrs.mode, isNull);
      harness.reply(SftpHandlePacket(second.requestId, Uint8List.fromList([2])));
      await plain;
    });
  });

  group('a real server', () {
    final env = Platform.environment;
    final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
    final port = int.tryParse(env['ZESTSSH_TEST_REKEY_SSHD_PORT'] ?? '') ?? 2297;
    final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
    final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
        (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
    final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';
    String? unavailable;
    var folders = 0;

    Future<SSHClient> connect() async {
      final client = SSHClient(
        await SSHSocket.connect(host, port, timeout: const Duration(seconds: 5)),
        username: user,
        identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
      );
      addTearDown(client.close);
      await client.authenticated.timeout(const Duration(seconds: 20));
      return client;
    }

    Future<String> run(SSHClient client, String command) async =>
        utf8.decode(await client.run(command).timeout(const Duration(seconds: 15))).trim();

    setUpAll(() async {
      try {
        (await Socket.connect(host, port, timeout: const Duration(seconds: 2))).destroy();
        if (!File(keyPath).existsSync()) {
          unavailable = 'the test key is not there';
          return;
        }
        final client = SSHClient(
          await SSHSocket.connect(host, port),
          username: user,
          identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
        );
        try {
          (await client.sftp()).close();
        } on SSHChannelRequestError {
          unavailable = 'the test server at $host:$port has no SFTP: start it again with tool/test_sshd.sh';
        } finally {
          client.close();
        }
      } catch (_) {
        unavailable = 'the test OpenSSH server is not running';
      }
    });

    /// A connection, SFTP on it, and a folder of this test's own on the server, removed when the test ends.
    Future<(SSHClient, SftpClient, String)> opened() async {
      final client = await connect();
      final sftp = await client.sftp();
      final path = '/tmp/zest-sftp-rename-test-$pid-${folders++}';
      await run(client, 'mkdir -p $path');
      addTearDown(() async {
        try {
          await run(client, 'rm -rf $path');
        } catch (_) {}
      });
      return (client, sftp, path);
    }

    test('a name that is taken: the plain rename is refused, and the one of rename(2) replaces the file in one step',
        () async {
      if (unavailable != null) {
        markTestSkipped(unavailable!);
        return;
      }
      final (client, sftp, folder) = await opened();
      expect(await sftp.canPosixRename, isTrue);
      await run(client, "printf 'old' > $folder/site; printf 'new' > $folder/site.zestpart");

      await expectLater(sftp.rename('$folder/site.zestpart', '$folder/site'), throwsA(isA<SftpStatusError>()));
      expect(await run(client, 'cat $folder/site; ls $folder | wc -l'), 'old2', reason: 'both are as they were');

      await sftp.posixRename('$folder/site.zestpart', '$folder/site');
      expect(await run(client, 'cat $folder/site; ls $folder | wc -l'), 'new1');

      // What is not there cannot be put anywhere.
      await expectLater(
        sftp.posixRename('$folder/nothing', '$folder/site'),
        throwsA(isA<SftpStatusError>().having((e) => e.code, 'code', SftpStatusCode.noSuchFile)),
      );
      sftp.close();
    });

    test('a file is made with the permissions it is opened with, from the moment it is there', () async {
      if (unavailable != null) {
        markTestSkipped(unavailable!);
        return;
      }
      final (client, sftp, folder) = await opened();
      final file = await sftp.open(
        '$folder/key',
        mode: SftpFileOpenMode.create | SftpFileOpenMode.write,
        attrs: SftpFileAttrs(mode: const SftpFileMode.value(384)),
      );
      // Before anything is written to it, and before it is closed.
      expect(await run(client, 'stat -c %a $folder/key'), '600');
      await file.writeBytes(Uint8List.fromList(utf8.encode('a secret')));
      await file.close();
      expect(await run(client, 'cat $folder/key; echo; stat -c %a $folder/key'), 'a secret\n600');
      sftp.close();
    });
  });
}

/// A client whose server is the test: what it sends is kept in order, and
/// what the test replies comes in as the server's.
class _Harness {
  _Harness({Map<String, String> extensions = const {}}) {
    _controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 1024 * 1024,
      sendMessage: _fromClient,
    );
    client = SftpClient(_controller.channel);
    // The first packet is the client's version; the server's follows.
    unawaited(next().then((_) => reply(SftpVersionPacket(3, extensions))));
  }

  late final SSHChannelController _controller;
  late final SftpClient client;

  /// What the client has sent and the test has not taken yet.
  final waiting = <Uint8List>[];
  Completer<void>? _arrival;
  var _disposed = false;

  void _fromClient(SSHMessage message) {
    if (message is! SSH_Message_Channel_Data) return;
    final reader = SSHMessageReader(message.data);
    while (!reader.isDone) {
      waiting.add(reader.readBytes(reader.readUint32()));
    }
    _arrival?.complete();
    _arrival = null;
  }

  /// The next packet the client sends.
  Future<Uint8List> next() async {
    while (waiting.isEmpty) {
      await (_arrival ??= Completer<void>()).future.timeout(const Duration(seconds: 10));
    }
    return waiting.removeAt(0);
  }

  void reply(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter()
      ..writeUint32(payload.length)
      ..writeBytes(payload);
    _controller.handleMessage(
      SSH_Message_Channel_Data(recipientChannel: _controller.localId, data: writer.takeBytes()),
    );
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    try {
      client.close();
    } catch (_) {}
    _controller.destroy();
  }
}
