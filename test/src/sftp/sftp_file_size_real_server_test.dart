import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// How far a file is read where no length is asked for, against a real
/// OpenSSH server (the second one tool/test_sshd.sh starts, 127.0.0.1:2297,
/// with SFTP). Skipped when it is not running.
///
/// A server's word for a file's size is not always the file's size: Linux
/// reports none for what the kernel makes up when it is read (everything
/// under /proc) and a whole page for what is a few bytes (everything under
/// /sys). Reading as many bytes as the size said gave an empty file for the
/// first.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_REKEY_SSHD_PORT'] ?? '') ?? 2297;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
  final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';
  String? unavailable;

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

  /// What a command prints, byte for byte.
  Future<Uint8List> printed(SSHClient client, String command) => client.run(command).timeout(const Duration(seconds: 15));

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

  test('a file the server reports no size for is read to its end', () async {
    if (unavailable != null) {
      markTestSkipped(unavailable!);
      return;
    }
    final client = await connect();
    final sftp = await client.sftp();
    // The kernel's own name and version: the same at every read.
    const path = '/proc/version';
    final onHost = await printed(client, 'cat $path');
    expect(onHost, isNotEmpty);
    final file = await sftp.open(path);
    expect((await file.stat()).size, 0, reason: 'the server reports no size for it');
    expect(utf8.decode(await file.readBytes()), utf8.decode(onHost));
    // In pieces, as a download takes it.
    final pieces = BytesBuilder();
    await for (final piece in file.read(chunkSize: 16)) {
      pieces.add(piece);
    }
    expect(utf8.decode(pieces.takeBytes()), utf8.decode(onHost));
    // From an offset, to its end.
    expect(utf8.decode(await file.readBytes(offset: 6)), utf8.decode(onHost.sublist(6)));
    await file.close();
    sftp.close();
  });

  test('a file the server reports a larger size for than it has is read to its end, and no further', () async {
    if (unavailable != null) {
      markTestSkipped(unavailable!);
      return;
    }
    final client = await connect();
    final sftp = await client.sftp();
    // A setting of the loopback interface: a number and a line end.
    const path = '/sys/class/net/lo/mtu';
    final onHost = await printed(client, 'cat $path');
    expect(onHost, isNotEmpty);
    final file = await sftp.open(path);
    expect((await file.stat()).size, greaterThan(onHost.length), reason: 'the server reports a whole page');
    expect(utf8.decode(await file.readBytes()), utf8.decode(onHost));
    await file.close();
    sftp.close();
  });

  test('a file of several pages that the server reports no size for, and hands over a page at a time, is read '
      'whole', () async {
    if (unavailable != null) {
      markTestSkipped(unavailable!);
      return;
    }
    final client = await connect();
    final sftp = await client.sftp();
    // What the kernel says of the processors: tens of thousands of bytes on a machine with a few of them.
    const path = '/proc/cpuinfo';
    final before = await printed(client, 'cat $path');
    final file = await sftp.open(path);
    expect((await file.stat()).size, 0, reason: 'the server reports no size for it');
    var counted = 0;
    final pieces = <int>[];
    final read = BytesBuilder();
    await for (final piece in file.read(chunkSize: 4096, onProgress: (total) => counted = total)) {
      pieces.add(piece.length);
      read.add(piece);
    }
    final came = utf8.decode(read.takeBytes());
    final after = await printed(client, 'cat $path');
    if (before.length <= 8192 || utf8.decode(before) != utf8.decode(after)) {
      markTestSkipped('$path is too small on this host, or changes from one read to the next');
      return;
    }
    expect(came, utf8.decode(before));
    expect(counted, before.length);
    // Every piece but the last is as long as was asked for, whatever the server gave at a time.
    expect(pieces.sublist(0, pieces.length - 1).toSet(), {4096});
    await file.close();
    sftp.close();
  });

  test('a file that is being written is read as far as it went when its size was asked', () async {
    if (unavailable != null) {
      markTestSkipped(unavailable!);
      return;
    }
    final client = await connect();
    final sftp = await client.sftp();
    final path = '/tmp/zest-sftp-size-test-$pid.log';
    addTearDown(() async {
      try {
        await printed(client, 'rm -f $path');
      } catch (_) {}
    });
    await printed(client, "printf 'first line\\n' > $path");
    final file = await sftp.open(path);
    var seen = 0;
    final read = BytesBuilder();
    // In pieces of four bytes, one asked for at a time: the size was asked for by the time the first comes, and
    // it was 11.
    await for (final piece in file.read(chunkSize: 4, maxPendingRequests: 1, onProgress: (total) => seen = total)) {
      // The file gains a line while it is read (a log in use).
      if (read.isEmpty) await printed(client, "printf 'second line\\n' >> $path");
      read.add(piece);
    }
    expect(utf8.decode(read.takeBytes()), 'first line\n', reason: 'as it was when its size was asked: not followed');
    expect(seen, 11);
    // Read again, it is the file it is by now.
    expect(utf8.decode(await file.readBytes()), 'first line\nsecond line\n');
    // A number of bytes that was asked for is a number of bytes, as before.
    expect(utf8.decode(await file.readBytes(length: 5)), 'first');
    expect(utf8.decode(await file.readBytes(length: 6, offset: 6)), 'line\ns');
    expect(await file.readBytes(length: 0), isEmpty);
    // Past its end there is nothing, and that is no error.
    expect(await file.readBytes(offset: 23), isEmpty);
    expect(await file.readBytes(offset: 500), isEmpty);
    await file.close();
    sftp.close();
  });

  test('a file of no bytes is a file of no bytes', () async {
    if (unavailable != null) {
      markTestSkipped(unavailable!);
      return;
    }
    final client = await connect();
    final sftp = await client.sftp();
    final path = '/tmp/zest-sftp-size-test-$pid.empty';
    addTearDown(() async {
      try {
        await printed(client, 'rm -f $path');
      } catch (_) {}
    });
    await printed(client, ': > $path');
    final file = await sftp.open(path);
    expect(await file.readBytes(), isEmpty);
    final sink = _Collect();
    expect(await file.downloadTo(sink), 0);
    expect(sink.bytes.takeBytes(), isEmpty);
    await file.close();
    sftp.close();
  });
}

/// Where a download is written, for a test to look at.
class _Collect implements StreamSink<List<int>> {
  final bytes = BytesBuilder();

  @override
  void add(List<int> event) => bytes.add(event);

  @override
  void addError(Object error, [StackTrace? stackTrace]) => throw error;

  @override
  Future<void> addStream(Stream<List<int>> stream) => stream.forEach(add);

  @override
  Future<void> close() async {}

  @override
  Future<void> get done async {}
}
