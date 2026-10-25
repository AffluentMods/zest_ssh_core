import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// SFTP against a real OpenSSH server: that it works there at all (a file
/// of a few megabytes written and read back, on a server that asks for new
/// keys every megabyte), and what becomes of a session that ends under its
/// requests: the network breaking, the connection closing, the server's
/// SFTP server ending while the connection goes on. Each of these left
/// whatever had asked waiting for ever.
///
/// The server is the second one tool/test_sshd.sh starts (127.0.0.1:2297,
/// "RekeyLimit 1M", with SFTP). Skipped when it is not running, or was
/// started before it had SFTP.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_REKEY_SSHD_PORT'] ?? '') ?? 2297;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
  final keyPath = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';
  const reset = SocketException('Connection reset by peer');
  var folders = 0;
  String? unavailable;

  Future<(SSHClient, _GatedSocket)> connect() async {
    final socket = _GatedSocket(await SSHSocket.connect(host, port));
    final client = SSHClient(
      socket,
      username: user,
      identities: SSHKeyPair.fromPem(File(keyPath).readAsStringSync()),
    );
    await client.authenticated;
    return (client, socket);
  }

  Future<String> run(SSHClient client, String command) async =>
      utf8.decode(await client.run(command).timeout(const Duration(seconds: 15))).trim();

  setUpAll(() async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      if (!File(keyPath).existsSync()) {
        unavailable = 'the test key is not there';
        return;
      }
      final (client, _) = await connect();
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

  /// A folder of this test's own on the server, removed when the test ends.
  Future<String> folder() async {
    final path = '/tmp/zest-sftp-test-$pid-${folders++}';
    final (client, _) = await connect();
    await run(client, 'mkdir -p $path');
    client.close();
    addTearDown(() async {
      final (cleaner, _) = await connect();
      await run(cleaner, 'rm -rf $path');
      cleaner.close();
    });
    return path;
  }

  /// [size] bytes that do not repeat soon.
  Uint8List bytes(int size) {
    final out = Uint8List(size);
    var x = 0x2545F491;
    for (var i = 0; i < size; i++) {
      x = (x * 1103515245 + 12345) & 0x7fffffff;
      out[i] = x >> 16;
    }
    return out;
  }

  /// How [asked] has ended by now: 'waiting', 'answered', or what it failed
  /// with.
  Object Function() watch(Future<Object?> asked) {
    Object ended = 'waiting';
    unawaited(asked.then<void>((_) => ended = 'answered', onError: (Object e) => ended = e));
    return () => ended;
  }

  Future<void> aMoment() => Future<void>.delayed(const Duration(milliseconds: 300));

  final broken = isA<SSHSocketError>().having((e) => e.error, 'error', same(reset));
  final closed = isA<SSHStateError>()
      .having((e) => e.message, 'message', 'Connection closed before the request was answered');

  test('a file of three megabytes written, read back the same, listed and removed', () async {
    if (unavailable != null) return markTestSkipped(unavailable!);
    final (client, _) = await connect();
    addTearDown(client.close);
    final sftp = await client.sftp();
    final at = await folder();
    final path = '$at/three-megabytes.bin';
    final content = bytes(3 * 1024 * 1024 + 17);

    final writing = await sftp.open(
      path,
      mode: SftpFileOpenMode.create | SftpFileOpenMode.write | SftpFileOpenMode.truncate,
    );
    await writing.write(Stream.value(content)).done.timeout(const Duration(seconds: 60));
    await writing.close();
    expect((await sftp.stat(path)).size, content.length);
    expect((await sftp.listdir(at)).map((name) => name.filename), contains('three-megabytes.bin'));

    final reading = await sftp.open(path);
    final back = await reading.readBytes().timeout(const Duration(seconds: 60));
    await reading.close();
    expect(back.length, content.length);
    expect(back, content);

    await sftp.remove(path);
    expect((await sftp.listdir(at)).map((name) => name.filename), isNot(contains('three-megabytes.bin')));
    sftp.close();
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('the network breaks with a listing and a look at a file under way: each fails with what the network said, '
      'and so does what is asked afterwards', () async {
    if (unavailable != null) return markTestSkipped(unavailable!);
    final (client, socket) = await connect();
    addTearDown(client.close);
    final sftp = await client.sftp();
    final at = await folder();
    expect(await sftp.listdir(at), isNotEmpty, reason: 'it answers while the connection is there');
    // Nothing the server says is heard from here on.
    socket.hold = true;
    final list = watch(sftp.listdir(at));
    final stat = watch(sftp.stat(at));
    await aMoment();
    expect([list(), stat()], ['waiting', 'waiting']);
    socket.breakWith(reset);
    await aMoment();
    expect(list(), broken);
    expect(stat(), broken);
    final afterwards = watch(sftp.stat(at));
    await aMoment();
    expect(afterwards(), broken);
  });

  test('the connection closes with a request under way: said as a connection that closed', () async {
    if (unavailable != null) return markTestSkipped(unavailable!);
    final (client, socket) = await connect();
    final sftp = await client.sftp();
    socket.hold = true;
    final stat = watch(sftp.stat('/tmp'));
    await aMoment();
    expect(stat(), 'waiting');
    socket.destroy();
    await aMoment();
    expect(stat(), closed);
    final afterwards = watch(sftp.listdir('/tmp'));
    await aMoment();
    expect(afterwards(), closed);
  });

  test('the server\'s SFTP server ends while the connection goes on: its session is over, said as that, and '
      'another can be opened', () async {
    if (unavailable != null) return markTestSkipped(unavailable!);
    final (client, _) = await connect();
    addTearDown(client.close);
    final sftp = await client.sftp();
    expect((await sftp.stat('/tmp')).isDirectory, isTrue);
    // The server's process for this connection is the parent of what it
    // runs for it: of the shell that says so here, and of its SFTP server.
    final connection = await run(client, 'echo \$PPID');
    expect(int.tryParse(connection), isNotNull, reason: connection);
    // (The pattern is written so that it does not find the shell it is typed into.)
    expect(await run(client, 'pkill -P $connection -f "internal-sft[p]"; echo \$?'), '0', reason: 'it was running');
    await aMoment();
    final over = isA<SftpAbortError>().having((e) => e.message, 'message', 'The server closed the SFTP session');
    final stat = watch(sftp.stat('/tmp'));
    await aMoment();
    expect(stat(), over);
    // The connection is there, and gives a new session.
    expect(await run(client, 'echo still-here'), 'still-here');
    final again = await client.sftp();
    expect((await again.stat('/tmp')).isDirectory, isTrue);
    again.close();
  });

  test('a download under way when the network breaks ends with what the network said, and throws at nobody',
      () async {
    if (unavailable != null) return markTestSkipped(unavailable!);
    final at = await folder();
    final path = '$at/download.bin';
    final content = bytes(3 * 1024 * 1024);
    final (writer, _) = await connect();
    final upload = await (await writer.sftp()).open(
      path,
      mode: SftpFileOpenMode.create | SftpFileOpenMode.write | SftpFileOpenMode.truncate,
    );
    await upload.write(Stream.value(content)).done.timeout(const Duration(seconds: 60));
    await upload.close();
    writer.close();

    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final (client, socket) = await connect();
      final sftp = await client.sftp();
      final sink = _Sink();
      var broke = false;
      final download = watch(sftp.download(path, sink, onProgress: (read) {
        if (broke || read < 256 * 1024) return;
        broke = true;
        socket.breakWith(reset);
      }));
      final clock = Stopwatch()..start();
      while (download() == 'waiting' && clock.elapsed < const Duration(seconds: 20)) {
        await Future<void>.delayed(const Duration(milliseconds: 20));
      }
      expect(broke, isTrue, reason: 'it was under way');
      expect(download(), broken);
      expect(sink.length, lessThan(content.length));
      await aMoment();
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('closed from here with a request under way: it fails as a session that was closed, and the connection goes on',
      () async {
    if (unavailable != null) return markTestSkipped(unavailable!);
    final (client, _) = await connect();
    addTearDown(client.close);
    final sftp = await client.sftp();
    // Asked, and closed before the server's answer can have come.
    final stat = watch(sftp.stat('/tmp'));
    sftp.close();
    await aMoment();
    expect(stat(), isA<SftpAbortError>().having((e) => e.message, 'message', 'Connection closed'));
    final afterwards = watch(sftp.stat('/tmp'));
    await aMoment();
    expect(afterwards(), isA<SftpAbortError>());
    expect(await run(client, 'echo still-here'), 'still-here');
    // And SFTP can be opened again on the connection.
    final again = await client.sftp();
    expect((await again.stat('/tmp')).isDirectory, isTrue);
    again.close();
  });
}

/// A real socket whose incoming data can be held back, as on a connection
/// that has gone quiet, and that can be made to break.
class _GatedSocket implements SSHSocket {
  _GatedSocket(this._socket) {
    _socket.stream.listen(
      (data) {
        if (!hold) _incoming.add(data);
      },
      onError: _incoming.addError,
      onDone: _incoming.close,
    );
  }

  final SSHSocket _socket;
  final _incoming = StreamController<Uint8List>();

  /// While true, what the server sends is dropped.
  bool hold = false;

  /// The network breaks: the connection ends with [error].
  void breakWith(Object error) => _incoming.addError(error);

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _socket.sink;

  @override
  Future<void> get done => _socket.done;

  @override
  Future<void> flush() => _socket.flush();

  @override
  Future<void> close() => _socket.close();

  @override
  void destroy() => _socket.destroy();
}

/// Where a download writes to: only how much came is kept.
class _Sink implements StreamSink<List<int>> {
  var length = 0;
  final _done = Completer<void>();

  @override
  void add(List<int> event) => length += event.length;

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      add(chunk);
    }
  }

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
  }

  @override
  Future<void> get done => _done.future;
}
