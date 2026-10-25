import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// How much the other side may send on a channel (its window) is opened
/// again as what came is read. A reader that stops for a while (it writes
/// what it gets somewhere slower, or has not begun to read yet) holds the
/// window where it is, so that no more than a window's worth waits here. If
/// the other side used the window up to its last byte meanwhile, nothing
/// opened it again when the reader came back: the channel stood still for
/// good, with no error, since nothing more could come to open it by.
void main() {
  /// A channel as the client makes one, with a window of 1024 bytes, and
  /// what it sent.
  (SSHChannelController, List<SSHMessage>) make() {
    final sent = <SSHMessage>[];
    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 32768,
      localInitialWindowSize: 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 32768,
      remoteInitialWindowSize: 1024,
      sendMessage: sent.add,
    );
    addTearDown(controller.destroy);
    return (controller, sent);
  }

  void feed(SSHChannelController controller, int bytes) =>
      controller.handleMessage(SSH_Message_Channel_Data(recipientChannel: 1, data: Uint8List(bytes)));

  /// By how many bytes the window was opened again, each time it was.
  List<int> opened(List<SSHMessage> sent) =>
      [for (final message in sent.whereType<SSH_Message_Channel_Window_Adjust>()) message.bytesToAdd];

  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 20));

  test('what is read as it comes opens the window again by as much', () async {
    final (controller, sent) = make();
    var read = 0;
    controller.channel.stream.listen((data) => read += data.bytes.length);
    feed(controller, 300);
    feed(controller, 200);
    await settle();
    expect(read, 500);
    expect(opened(sent), [300, 200]);
  });

  test('a reader that stopped and comes back: the window opens again, also where the other side had used it up to '
      'the last byte', () async {
    final (controller, sent) = make();
    var read = 0;
    final reading = controller.channel.stream.listen((data) => read += data.bytes.length);
    reading.pause();
    for (var i = 0; i < 4; i++) {
      feed(controller, 256);
    }
    await settle();
    expect(opened(sent), isEmpty, reason: 'held while nobody reads: no more than a window waits here');

    reading.resume();
    await settle();
    expect(read, 1024);
    expect(opened(sent), [1024], reason: 'nothing more can come to open it by');

    // And it goes on from there.
    feed(controller, 100);
    await settle();
    expect(read, 1124);
    expect(opened(sent), [1024, 100]);
  });

  test('a reader that stopped with some of the window left: opened again by what had come', () async {
    final (controller, sent) = make();
    final reading = controller.channel.stream.listen((_) {});
    reading.pause();
    feed(controller, 500);
    await settle();
    expect(opened(sent), isEmpty);
    reading.resume();
    await settle();
    expect(opened(sent), [500]);
  });

  test('whoever begins to read after the window was used up: the same', () async {
    final (controller, sent) = make();
    for (var i = 0; i < 4; i++) {
      feed(controller, 256);
    }
    await settle();
    expect(opened(sent), isEmpty);

    var read = 0;
    controller.channel.stream.listen((data) => read += data.bytes.length);
    await settle();
    expect(read, 1024);
    expect(opened(sent), [1024]);
  });

  test('a reader that begins, or stops and comes back, with nothing having come: nothing is said of the window',
      () async {
    final (controller, sent) = make();
    final reading = controller.channel.stream.listen((_) {});
    await settle();
    reading.pause();
    reading.resume();
    await settle();
    expect(sent, isEmpty);
    // And once the window is whole again, a reader that comes back says nothing more.
    feed(controller, 100);
    await settle();
    reading.pause();
    reading.resume();
    await settle();
    expect(opened(sent), [100]);
  });

  test('more than the window allows ends the channel, as before', () async {
    final (controller, sent) = make();
    controller.channel.stream.listen((_) {}).pause();
    feed(controller, 1024);
    feed(controller, 1);
    await settle();
    expect(opened(sent), isEmpty);
    await controller.channel.done.timeout(const Duration(seconds: 2));
  });

  // Against a real OpenSSH server (tool/test_sshd.sh, 127.0.0.1:2299): a
  // program that prints eight megabytes, read by someone who stops for a
  // second after the first piece. The server sends until the window is
  // used up, to the byte, and waits.
  test('a real server: a program whose output is read with a stop in it is read to its end', () async {
    final env = Platform.environment;
    final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
    final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
    final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
    final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
        (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
    final key = File(env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519');
    try {
      (await Socket.connect(host, port, timeout: const Duration(seconds: 2))).destroy();
    } catch (_) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    if (!key.existsSync()) {
      markTestSkipped('the test key is not there');
      return;
    }
    final client = SSHClient(
      await SSHSocket.connect(host, port),
      username: user,
      identities: SSHKeyPair.fromPem(key.readAsStringSync()),
    );
    addTearDown(client.close);
    await client.authenticated.timeout(const Duration(seconds: 20));

    const size = 8 * 1024 * 1024;
    final session = await client.execute('head -c $size /dev/zero');
    var read = 0;
    final ended = Completer<void>();
    late final StreamSubscription<Uint8List> reading;
    reading = session.stdout.listen(
      (data) {
        if (read == 0) {
          // Whoever reads has something else to do for a second.
          reading.pause(Future<void>.delayed(const Duration(seconds: 1)));
        }
        read += data.length;
      },
      onDone: ended.complete,
    );
    await ended.future.timeout(const Duration(seconds: 30), onTimeout: () {});
    expect(read, size, reason: 'it stood still at ${utf8.decode(utf8.encode('$read'))} bytes');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
