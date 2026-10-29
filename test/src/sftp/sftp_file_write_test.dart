// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io' show FileSystemException;
import 'dart:typed_data';

import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/sftp/sftp_client.dart';
import 'package:zest_ssh_core/src/sftp/sftp_errors.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/sftp/sftp_status_code.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:test/test.dart';

/// Writing a stream to a file ([SftpFile.write]), with the server played
/// here.
///
/// The writer listened to what it was given to write for data and for its
/// end, and for nothing else: where that stream failed (a file on a stick
/// that is pulled out, a file that another program holds), the error went
/// to nobody, the stream ended behind it, and the writing was over without
/// a failure, with as much written as had come. Whoever uploaded a file was
/// told that it was done, or had to find out from the size of what the
/// server held.
void main() {
  /// How [asked] has ended by now: 'waiting' while it has not, 'done', or
  /// what it failed with.
  Object Function() watch(Future<Object?> asked) {
    Object ended = 'waiting';
    unawaited(asked.then<void>((_) => ended = 'done', onError: (Object e) => ended = e));
    return () => ended;
  }

  /// Runs [body], and gives everything that was thrown at nobody meanwhile.
  /// (What [body] itself fails with, an expectation of the test's, fails
  /// the test.)
  Future<List<Object>> thrownAtNobody(Future<void> Function() body) async {
    final uncaught = <Object>[];
    final over = Completer<void>();
    runZonedGuarded(() async {
      try {
        await body();
        over.complete();
      } catch (error, stack) {
        over.completeError(error, stack);
      }
    }, (error, stack) => uncaught.add(error));
    await over.future;
    return uncaught;
  }

  const broke = FileSystemException('The device is not ready', 'report.pdf');

  test('what it is given to write fails half way: the writing ends with what that failed with, at once, the stream '
      'is let go of, and nothing is thrown at nobody', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final file = await harness.opened('/srv/app/report.pdf');
        final source = StreamController<Uint8List>();
        final writer = file.write(source.stream);
        final done = watch(writer.done);

        source.add(Uint8List(40000));
        await harness.settle();
        expect(harness.writes().map((write) => (write.offset, write.data.length)), [(0, 32768), (32768, 7232)]);
        // The first piece is answered, the second is still on its way.
        harness.answer(harness.writes().first);
        await harness.settle();
        expect(done(), 'waiting');

        source.addError(broke);
        await harness.settle();
        expect(done(), same(broke), reason: 'and not when the server has answered what was on its way');
        expect(source.hasListener, isFalse);
        expect(writer.progress, 32768, reason: 'what the server has said yes to');

        // The answer to what was on its way comes later, and is nothing to anybody.
        harness.answer(harness.writes().last);
        await harness.settle();
        expect(done(), same(broke));
        expect(harness.writes(), hasLength(2), reason: 'nothing more was sent');
      }),
      isEmpty,
    );
  });

  test('what it is given to write fails before anything came: the writing fails with that, and nothing is sent',
      () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final file = await harness.opened('/srv/app/report.pdf');
        final writer = file.write(Stream<Uint8List>.error(broke));
        final done = watch(writer.done);
        await harness.settle();
        expect(done(), same(broke));
        expect(harness.writes(), isEmpty);
      }),
      isEmpty,
    );
  });

  test('a write that the server refuses ends the writing with the refusal, nothing more is sent, and a refusal '
      'that follows is an error for nobody', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final file = await harness.opened('/srv/app/report.pdf');
        final source = StreamController<Uint8List>();
        final writer = file.write(source.stream);
        final done = watch(writer.done);

        source.add(Uint8List(3 * 32768));
        await harness.settle();
        final writes = harness.writes().toList();
        expect(writes, hasLength(3));
        harness.answer(writes[0]);
        harness.refuse(writes[1], 'No space left on device');
        await harness.settle();
        expect(done(), isA<SftpStatusError>().having((e) => e.message, 'message', 'No space left on device'));

        // What it was writing goes on giving: nothing of that is sent, and the stream is let go of by then.
        harness.refuse(writes[2], 'No space left on device');
        source.add(Uint8List(100));
        await harness.settle();
        expect(harness.writes(), hasLength(3), reason: 'nothing more was sent');
        expect(source.hasListener, isFalse);
      }),
      isEmpty,
    );
  });

  test('no more is on its way unanswered than a megabyte and one piece: what it writes is taken only as fast as '
      'the server answers, and all of it arrives in its place', () async {
    final harness = await _Harness.started();
    final file = await harness.opened('/srv/app/video.mkv');
    final content = Uint8List.fromList([for (var i = 0; i < 3 * 1024 * 1024; i++) (i * 31 + i ~/ 251) % 256]);
    final writer = file.write(Stream.value(content), offset: 100);
    final done = watch(writer.done);

    // A server that answers nothing: a megabyte and one piece go out, and no more.
    await harness.settle();
    await harness.settle();
    expect(harness.writes(), hasLength(33));
    expect(done(), 'waiting');

    // It answers one at a time: never more than that is unanswered.
    final written = Uint8List(content.length);
    var answered = 0;
    while (done() == 'waiting') {
      final writes = harness.writes().toList();
      expect(writes.length - answered, lessThanOrEqualTo(33));
      if (answered == writes.length) {
        await harness.settle();
        continue;
      }
      final write = writes[answered++];
      written.setRange(write.offset - 100, write.offset - 100 + write.data.length, write.data);
      harness.answer(write);
      await Future<void>.delayed(Duration.zero);
    }
    expect(done(), 'done');
    expect(answered, 96, reason: 'three megabytes in pieces of 32768 bytes');
    expect(written, content);
    expect(writer.progress, content.length);
  });
}

/// An SFTP client whose server is played by the test.
class _Harness {
  _Harness() {
    _controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 1024 * 1024,
      localInitialWindowSize: 16 * 1024 * 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 1024 * 1024,
      remoteInitialWindowSize: 16 * 1024 * 1024,
      sendMessage: sent.add,
    );
    client = SftpClient(_controller.channel);
  }

  /// A client whose handshake is done.
  static Future<_Harness> started() async {
    final harness = _Harness();
    await harness.settle();
    harness.serverSends(SftpVersionPacket(3));
    await harness.client.handshake;
    return harness;
  }

  late final SSHChannelController _controller;
  late final SftpClient client;

  /// Everything the client's channel sent.
  final sent = <SSHMessage>[];

  /// Lets what was asked reach the channel, and what it says reach whoever asked.
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 20));

  /// Every SFTP packet the client sent, in order (each goes out as one piece of data).
  Iterable<Uint8List> packets() => sent.whereType<SSH_Message_Channel_Data>().map((message) {
        final reader = SSHMessageReader(message.data);
        return reader.readBytes(reader.readUint32());
      });

  /// Every write the client sent, in order.
  Iterable<SftpWritePacket> writes() =>
      packets().where((packet) => packet[0] == SftpWritePacket.packetType).map(SftpWritePacket.decode);

  /// A file opened at [path], the server having handed out a handle for it.
  Future<SftpFile> opened(String path) async {
    final file = client.open(path);
    await settle();
    final open = SftpOpenPacket.decode(packets().last);
    serverSends(SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])));
    return file;
  }

  /// The server says yes to [write].
  void answer(SftpWritePacket write) =>
      serverSends(SftpStatusPacket(requestId: write.requestId, code: SftpStatusCode.ok, message: 'OK'));

  /// The server refuses [write], with [words].
  void refuse(SftpWritePacket write, String words) =>
      serverSends(SftpStatusPacket(requestId: write.requestId, code: SftpStatusCode.failure, message: words));

  void serverSends(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter()
      ..writeUint32(payload.length)
      ..writeBytes(payload);
    _controller.handleMessage(SSH_Message_Channel_Data(recipientChannel: 1, data: writer.takeBytes()));
  }
}
