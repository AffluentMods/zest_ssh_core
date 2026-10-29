// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/sftp/sftp_client.dart';
import 'package:zest_ssh_core/src/sftp/sftp_errors.dart';
import 'package:zest_ssh_core/src/sftp/sftp_file_attrs.dart';
import 'package:zest_ssh_core/src/sftp/sftp_name.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/sftp/sftp_status_code.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:test/test.dart';

/// Listing a directory ([SftpClient.readdir], [SftpClient.listdir]), with
/// the server played here: what becomes of the directory's handle.
///
/// The handle was closed where the listing had been read to its end, and
/// nowhere else: a listing that the server refused half way, and one that
/// whoever listened gave up, left the directory open on the server for as
/// long as the session lasted. A server lets a session hold only so many.
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

  test('a listing that the server refuses half way fails with the refusal, at once, and the directory is closed; '
      'what the server says to that is nobody\'s', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final listing = harness.client.listdir('/srv/app');
        final ended = watch(listing);
        await harness.opensTheDirectory();

        harness.names(['a.conf', 'b.conf']);
        await harness.settle();
        expect(ended(), 'waiting');
        harness.refuse(harness.reads().last, 'Input/output error');
        await harness.settle();
        expect(ended(), isA<SftpStatusError>().having((e) => e.message, 'message', 'Input/output error'),
            reason: 'and not when the server has answered the close');
        expect(harness.closes().map((close) => close.handle), [harness.handle]);
        expect(harness.reads(), hasLength(2), reason: 'nothing more was asked');

        // The close is refused as well: an error for nobody.
        harness.refuse(harness.closes().single, 'Bad message');
        await harness.settle();
        expect(ended(), isA<SftpStatusError>().having((e) => e.message, 'message', 'Input/output error'));
      }),
      isEmpty,
    );
  });

  test('a listing that whoever listened gives up closes the directory', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final came = <List<String>>[];
        final listening =
            harness.client.readdir('/srv/app').listen((names) => came.add([for (final n in names) n.filename]));
        await harness.opensTheDirectory();
        harness.names(['a.conf', 'b.conf']);
        await harness.settle();
        expect(came, [
          ['a.conf', 'b.conf'],
        ]);
        expect(harness.closes(), isEmpty);

        // Given up with the next piece asked for and not yet answered.
        final given = watch(listening.cancel());
        await harness.settle();
        harness.names(['c.conf']);
        await harness.settle();
        expect(given(), 'done');
        expect(harness.closes().map((close) => close.handle), [harness.handle]);
        expect(came, hasLength(1), reason: 'what came after it was given up goes to nobody');
        harness.answer(harness.closes().single);
        await harness.settle();
        expect(harness.reads(), hasLength(2));
      }),
      isEmpty,
    );
  });

  test('a listing that is read to its end closes the directory once, and is over when the server has answered '
      'that', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final listing = harness.client.listdir('/srv/app');
        final ended = watch(listing);
        await harness.opensTheDirectory();
        harness.names(['a.conf', 'b.conf']);
        await harness.settle();
        harness.names(['c.conf']);
        await harness.settle();
        harness.end(harness.reads().last);
        await harness.settle();
        expect(harness.closes().map((close) => close.handle), [harness.handle]);
        expect(ended(), 'waiting');
        harness.answer(harness.closes().single);
        await harness.settle();
        expect(ended(), 'done');
        expect((await listing).map((name) => name.filename), ['a.conf', 'b.conf', 'c.conf']);
        expect(harness.closes(), hasLength(1));
      }),
      isEmpty,
    );
  });

  test('a listing that is read to its end fails where the server refuses the close, as it did', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final ended = watch(harness.client.listdir('/srv/app'));
        await harness.opensTheDirectory();
        harness.names(['a.conf']);
        await harness.settle();
        harness.end(harness.reads().last);
        await harness.settle();
        harness.refuse(harness.closes().single, 'Bad message');
        await harness.settle();
        expect(ended(), isA<SftpStatusError>().having((e) => e.message, 'message', 'Bad message'));
        expect(harness.closes(), hasLength(1));
      }),
      isEmpty,
    );
  });

  test('a directory that the server does not open is one that there is nothing to close of', () async {
    expect(
      await thrownAtNobody(() async {
        final harness = await _Harness.started();
        final ended = watch(harness.client.listdir('/root'));
        await harness.settle();
        final open = SftpOpenDirPacket.decode(harness.packets().last);
        harness.serverSends(
            SftpStatusPacket(requestId: open.requestId, code: SftpStatusCode.permissionDenied, message: 'Permission denied'));
        await harness.settle();
        expect(ended(), isA<SftpStatusError>().having((e) => e.code, 'code', SftpStatusCode.permissionDenied));
        expect(harness.closes(), isEmpty);
        expect(harness.reads(), isEmpty);
      }),
      isEmpty,
    );
  });
}

/// An SFTP client on a channel whose other end the test plays.
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

  /// The handle the server hands out for the directory.
  final handle = Uint8List.fromList([7, 7, 7]);

  /// Everything the client's channel sent.
  final sent = <SSHMessage>[];

  /// Lets what was asked reach the channel, and what it says reach whoever asked.
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 20));

  /// Every SFTP packet the client sent, in order (each goes out as one piece of data).
  Iterable<Uint8List> packets() => sent.whereType<SSH_Message_Channel_Data>().map((message) {
        final reader = SSHMessageReader(message.data);
        return reader.readBytes(reader.readUint32());
      });

  /// Every time the client asked for the next piece of a directory, in order.
  List<SftpReadDirPacket> reads() => [
        for (final packet in packets())
          if (packet[0] == SftpReadDirPacket.packetType) SftpReadDirPacket.decode(packet),
      ];

  /// Every close the client sent, in order.
  List<SftpClosePacket> closes() => [
        for (final packet in packets())
          if (packet[0] == SftpClosePacket.packetType) SftpClosePacket.decode(packet),
      ];

  /// The server opens the directory the client asked for, and the client asks for its first piece.
  Future<void> opensTheDirectory() async {
    await settle();
    final open = SftpOpenDirPacket.decode(packets().last);
    serverSends(SftpHandlePacket(open.requestId, handle));
    await settle();
  }

  /// The server answers the piece that was asked for last with [filenames].
  void names(List<String> filenames) => serverSends(SftpNamePacket(reads().last.requestId, [
        for (final filename in filenames) SftpName(filename: filename, longname: filename, attr: SftpFileAttrs()),
      ]));

  /// The server says that [read] was past the end of the directory.
  void end(SftpReadDirPacket read) =>
      serverSends(SftpStatusPacket(requestId: read.requestId, code: SftpStatusCode.eof, message: 'End of file'));

  /// The server says yes to [request].
  void answer(SftpRequestPacket request) =>
      serverSends(SftpStatusPacket(requestId: request.requestId, code: SftpStatusCode.ok, message: 'OK'));

  /// The server refuses [request], with [words].
  void refuse(SftpRequestPacket request, String words) =>
      serverSends(SftpStatusPacket(requestId: request.requestId, code: SftpStatusCode.failure, message: words));

  void serverSends(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter()
      ..writeUint32(payload.length)
      ..writeBytes(payload);
    _controller.handleMessage(SSH_Message_Channel_Data(recipientChannel: 1, data: writer.takeBytes()));
  }
}
