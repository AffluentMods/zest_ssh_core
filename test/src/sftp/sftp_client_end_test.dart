// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:io' show SocketException;
import 'dart:typed_data';

import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/sftp/sftp_client.dart';
import 'package:zest_ssh_core/src/sftp/sftp_errors.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:test/test.dart';

/// An SFTP session that ends under its requests. The client listened to its
/// channel for data and for nothing else: when the channel ended (the server
/// closed it, or the connection dropped), a request that waited for its
/// reply waited for ever, and so did every request made after that, and
/// after the client itself had been closed. A session that ended before the
/// server's first packet, or over something that is no SFTP, left the
/// handshake unanswered, on which every request waits first.
///
/// Each of these ends now, with what ended the session.
void main() {
  /// How [asked] has ended by now: 'waiting' while it has not, 'answered',
  /// or what it failed with. (It is listened to from here on, as whoever
  /// asks for something listens for the answer.)
  Object Function() watch(Future<Object?> asked) {
    Object ended = 'waiting';
    unawaited(asked.then<void>((_) => ended = 'answered', onError: (Object e) => ended = e));
    return () => ended;
  }

  final sessionClosed = isA<SftpAbortError>();
  const reset = SocketException('Connection reset by peer');

  test('the server closes the session with requests waiting: each fails, as a session that closed', () async {
    final harness = await _Harness.started();
    final asked = [
      ('open', watch(harness.client.open('/srv/app/app.log'))),
      ('stat', watch(harness.client.stat('/srv/app'))),
      ('listdir', watch(harness.client.listdir('/srv'))),
      ('remove', watch(harness.client.remove('/srv/app/old.log'))),
      ('rename', watch(harness.client.rename('/srv/a', '/srv/b'))),
    ];
    await harness.settle();
    expect(harness.packetsSent, 1 + asked.length, reason: 'each was sent');
    for (final (what, ended) in asked) {
      expect(ended(), 'waiting', reason: what);
    }
    harness.serverCloses();
    await harness.settle();
    for (final (what, ended) in asked) {
      expect(ended(), sessionClosed, reason: what);
    }
  });

  test('the connection ends with requests waiting: each fails with what ended the connection', () async {
    final harness = await _Harness.started();
    final open = watch(harness.client.open('/srv/app/app.log'));
    final stat = watch(harness.client.stat('/srv/app'));
    await harness.settle();
    final ended = SSHSocketError(reset);
    harness.connectionEnds(ended);
    await harness.settle();
    expect(open(), same(ended));
    expect(stat(), same(ended));
  });

  test('a request made after the session ended fails at once, with what ended it, and nothing is sent for it',
      () async {
    final closedByServer = await _Harness.started();
    closedByServer.serverCloses();
    await closedByServer.settle();
    final stat = watch(closedByServer.client.stat('/srv/app'));
    final list = watch(closedByServer.client.listdir('/srv'));
    await closedByServer.settle();
    expect(stat(), sessionClosed);
    expect(list(), sessionClosed);
    expect(closedByServer.packetsSent, 1, reason: 'the handshake, and nothing after the end');

    final dropped = await _Harness.started();
    final ended = SSHSocketError(reset);
    dropped.connectionEnds(ended);
    await dropped.settle();
    final afterDrop = watch(dropped.client.stat('/srv/app'));
    await dropped.settle();
    expect(afterDrop(), same(ended));

    final closedHere = await _Harness.started();
    closedHere.client.close();
    final afterClose = watch(closedHere.client.stat('/srv/app'));
    final open = watch(closedHere.client.open('/srv/app/app.log'));
    await closedHere.settle();
    expect(afterClose(), sessionClosed);
    expect(open(), sessionClosed);
    expect(closedHere.packetsSent, 1);
  });

  test('the session ends before the server said anything: the handshake fails, and what waited on it', () async {
    for (final (what, end, expected) in <(String, void Function(_Harness), Matcher)>[
      ('the server closes it', (h) => h.serverCloses(), sessionClosed),
      ('the connection ends', (h) => h.connectionEnds(SSHSocketError(reset)), isA<SSHSocketError>()),
      ('it is closed from here', (h) => h.client.close(), sessionClosed),
    ]) {
      final harness = _Harness();
      final handshake = watch(harness.client.handshake);
      final stat = watch(harness.client.stat('/srv/app'));
      await harness.settle();
      expect([handshake(), stat()], ['waiting', 'waiting'], reason: what);
      end(harness);
      await harness.settle();
      expect(handshake(), expected, reason: what);
      expect(stat(), expected, reason: what);
      final afterwards = watch(harness.client.stat('/srv/app'));
      await harness.settle();
      expect(afterwards(), expected, reason: '$what, asked afterwards');
    }
  });

  test('a session says whether it is over: however it ended, and not before', () async {
    for (final (what, end) in <(String, void Function(_Harness))>[
      ('the server closes it', (h) => h.serverCloses()),
      ('the connection ends', (h) => h.connectionEnds(SSHSocketError(reset))),
      ('it is closed from here', (h) => h.client.close()),
      ('what the server sends is no SFTP', (h) => h.serverSays(Uint8List.fromList(List.filled(12, 0xff)))),
    ]) {
      final harness = await _Harness.started();
      final stat = watch(harness.client.stat('/srv/app'));
      await harness.settle();
      expect(harness.client.isClosed, isFalse, reason: '$what: open, with a request under way');
      end(harness);
      await harness.settle();
      expect(harness.client.isClosed, isTrue, reason: what);
      expect(stat(), isNot(anyOf('waiting', 'answered')), reason: what);
    }

    // A session that has only begun, and one that ends before the server said anything.
    final early = _Harness();
    await early.settle();
    expect(early.client.isClosed, isFalse);
    early.serverCloses();
    await early.settle();
    expect(early.client.isClosed, isTrue);
  });

  test('a handshake that fails with nobody waiting on it is an error for nobody', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final harness = _Harness();
      await harness.settle();
      harness.serverCloses();
      await harness.settle();
      // Whoever asks later still gets it.
      final handshake = watch(harness.client.handshake);
      await harness.settle();
      expect(handshake(), sessionClosed);
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('what is no SFTP before the server\'s first packet (a shell that prints at sign-in): the handshake fails, '
      'requests fail, what the server goes on sending is not kept, and nothing is thrown at nobody', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final harness = _Harness();
      final handshake = watch(harness.client.handshake);
      final stat = watch(harness.client.stat('/srv/app'));
      await harness.settle();
      // (Read as a packet length, the first four letters are more than a gigabyte.)
      harness.serverSays(Uint8List.fromList('Welcome to web-01\n'.codeUnits));
      await harness.settle();
      final failed = isA<SftpNotSftpError>()
          .having((e) => e.received, 'what came', 'Welcome to web-01')
          .having((e) => e.message, 'message', endsWith('when a session starts): "Welcome to web-01"'))
          .having((e) => '$e', 'as text', startsWith('SftpNotSftpError: The server sent something that is no SFTP'));
      expect(handshake(), failed);
      expect(stat(), failed);
      final afterwards = watch(harness.client.listdir('/srv'));
      await harness.settle();
      expect(afterwards(), failed);
      // The channel is torn down, and what still comes is dropped.
      expect(harness.sent.whereType<SSH_Message_Channel_Close>(), hasLength(1));
      for (var i = 0; i < 4; i++) {
        harness.serverSays(Uint8List(64 * 1024));
      }
      await harness.settle();
      expect(harness.client.bufferedBytes, 0);
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('what came is shown as its first line that says something, cut to eighty characters, with nothing in it '
      'that cannot be shown', () async {
    Future<String> shownOf(List<int> bytes) async {
      final harness = _Harness();
      final handshake = watch(harness.client.handshake);
      await harness.settle();
      harness.serverSays(Uint8List.fromList(bytes));
      await harness.settle();
      expect(handshake(), isA<SftpNotSftpError>());
      return (handshake() as SftpNotSftpError).received;
    }

    expect(await shownOf('\r\n\r\n  Last login: Fri Oct  9 on pts/0\r\nmore\r\n'.codeUnits),
        'Last login: Fri Oct  9 on pts/0');
    expect(await shownOf(('x' * 300).codeUnits), 'x' * 80);
    // A line in colour: what steers the terminal is not shown.
    expect(await shownOf([0x1b, ...'[1;32mweb-01 ready'.codeUnits, 0x1b, ...'[0m'.codeUnits, 0x0a]),
        '[1;32mweb-01 ready[0m');
    // Text in another alphabet, and bytes that are no text at all.
    expect(await shownOf([...[0xd0, 0x9f, 0xd1, 0x80, 0xd0, 0xb8, 0xd0, 0xb2, 0xd0, 0xb5, 0xd1, 0x82], 0x0a]),
        String.fromCharCodes([0x41f, 0x440, 0x438, 0x432, 0x435, 0x442]));
    expect(await shownOf([0xff, 0xfe, 0xfd, 0xfc, 0x80, 0x81]), '');
  });

  test('after the handshake, a length no packet has is a packet that is too long, as it was', () async {
    final harness = await _Harness.started();
    final stat = watch(harness.client.stat('/srv/app'));
    await harness.settle();
    harness.serverSays(Uint8List.fromList('Welcome to web-01\n'.codeUnits));
    await harness.settle();
    expect(stat(), isNot(isA<SftpNotSftpError>()));
    expect(stat(), isA<SftpError>().having((e) => e.message, 'message', contains('exceeds maximum')));
  });

  test('a packet that cannot be read after the handshake: every waiting request fails with that, and nothing is '
      'thrown at nobody', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final harness = await _Harness.started();
      final open = watch(harness.client.open('/srv/app/app.log'));
      final stat = watch(harness.client.stat('/srv/app'));
      await harness.settle();
      // A packet of no bytes at all.
      harness.serverSays(Uint8List(4));
      await harness.settle();
      final failed = isA<SftpError>().having((e) => e.message, 'message', 'Empty SFTP packet');
      expect(open(), failed);
      expect(stat(), failed);
      final afterwards = watch(harness.client.stat('/srv/app'));
      await harness.settle();
      expect(afterwards(), failed);
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('the server\'s version a second time, or another version than this client speaks, ends the session with that',
      () async {
    final twice = await _Harness.started();
    final stat = watch(twice.client.stat('/srv/app'));
    await twice.settle();
    twice.serverSends(SftpVersionPacket(3));
    await twice.settle();
    expect(stat(), isA<SftpError>().having((e) => e.message, 'message', 'A second version packet from the server'));

    final other = _Harness();
    final handshake = watch(other.client.handshake);
    final early = watch(other.client.stat('/srv/app'));
    await other.settle();
    other.serverSends(SftpVersionPacket(4));
    await other.settle();
    final mismatch = isA<SftpError>().having((e) => e.message, 'message', 'Version mismatch: 4');
    expect(handshake(), mismatch);
    expect(early(), mismatch);
  });

  test('closed from here: what waited fails, closing again does nothing, and the server is told', () async {
    final harness = await _Harness.started();
    final open = watch(harness.client.open('/srv/app/app.log'));
    await harness.settle();
    harness.client.close();
    await harness.settle();
    expect(open(), sessionClosed.having((e) => e.message, 'message', 'Connection closed'));
    expect(() => harness.client.close(), returnsNormally);
    expect(harness.sent.whereType<SSH_Message_Channel_EOF>(), hasLength(1), reason: 'the server is told');
    // What the server still sends (the rest of a reply that was on its way)
    // is not taken in: here, the start of a packet of a thousand bytes.
    harness.serverSays(Uint8List.fromList([0, 0, 3, 232, ...List.filled(100, 7)]));
    await harness.settle();
    expect(harness.client.bufferedBytes, 0);
    // The server closing its side afterwards is no second ending.
    harness.serverCloses();
    await harness.settle();
    expect(() => harness.client.close(), returnsNormally);
    final afterwards = watch(harness.client.stat('/srv/app'));
    await harness.settle();
    expect(afterwards(), sessionClosed.having((e) => e.message, 'message', 'Connection closed'));
  });

  test('a file of a session that is over is closed without a failure, and so is one whose close was on its way; '
      'a close the server refuses still fails', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      // The session is over: nothing is left to close, and nothing is sent.
      final over = await _Harness.started();
      final file = await over.opened('/srv/app/app.log');
      over.serverCloses();
      await over.settle();
      final before = over.packetsSent;
      await file.close().timeout(const Duration(seconds: 1));
      expect(file.isClosed, isTrue);
      expect(over.packetsSent, before);

      // The session ends with the close on its way, which nobody waits for.
      final ending = await _Harness.started();
      final other = await ending.opened('/srv/app/app.log');
      final closing = other.close();
      await ending.settle();
      ending.connectionEnds(SSHSocketError(reset));
      await ending.settle();
      await closing.timeout(const Duration(seconds: 1));

      // A close the server refuses is a failure as ever.
      final refusing = await _Harness.started();
      final third = await refusing.opened('/srv/app/app.log');
      final refused = watch(third.close());
      await refusing.settle();
      final close = SftpClosePacket.decode(refusing.lastPacket());
      refusing.serverSends(SftpStatusPacket(requestId: close.requestId, code: 4, message: 'Failure'));
      await refusing.settle();
      expect(refused(), isA<SftpStatusError>().having((e) => e.code, 'code', 4));
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('a download under way when the connection ends fails, with what ended the connection, and the reads it had '
      'asked for ahead are errors for nobody', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final harness = await _Harness.started();
      final download = watch(harness.client.download(
        '/srv/app/big.bin',
        _Sink(),
        length: 64,
        chunkSize: 8,
        maxPendingRequests: 4,
      ));
      await harness.settle();
      final open = SftpOpenPacket.decode(harness.lastPacket());
      harness.serverSends(SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])));
      await harness.settle();
      expect(harness.packetsSent, 1 + 1 + 4, reason: 'the handshake, the open, and four reads asked for ahead');
      expect(download(), 'waiting');
      final ended = SSHSocketError(reset);
      harness.connectionEnds(ended);
      await harness.settle();
      expect(download(), same(ended), reason: 'it waited for ever, for its read and then for the close of its file');
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('a download whose reads the server refuses fails with the first refusal, and the others are errors for nobody',
      () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final harness = await _Harness.started();
      final download = watch(harness.client.download(
        '/srv/app/big.bin',
        _Sink(),
        length: 64,
        chunkSize: 8,
        maxPendingRequests: 4,
      ));
      await harness.settle();
      final open = SftpOpenPacket.decode(harness.lastPacket());
      harness.serverSends(SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])));
      await harness.settle();
      // Every read it asked for is refused, the first with words of its own.
      final reads = harness.packets().skip(2).map(SftpReadPacket.decode).toList();
      expect(reads, hasLength(4));
      for (final (i, read) in reads.indexed) {
        harness.serverSends(SftpStatusPacket(
          requestId: read.requestId,
          code: 4,
          message: i == 0 ? 'Input/output error' : 'Failure',
        ));
      }
      await harness.settle();
      // The file is closed, and the download ends once the server has said so.
      final close = SftpClosePacket.decode(harness.lastPacket());
      harness.serverSends(SftpStatusPacket(requestId: close.requestId, code: 0, message: 'OK'));
      await harness.settle();
      expect(download(), isA<SftpStatusError>().having((e) => e.message, 'message', 'Input/output error'));
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('an upload under way when the connection ends: its writer fails with what ended the connection', () async {
    final uncaught = <Object>[];
    await runZonedGuarded(() async {
      final harness = await _Harness.started();
      final file = await harness.opened('/srv/app/upload.bin');
      final source = StreamController<Uint8List>();
      final writer = file.write(source.stream);
      final done = watch(writer.done);
      source.add(Uint8List(1024));
      await harness.settle();
      expect(SftpWritePacket.decode(harness.lastPacket()).data, hasLength(1024));
      expect(done(), 'waiting');
      final ended = SSHSocketError(reset);
      harness.connectionEnds(ended);
      await harness.settle();
      expect(done(), same(ended));
      await source.close();
      // Its file, closed afterwards and not waited for, as an upload that failed closes it.
      unawaited(file.close());
      await harness.settle();
    }, (error, stack) => uncaught.add(error));
    expect(uncaught, isEmpty);
  });

  test('a reply that comes is still handed to who asked, and a session that goes on is not ended by any of this',
      () async {
    final harness = await _Harness.started();
    final stat = watch(harness.client.stat('/srv/app'));
    await harness.settle();
    final request = SftpStatPacket.decode(harness.lastPacket());
    harness.serverSends(SftpStatusPacket(requestId: request.requestId, code: 2, message: 'No such file'));
    await harness.settle();
    expect(stat(), isA<SftpStatusError>().having((e) => e.code, 'code', 2));
    // The next request goes out as ever.
    final again = watch(harness.client.stat('/srv/other'));
    await harness.settle();
    expect(SftpStatPacket.decode(harness.lastPacket()).path, '/srv/other');
    expect(again(), 'waiting');
    harness.client.close();
    await harness.settle();
    expect(again(), sessionClosed);
  });
}

/// An SFTP client on a channel built by hand, and the server's side of it.
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

  /// How many SFTP packets the client sent (each goes out as one piece of data).
  int get packetsSent => sent.whereType<SSH_Message_Channel_Data>().length;

  /// Lets what was asked reach the channel, and what it says reach whoever asked.
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 20));

  /// The SFTP packet the client sent last.
  Uint8List lastPacket() => packets().last;

  /// Every SFTP packet the client sent, in order.
  Iterable<Uint8List> packets() => sent.whereType<SSH_Message_Channel_Data>().map((message) {
        final reader = SSHMessageReader(message.data);
        return reader.readBytes(reader.readUint32());
      });

  /// A file opened at [path], the server having handed out a handle for it.
  Future<SftpFile> opened(String path) async {
    final file = client.open(path);
    await settle();
    final open = SftpOpenPacket.decode(lastPacket());
    serverSends(SftpHandlePacket(open.requestId, Uint8List.fromList([1, 2, 3])));
    return file;
  }

  void serverSends(SftpPacket packet) {
    final payload = packet.encode();
    final writer = SSHMessageWriter()
      ..writeUint32(payload.length)
      ..writeBytes(payload);
    serverSays(writer.takeBytes());
  }

  /// Bytes from the server, whatever they are.
  void serverSays(Uint8List bytes) =>
      _controller.handleMessage(SSH_Message_Channel_Data(recipientChannel: 1, data: bytes));

  /// The server closes the channel: its SFTP server ended, or was ended.
  void serverCloses() => _controller.handleMessage(SSH_Message_Channel_Close(recipientChannel: 1));

  /// The connection ends, with [error] (what the client does with each of
  /// its channels then).
  void connectionEnds(Object error) => _controller.destroy(error);
}

/// Where a download writes to.
class _Sink implements StreamSink<List<int>> {
  final bytes = BytesBuilder();
  final _done = Completer<void>();

  @override
  void add(List<int> event) => bytes.add(event);

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
