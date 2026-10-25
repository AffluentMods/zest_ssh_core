import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/sftp/sftp_client.dart';
import 'package:zest_ssh_core/src/sftp/sftp_errors.dart';
import 'package:zest_ssh_core/src/sftp/sftp_file_attrs.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/sftp/sftp_status_code.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// How far a file is read where no length is asked for: to the size the
/// server reports for it, or to where it ends if that is sooner; and where
/// the server reports no size, to where it says the file ends. The size is
/// not the file's for everything: Linux reports none for what the kernel
/// makes up as it is read (/proc) and a whole page for a few bytes (/sys),
/// and some servers report none at all. Reading as many bytes as the size
/// said gave an empty file for the first, and an error for the last.
///
/// With a server played here, which holds one file and answers every
/// request in order, as a real one does, and each once the client has sent
/// all it sends in one go, so that what is counted here is what the client
/// asks for and not how fast the machine is. (Against a real server:
/// sftp_file_size_real_server_test.dart.)
void main() {
  Uint8List bytes(String text) => Uint8List.fromList(utf8.encode(text));

  Future<String> readAll(SftpFile file, {int? length, int offset = 0, int chunkSize = 4, int ahead = 64}) async {
    final all = BytesBuilder();
    await for (final piece in file.read(length: length, offset: offset, chunkSize: chunkSize, maxPendingRequests: ahead)) {
      all.add(piece);
    }
    return utf8.decode(all.takeBytes());
  }

  test('a file the server reports no size for is read to its end: one piece is asked for, then more at a time',
      () async {
    final server = _Served(bytes('the kernel wrote this'), sizeSaid: 0);
    addTearDown(server.dispose);
    final file = await server.client.open('/proc/version');
    expect(await readAll(file), 'the kernel wrote this');
    // Nothing says how much there is: one piece first, and for each that came back whole twice as many may be
    // on their way (one, then two, then four).
    expect(server.arrivedWhenAnswered.take(3), [1, 3, 6]);
    expect(server.asked.first, (0, 4));
    // All at once, as readBytes gives it, and as a download writes it.
    expect(utf8.decode(await file.readBytes()), 'the kernel wrote this');
    final sink = _Collected();
    expect(await file.downloadTo(sink), 21);
    expect(utf8.decode(sink.bytes.takeBytes()), 'the kernel wrote this');
  });

  test('a file whose size the server reports is read ahead to that size, and no further', () async {
    final server = _Served(bytes('ABCDEFGHIJKL'));
    addTearDown(server.dispose);
    final file = await server.client.open('/tmp/file');
    var progress = <int>[];
    final all = BytesBuilder();
    await for (final piece in file.read(chunkSize: 4, onProgress: progress.add)) {
      all.add(piece);
    }
    expect(utf8.decode(all.takeBytes()), 'ABCDEFGHIJKL');
    expect(progress, [4, 8, 12]);
    // The three pieces of the size it reported were all on their way before the first answer, and nothing
    // was asked for past it.
    expect(server.asked, [(0, 4), (4, 4), (8, 4)]);
    expect(server.arrivedWhenAnswered.first, 3);
  });

  test('a file of forty pieces: all of them are on their way before the first answer, and none past its size',
      () async {
    // (A channel sends eight messages and then gives way to the event loop:
    // what is asked for in one go reaches the server in five.)
    final content = bytes(List.generate(40, (i) => 'p${i.toString().padLeft(2, '0')}.').join());
    final server = _Served(content);
    addTearDown(server.dispose);
    final file = await server.client.open('/tmp/file');
    expect(await readAll(file), utf8.decode(content));
    expect(server.asked, [for (var i = 0; i < 40; i++) (i * 4, 4)]);
    expect(server.arrivedWhenAnswered, List.filled(40, 40));
  });

  // What a client asks for in one go can reach the server a turn of the
  // event loop apart: a channel that sends gives way to the event loop when
  // eight milliseconds have gone by since it last did, by the clock. On a
  // machine that has other things to do that is between two requests of
  // one go. The counts above are of what is asked for, not of when it
  // arrives, so they are the same there. (They were one fewer now and then,
  // when all the package's tests ran at once: the played server answered a
  // request in the turn after it came.)
  group('on a machine that has other things to do, what is asked for in one go is counted as one go', () {
    const busy = Duration(milliseconds: 10);

    test('a file the server reports no size for: one piece, then two, then four on their way', () async {
      final server = _Served(bytes('the kernel wrote this'), sizeSaid: 0, busyFor: busy);
      addTearDown(server.dispose);
      final file = await server.client.open('/proc/version');
      expect(await readAll(file), 'the kernel wrote this');
      expect(server.arrivedWhenAnswered.take(3), [1, 3, 6]);
      expect(server.asked.first, (0, 4));
    });

    test('a file whose size the server reports: all its pieces on their way before the first answer', () async {
      final server = _Served(bytes('ABCDEFGHIJKL'), busyFor: busy);
      addTearDown(server.dispose);
      final file = await server.client.open('/tmp/file');
      expect(await readAll(file), 'ABCDEFGHIJKL');
      expect(server.asked, [(0, 4), (4, 4), (8, 4)]);
      expect(server.arrivedWhenAnswered.first, 3);
    });

    test('a read that is asked for with its length when nothing is under way: all its pieces on their way before '
        'the first answer, a second time as the first', () async {
      final server = _Served(bytes('ABCDEFGHIJKL'), busyFor: busy);
      addTearDown(server.dispose);
      final file = await server.client.open('/tmp/file');
      // Some time after the file was opened: the server has nothing left to answer.
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(await readAll(file, length: 12), 'ABCDEFGHIJKL');
      expect(server.arrivedWhenAnswered, [3, 3, 3]);
      expect(server.sizeAsked, 0, reason: 'a length that is given is not asked of the server');
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(await readAll(file, length: 8, offset: 4), 'EFGHIJKL');
      expect(server.arrivedWhenAnswered.skip(3), [5, 5]);
    });
  });

  test('a file that is being written is read as far as it went when its size was reported, and is not followed',
      () async {
    final server = _Served(bytes('ABCDEFGH'));
    addTearDown(server.dispose);
    // Six more bytes are written while its second piece is read, and more would follow.
    server.beforeRead = (offset, length) {
      if (offset == 4) server.content = bytes('ABCDEFGHijklmn');
    };
    final file = await server.client.open('/var/log/app.log');
    var counted = 0;
    final all = BytesBuilder();
    await for (final piece in file.read(chunkSize: 4, onProgress: (total) => counted = total)) {
      all.add(piece);
    }
    expect(utf8.decode(all.takeBytes()), 'ABCDEFGH');
    expect(counted, 8);
    expect(server.asked, [(0, 4), (4, 4)], reason: 'nothing is asked for past the size it had');
  });

  test('a file that is shorter than the size the server reports is read to its end, and no further', () async {
    // A page for a number and a line end, as Linux reports under /sys.
    final server = _Served(bytes('65536\n'), sizeSaid: 4096);
    addTearDown(server.dispose);
    final file = await server.client.open('/sys/class/net/lo/mtu');
    expect(await readAll(file), '65536\n');
    expect(utf8.decode(await file.readBytes()), '65536\n');
  });

  test('a server that reports no size at all: the file is read to its end', () async {
    final server = _Served(bytes('ABCDEFGHIJ'), sizeSaid: null);
    addTearDown(server.dispose);
    final file = await server.client.open('/tmp/file');
    expect(await readAll(file), 'ABCDEFGHIJ');
  });

  test('nothing is taken from beyond a piece that came back short', () async {
    // A file that was cut short and written again while it was being read: the piece at 4 ends at 6, and the
    // one at 8, asked for ahead, has bytes all the same.
    final server = _Served(bytes('ABCDEF'), sizeSaid: 12);
    addTearDown(server.dispose);
    server.answer = (offset, length) => offset == 8 ? bytes('IJKL') : null;
    final file = await server.client.open('/tmp/file');
    expect(await readAll(file), 'ABCDEF', reason: 'what follows a gap is not the file');
    expect(await readAll(file, length: 12), 'ABCDEF', reason: 'with a length asked for as well');
  });

  test('a server that sends more than it was asked for is refused', () async {
    final server = _Served(bytes('ABCDEFGH'));
    addTearDown(server.dispose);
    server.answer = (offset, length) => offset == 0 ? bytes('ABCDEF') : null;
    final file = await server.client.open('/tmp/file');
    await expectLater(
      readAll(file, length: 8),
      throwsA(isA<SftpError>().having((e) => e.message, 'message', 'The server sent 6 bytes where 4 were asked for')),
    );
    await expectLater(readAll(file), throwsA(isA<SftpError>()));
  });

  test('a number of bytes that is asked for is read, and no more; none is none; past the end there is nothing',
      () async {
    final server = _Served(bytes('ABCDEFGHIJKL'));
    addTearDown(server.dispose);
    final file = await server.client.open('/tmp/file');
    expect(await readAll(file, length: 6), 'ABCDEF');
    expect(server.asked, [(0, 4), (4, 2)], reason: 'nothing is asked for past what was asked for');
    expect(server.sizeAsked, 0, reason: 'nor is the size');
    expect(await readAll(file, length: 5, offset: 3), 'DEFGH');
    // More than there is: what there is.
    expect(await readAll(file, length: 100, offset: 8), 'IJKL');

    server.asked.clear();
    expect(await readAll(file, length: 0), '');
    expect(server.asked, isEmpty);

    // From where the file ends, and from beyond: nothing, and no error.
    expect(await readAll(file, offset: 12), '');
    expect(await readAll(file, offset: 500), '');
    expect(await file.readBytes(offset: 500), isEmpty);

    await expectLater(readAll(file, length: -1), throwsA(isA<SftpError>()));
  });

  test('a server that gives fewer bytes at a time than it is asked for: the file is whole', () async {
    final server = _Served(bytes('ABCDEFGHIJ'), mostPerRead: 3);
    addTearDown(server.dispose);
    final file = await server.client.open('/tmp/file');
    expect(await readAll(file), 'ABCDEFGHIJ');
    final sized = _Served(bytes('ABCDEFGHIJ'), sizeSaid: 0, mostPerRead: 3);
    addTearDown(sized.dispose);
    expect(await readAll(await sized.client.open('/proc/file')), 'ABCDEFGHIJ');
  });

  test('a file of no bytes is a file of no bytes: one question, and no piece', () async {
    final server = _Served(Uint8List(0));
    addTearDown(server.dispose);
    final file = await server.client.open('/tmp/empty');
    expect(await readAll(file), '');
    expect(server.asked, [(0, 4)]);
    expect(await file.readBytes(), isEmpty);
  });

  test('a read the server refuses fails with what it said, wherever in the file', () async {
    final server = _Served(bytes('ABCDEFGHIJKL'));
    addTearDown(server.dispose);
    server.refuseAt = 8;
    final file = await server.client.open('/tmp/file');
    final got = <String>[];
    Object? failure;
    try {
      await for (final piece in file.read(chunkSize: 4)) {
        got.add(utf8.decode(piece));
      }
    } catch (e) {
      failure = e;
    }
    expect(got, ['ABCD', 'EFGH']);
    expect(failure, isA<SftpStatusError>().having((e) => e.code, 'code', SftpStatusCode.permissionDenied));
  });
}

/// A server that holds one file ([content]) and answers every request of a
/// client in order, each once the client has sent all it sends in one go.
class _Served {
  _Served(this.content, {this.sizeSaid = _itsOwn, this.mostPerRead, this.busyFor = Duration.zero}) {
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
  }

  static const _itsOwn = -1;

  /// What the file holds. A test may change it while it is read.
  Uint8List content;

  /// The size the server reports for the file: its own, another, or none.
  final int? sizeSaid;

  /// The most bytes the server gives for one read, where it gives fewer
  /// than it is asked for.
  final int? mostPerRead;

  /// How long every message of the client's keeps the machine from
  /// anything else, as on one that has other things to do.
  final Duration busyFor;

  /// Called before a read is answered.
  void Function(int offset, int length)? beforeRead;

  /// What the server answers a read with, where a test says so: bytes, or
  /// null for what the file holds there.
  Uint8List? Function(int offset, int length)? answer;

  /// Where the server refuses to read.
  int? refuseAt;

  /// Every read that was asked for, in order: where, and how much.
  final asked = <(int, int)>[];

  /// For each read, how many had arrived by the time it was answered.
  final arrivedWhenAnswered = <int>[];

  /// How often the size was asked for.
  var sizeAsked = 0;

  late final SSHChannelController _controller;
  late final SftpClient client;
  var _disposed = false;

  /// What has arrived and is not answered yet, in order.
  final _waiting = <Uint8List>[];

  /// How many requests have arrived, of any kind.
  var _arrived = 0;

  /// Whether the requests that wait are being answered.
  var _answering = false;

  void _fromClient(SSHMessage message) {
    if (message is! SSH_Message_Channel_Data) return;
    for (final kept = Stopwatch()..start(); kept.elapsed < busyFor;) {}
    final reader = SSHMessageReader(message.data);
    while (!reader.isDone) {
      final payload = reader.readBytes(reader.readUint32());
      if (payload[0] == SftpReadPacket.packetType) {
        final read = SftpReadPacket.decode(payload);
        asked.add((read.offset, read.length));
      }
      _waiting.add(payload);
      _arrived++;
    }
    if (!_answering) {
      _answering = true;
      _answerWhenQuiet(_arrived, false);
    }
  }

  /// Answers the request that has waited longest once the client has sent
  /// all it sends in one go (which reaches this side a piece at a time):
  /// once a whole turn of the event loop has gone by in which nothing more
  /// arrived. The turn after a request came is too soon: a channel that
  /// sends gives way to the event loop between two messages when it has
  /// been at it for a while, by the clock, so what a client sends in one go
  /// can arrive a turn apart. Then the next request, when the client has
  /// done what it does with the answer.
  void _answerWhenQuiet(int arrived, bool quiet) => Timer.run(() {
        if (_disposed) return;
        if (_arrived != arrived) return _answerWhenQuiet(_arrived, false);
        if (!quiet) return _answerWhenQuiet(arrived, true);
        if (_waiting.isEmpty) {
          _answering = false;
          return;
        }
        _answer(_waiting.removeAt(0));
        _answerWhenQuiet(_arrived, false);
      });

  void _answer(Uint8List payload) {
    if (_disposed) return;
    switch (payload[0]) {
      case SftpInitPacket.packetType:
        _send(SftpVersionPacket(3));
      case SftpOpenPacket.packetType:
        _send(SftpHandlePacket(SftpOpenPacket.decode(payload).requestId, Uint8List.fromList([1, 2, 3])));
      case SftpClosePacket.packetType:
        _status(SftpClosePacket.decode(payload).requestId, SftpStatusCode.ok);
      case SftpFStatPacket.packetType:
        sizeAsked++;
        _send(SftpAttrsPacket(
          SftpFStatPacket.decode(payload).requestId,
          SftpFileAttrs(
            size: sizeSaid == _itsOwn ? content.length : sizeSaid,
            mode: const SftpFileMode.value(1 << 15),
          ),
        ));
      case SftpReadPacket.packetType:
        final read = SftpReadPacket.decode(payload);
        beforeRead?.call(read.offset, read.length);
        arrivedWhenAnswered.add(asked.length);
        if (refuseAt == read.offset) {
          _status(read.requestId, SftpStatusCode.permissionDenied);
          return;
        }
        final scripted = answer?.call(read.offset, read.length);
        if (scripted != null) {
          _send(SftpDataPacket(read.requestId, scripted));
          return;
        }
        if (read.offset >= content.length) {
          _status(read.requestId, SftpStatusCode.eof);
          return;
        }
        var end = read.offset + read.length;
        if (mostPerRead != null && end > read.offset + mostPerRead!) end = read.offset + mostPerRead!;
        if (end > content.length) end = content.length;
        _send(SftpDataPacket(read.requestId, Uint8List.sublistView(content, read.offset, end)));
      default:
        throw StateError('a request this server does not know: ${payload[0]}');
    }
  }

  void _status(int requestId, int code) =>
      _send(SftpStatusPacket(requestId: requestId, code: code, message: code == SftpStatusCode.ok ? 'ok' : 'no'));

  void _send(SftpPacket packet) {
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

/// Where a download is written, for a test to look at.
class _Collected implements StreamSink<List<int>> {
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
