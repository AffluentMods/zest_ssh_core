import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/message/msg_kex_dh.dart';
import 'package:zest_ssh_core/src/ssh_packet.dart';

import 'played_server.dart' show PlayedLine;

/// A server that offers a group exchange and no other key exchange, played
/// to a client as far as the group it names: the versions, the proposals,
/// the client's request for a group, and a group of the test's choosing.
/// What the client does with that group is what is asked about: it goes on
/// with a public value of its own, or it ends the connection.
///
/// All of it is in the clear, since no keys are in force before the
/// exchange has ended. For a whole group exchange with its answer, see
/// ssh_transport_kex_reply_test.dart. Nothing here is of a test framework:
/// what goes wrong is thrown as a [StateError].
class PlayedGroupExchange {
  /// A server with nobody connected to it yet, which names [kex] as the
  /// only key exchange it has. It is played to whoever is made on its
  /// [socket], or to whoever is on [line] (a program that dials for itself:
  /// played_listener.dart).
  PlayedGroupExchange({this.kex = 'diffie-hellman-group-exchange-sha256', PlayedLine? line})
      : _line = line ?? _GroupWire();

  /// The one key exchange the server offers.
  final String kex;

  final PlayedLine _line;

  /// What the client wrote and was not read as packets yet, and its packets
  /// that nobody has asked for yet.
  final _raw = BytesBuilder(copy: true);
  final _unread = <Uint8List>[];
  var _versionRead = false;

  /// The server's end of a connection, for a client to be made on.
  SSHSocket get socket {
    final line = _line;
    if (line is! _GroupWire) throw StateError('this played server is on a line of the test\'s own');
    return line;
  }

  static const version = 'SSH-2.0-OpenSSH_9.6';

  /// How long the client is given to do something a test waits for.
  static const patience = Duration(seconds: 10);

  /// Whether the client has ended the connection.
  bool get clientGone => _line.clientGone;

  /// Sends the server's version and proposal, and reads which groups the
  /// client asks for: the shortest and the longest it takes, and the length
  /// it would like.
  Future<({int shortest, int preferred, int longest})> request() async {
    _line.feed([...latin1.encode('$version\r\n'), ...SSHPacket.pack(_proposal(), align: 8)]);
    final asked = await _next(SSH_Message_KexDH_GexRequest.messageId);
    if (asked == null) throw StateError('the client ended the connection before it asked for a group');
    final request = SSH_Message_KexDH_GexRequest.decode(asked);
    return (shortest: request.minN, preferred: request.preferredN, longest: request.maxN);
  }

  /// Names the group of the modulus [p] and the generator [g], and says
  /// what the client did with it: its public value where it went on with
  /// the exchange, null where it ended the connection.
  Future<BigInt?> name(BigInt p, BigInt g) async {
    _line.feed(SSHPacket.pack(SSH_Message_KexDH_GexGroup(p: p, g: g).encode(), align: 8));
    final init = await _next(SSH_Message_KexDH_GexInit.messageId);
    return init == null ? null : SSH_Message_KexDH_GexInit.decode(init).e;
  }

  /// Ends the connection from the server's side: for a client that went on
  /// with the exchange, where the test has seen all it asks about.
  void hangUp() => _line.end();

  Uint8List _proposal() => SSH_Message_KexInit(
        kexAlgorithms: [kex, 'kex-strict-s-v00@openssh.com'],
        serverHostKeyAlgorithms: const ['ssh-ed25519'],
        encryptionClientToServer: const ['aes256-ctr'],
        encryptionServerToClient: const ['aes256-ctr'],
        macClientToServer: const ['hmac-sha2-256'],
        macServerToClient: const ['hmac-sha2-256'],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

  /// The next packet of the client's with the message number [id], or null
  /// once the client has ended the connection without one.
  Future<Uint8List?> _next(int id) async {
    final clock = Stopwatch()..start();
    while (true) {
      _read();
      while (_unread.isNotEmpty) {
        final packet = _unread.removeAt(0);
        if (packet.isNotEmpty && packet[0] == id) return packet;
      }
      if (_line.clientGone) {
        // What it wrote last may have come with the news that it has gone.
        _read();
        if (_unread.isEmpty) return null;
        continue;
      }
      if (clock.elapsed > patience) throw StateError('the client did not send message $id');
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
  }

  /// Takes what the client wrote since this was last asked: its version
  /// line first, then its packets, each one's payload. All of them are in
  /// the clear, and one that has not come whole yet waits for the rest.
  void _read() {
    _raw.add(_line.takeOutput());
    var bytes = _raw.toBytes();
    var at = 0;
    if (!_versionRead) {
      final end = latin1.decode(bytes).indexOf('\r\n');
      if (end < 0) return;
      _versionRead = true;
      at = end + 2;
    }
    while (at + 5 <= bytes.length) {
      final length = ByteData.sublistView(bytes, at).getUint32(0);
      if (at + 4 + length > bytes.length) break;
      final padding = bytes[at + 4];
      _unread.add(Uint8List.fromList(Uint8List.sublistView(bytes, at + 5, at + 4 + length - padding)));
      at += 4 + length;
    }
    bytes = Uint8List.sublistView(bytes, at);
    _raw.clear();
    _raw.add(bytes);
  }
}

/// The connection as a played group exchange holds it where the client is
/// made on its socket.
class _GroupWire implements SSHSocket, PlayedLine {
  final _incoming = StreamController<Uint8List>();
  final _done = Completer<void>();
  final _written = BytesBuilder(copy: true);

  @override
  bool get clientGone => _done.isCompleted;

  /// Bytes from the server. Once the client has ended the connection they
  /// go nowhere, as they would.
  @override
  void feed(List<int> bytes) {
    if (!_incoming.isClosed) _incoming.add(Uint8List.fromList(bytes));
  }

  @override
  Uint8List takeOutput() => _written.takeBytes();

  @override
  void end() => unawaited(_incoming.close());

  @override
  bool get wholePackets => true;

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _GroupSink(_written);

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

class _GroupSink implements StreamSink<List<int>> {
  _GroupSink(this._into);

  final BytesBuilder _into;

  @override
  void add(List<int> data) => _into.add(data);

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      _into.add(chunk);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done => Future.value();
}
