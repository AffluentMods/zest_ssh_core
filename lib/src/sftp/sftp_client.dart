// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import 'package:zest_ssh_core/src/sftp/sftp_errors.dart';
import 'package:zest_ssh_core/src/sftp/sftp_file_attrs.dart';
import 'package:zest_ssh_core/src/sftp/sftp_file_open_mode.dart';
import 'package:zest_ssh_core/src/sftp/sftp_name.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet_ext.dart';
import 'package:zest_ssh_core/src/sftp/sftp_request_id.dart';
import 'package:zest_ssh_core/src/sftp/sftp_statvfs.dart';
import 'package:zest_ssh_core/src/sftp/sftp_stream_io.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_transport.dart';
import 'package:zest_ssh_core/src/utils/chunk_buffer.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

const _kVersion = 3;
const _kReadChunkSize = 16 * 1024;
const _kReadMaxPendingRequests = 64;
const _kDownloadChunkSize = 64 * 1024;
const _kDownloadMaxPendingRequests = 128;

/// Upper bound on a single server-advertised SFTP packet length. Without it a
/// hostile or compromised server can claim a multi-gigabyte packet and stream
/// junk, and the client reassembles it in memory until it runs out (the
/// application-level byte caps all sit downstream of this reassembly buffer).
/// 64 MB is far above any legitimate SFTP packet, DATA is bounded by the 64 KB
/// download chunk and a NAME/readdir batch is far smaller, while still keeping
/// the buffer bounded. A packet over this cap tears the session down cleanly.
const _kMaxPacketLength = 64 * 1024 * 1024;

class SftpClient {
  final SSHChannel _channel;

  final SSHPrintHandler? printDebug;

  final SSHPrintHandler? printTrace;

  SftpClient(this._channel, {this.printDebug, this.printTrace}) {
    // A handshake that fails with nobody waiting on it yet is no error
    // thrown at nobody: whoever asks for it, or makes a request, gets it.
    _handshake.future.ignore();
    _startHandshake();
    _channel.stream.listen(_handleData, onDone: _handleChannelDone);
  }

  final _buffer = ChunkBuffer();

  /// How many bytes from the server are held, not yet read as packets. For
  /// tests.
  @visibleForTesting
  int get bufferedBytes => _buffer.length;

  final _handshake = Completer<SftpHandsake>();

  /// What ended the session; null while it is open. Every request waiting
  /// for a reply failed with it, the handshake did where it was not done,
  /// and every request made afterwards fails with it at once.
  Object? _ended;

  /// Whether the session is over: closed from here ([close]), closed by the
  /// server, or gone with its connection. Every request then fails with what
  /// ended it; a session that is over is not opened again, and whoever holds
  /// it opens another.
  bool get isClosed => _ended != null;

  final _requestId = SftpRequestId();

  final _replyWaiters = <int, Completer<SftpResponsePacket>>{};

  /// The handshake information received from the server.
  Future<SftpHandsake> get handshake => _handshake.future;

  /// Gets the attributes of the file at [path].
  Future<SftpFileAttrs> stat(String path, {bool followLink = true}) async {
    final reply = followLink ? await _sendStat(path) : await _sendLStat(path);
    if (reply is SftpAttrsPacket) return reply.attrs;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Sets the attributes of the file at [path].
  Future<void> setStat(String path, SftpFileAttrs attrs) async {
    final reply = await _sendSetStat(path, attrs);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Opens a file for reading or/and writing.
  ///
  /// [attrs] are the attributes a file that is made by this is made with
  /// (its permissions, which the server's umask may narrow): a file that
  /// only its owner may read is that from the moment it is there, and not
  /// once its permissions are set afterwards.
  Future<SftpFile> open(
    String path, {
    SftpFileOpenMode mode = SftpFileOpenMode.read,
    SftpFileAttrs? attrs,
  }) async {
    final reply = await _sendOpen(path, mode, attrs ?? SftpFileAttrs());
    if (reply is SftpHandlePacket) return SftpFile(this, reply.handle);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Downloads a remote file from [path] into [destination].
  ///
  /// This is a convenience API built on top of [SftpFile.read] and keeps the
  /// existing stream-based APIs fully compatible.
  ///
  /// Returns the total number of bytes written.
  Future<int> download(
    String path,
    StreamSink<List<int>> destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
    bool closeDestination = false,
  }) async {
    final file = await open(path, mode: SftpFileOpenMode.read);
    try {
      return await file.downloadTo(
        destination,
        length: length,
        offset: offset,
        onProgress: onProgress,
        chunkSize: chunkSize,
        maxPendingRequests: maxPendingRequests,
        closeDestination: closeDestination,
      );
    } finally {
      await file.close();
    }
  }

  /// Reads the items of a directory. Returns an [Stream] of [SftpName] chunks.
  /// Use [listdir] instead of this unless the directory contains a large number
  /// of items.
  ///
  /// The directory is closed on the server however the listing ends. Read to
  /// its end, the stream is done when the server has answered the close, and
  /// fails where the server refuses it. A listing that fails, and one that
  /// whoever listens gives up, tells the server to let go of the directory
  /// as well, and what the server says to that is nobody's: the listing has
  /// failed with what it failed with, or is over for whoever gave it up.
  /// (Until this, only a listing that was read to its end closed its
  /// directory: every other left it open for as long as the session lasted,
  /// and a server lets a session hold only so many.)
  Stream<List<SftpName>> readdir(String path) async* {
    final dir = await _opendir(path);
    var read = false;
    try {
      while (true) {
        final names = await _readdir(dir);
        if (names == null) break;
        yield names;
      }
      read = true;
    } finally {
      if (!read) _close(dir).ignore();
    }
    await _close(dir);
  }

  /// List the items of a directory. This is a convenience method wrapping
  /// [readdir].
  Future<List<SftpName>> listdir(String path) async {
    final result = <SftpName>[];
    await for (final names in readdir(path)) {
      result.addAll(names);
    }
    return result;
  }

  /// Remove a file whose name is [filename]. This can only be used to remove
  /// files. Use [rmdir] to remove a directory.
  Future<void> remove(String filename) async {
    final reply = await _sendRemove(filename);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Makes a directory at the given [path].
  Future<void> mkdir(String path, [SftpFileAttrs? attrs]) async {
    final reply = await _sendMakeDir(path, attrs ?? SftpFileAttrs());
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Removes a directory whose name is [dirname]. This can only be used to
  /// remove directories. Use [remove] to remove a file.
  /// This will fail if the directory is not empty.
  Future<void> rmdir(String dirname) async {
    final reply = await _sendRemoveDir(dirname);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Returns the absolute path of [path].
  Future<String> absolute(String path) async {
    final reply = await _sendRealPath(path);
    if (reply is SftpNamePacket) return reply.names.first.filename;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Renames a file or directory from [oldPath] to [newPath].
  Future<void> rename(String oldPath, String newPath) async {
    final reply = await _sendRename(oldPath, newPath);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Whether the server can put a file in the place of another in one step
  /// ([posixRename]).
  Future<bool> get canPosixRename async => (await handshake).extensions['posix-rename@openssh.com'] == '1';

  /// Renames [oldPath] to [newPath] as rename(2) does: where there is a file
  /// under [newPath] already it is replaced, in one step, so that there is
  /// no moment with no file under that name. ([rename] is refused for a name
  /// that is taken by most servers, OpenSSH among them.)
  ///
  /// **Note**: This is an extension to the SFTP protocol, supported by most
  /// openssh servers. A [SftpExtensionError] is thrown if the server does not
  /// support this extension ([canPosixRename] says beforehand).
  Future<void> posixRename(String oldPath, String newPath) async {
    await _checkExtension('posix-rename@openssh.com', '1');
    final reply = await _sendExtended(SftpPosixRenameRequest(oldPath: oldPath, newPath: newPath));
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Reads the target of a symbolic link.
  Future<String> readlink(String path) async {
    final reply = await _sendReadLink(path);
    if (reply is SftpNamePacket) return reply.names.first.filename;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Creates a symbolic link at [targetPath] that points to [linkPath].
  Future<void> link(String linkPath, String targetPath) async {
    final reply = await _sendSymlink(linkPath, targetPath);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Gets the information about a mounted filesystem. [path] is the pathname of
  /// any file within the mounted filesystem.
  ///
  /// **Note**: This is an extension to the SFTP protocol, supported by most
  /// openssh servers. A [SftpExtensionError] is thrown if the server does not
  /// support this extension.
  ///
  /// See also:
  ///
  /// - [SftpFile.statvfs] which requires an open [SftpFile] instance instead of
  ///   a path.
  Future<SftpStatVfs> statvfs(String path) async {
    await _checkExtension('statvfs@openssh.com', '2');
    final payload = SftpStatVfsRequest(path: path);
    final reply = await _sendExtended(payload);
    if (reply is SftpStatusPacket) throw SftpStatusError.fromStatus(reply);
    if (reply is! SftpExtendedReplyPacket) throw SftpError('Unexpected reply');
    final stat = SftpStatVfsReply.decode(reply.payload);
    return SftpStatVfs.fromReply(stat);
  }

  /// Close the sftp session.
  ///
  /// Also tears down the underlying channel: without that, every
  /// open/close cycle of the SFTP subsystem left a channel open on the
  /// server for the lifetime of the SSH connection, and any file or
  /// directory handles opened through it were never released. Closing is
  /// idempotent so a double close (an explicit `close()` after the peer
  /// already went away) is a no-op rather than a "Future already
  /// completed" crash.
  void close() {
    _end(SftpAbortError("Connection closed"));
    // Fire-and-forget: the caller's close() is synchronous by contract and
    // a failure here only means the channel was already gone.
    _channel.close().catchError((_) {});
  }

  /// The session is over, with [error]: for whoever waits for a reply, for
  /// the handshake where the server had not answered it yet (every request
  /// waits on that first), and for every request made from now on. Without
  /// this each of them waited for ever. The first ending stands.
  void _end(Object error, [StackTrace? stackTrace]) {
    if (_ended != null) return;
    _ended = error;
    stackTrace ??= StackTrace.current;
    if (!_handshake.isCompleted) {
      _handshake.completeError(error, stackTrace);
    }
    final waiters = _replyWaiters.values.toList();
    _replyWaiters.clear();
    for (final waiter in waiters) {
      waiter.completeError(error, stackTrace);
    }
    // What the server sent and was not read yet is nobody's any more.
    _buffer.clear();
  }

  /// The channel ended under the session: the connection ended (then with
  /// what it ended with), or the server closed the channel, its SFTP server
  /// having ended.
  void _handleChannelDone() {
    _end(_channel.endedBecause ?? SftpAbortError('The server closed the SFTP session'));
  }

  /// What the server sent cannot be SFTP, or cannot be read: the session is
  /// over, and the channel is torn down, so that a server that goes on
  /// sending is not listened to.
  void _closeError(Object error, [StackTrace? stackTrace]) {
    _end(error, stackTrace);
    _channel.destroy();
  }

  void _startHandshake() {
    _sendPacket(SftpInitPacket(_kVersion));
  }

  /// Open a directory and return the handle.
  Future<Uint8List> _opendir(String path) async {
    final reply = await _sendOpenDir(path);
    if (reply is SftpHandlePacket) return reply.handle;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  /// Reads the next bunch of entries from the directory. Returns `null` when
  /// there are no more entries.
  Future<List<SftpName>?> _readdir(Uint8List handle) async {
    final reply = await _sendReadDir(handle);
    if (reply is SftpNamePacket) return reply.names;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
    return null;
  }

  Future<void> _close(Uint8List handle) async {
    final reply = await _sendClose(handle);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  void _sendPacket(SftpPacket packet) {
    // Nothing is sent for a session that is over, and whoever asked is told
    // what ended it (every request comes through here before it waits).
    final ended = _ended;
    if (ended != null) throw ended;
    printTrace?.call('-> $_channel: $packet');
    final data = packet.encode();
    final writer = SSHMessageWriter();
    writer.writeUint32(data.length);
    writer.writeBytes(data);
    _channel.addData(writer.takeBytes());
  }

  Future<SftpResponsePacket> _sendOpen(
    String path,
    SftpFileOpenMode mode,
    SftpFileAttrs attrs,
  ) async {
    await handshake;
    final request = SftpOpenPacket(_requestId.next, path, mode.flag, attrs);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendClose(Uint8List handle) async {
    await handshake;
    final request = SftpClosePacket(_requestId.next, handle);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendRead(
    Uint8List handle,
    int offset,
    int length,
  ) async {
    await handshake;
    final request = SftpReadPacket(
      requestId: _requestId.next,
      handle: handle,
      offset: offset,
      length: length,
    );
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendWrite(
    Uint8List handle,
    int offset,
    Uint8List data,
  ) async {
    await handshake;
    final request = SftpWritePacket(
      requestId: _requestId.next,
      handle: handle,
      offset: offset,
      data: data,
    );
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendLStat(String path) async {
    await handshake;
    final request = SftpLStatPacket(_requestId.next, path);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendFStat(Uint8List handle) async {
    await handshake;
    final request = SftpFStatPacket(_requestId.next, handle);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendSetStat(
    String path,
    SftpFileAttrs attrs,
  ) async {
    await handshake;
    final request = SftpSetStatPacket(_requestId.next, path, attrs);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendFSetStat(
    Uint8List handle,
    SftpFileAttrs attrs,
  ) async {
    await handshake;
    final request = SftpFSetStatPacket(_requestId.next, handle, attrs);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendOpenDir(String path) async {
    await handshake;
    final request = SftpOpenDirPacket(_requestId.next, path);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendReadDir(Uint8List handle) async {
    await handshake;
    final request = SftpReadDirPacket(_requestId.next, handle);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendRemove(String filename) async {
    await handshake;
    final request = SftpRemovePacket(_requestId.next, filename);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendMakeDir(
    String path,
    SftpFileAttrs attrs,
  ) async {
    await handshake;
    final request = SftpMkdirPacket(_requestId.next, path, attrs);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendRemoveDir(String path) async {
    await handshake;
    final request = SftpRmdirPacket(_requestId.next, path);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendRealPath(String path) async {
    await handshake;
    final request = SftpRealpathPacket(_requestId.next, path);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendStat(String path) async {
    await handshake;
    final request = SftpStatPacket(_requestId.next, path);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendRename(
    String oldPath,
    String newPath,
  ) async {
    await handshake;
    final request = SftpRenamePacket(_requestId.next, oldPath, newPath);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendReadLink(String path) async {
    await handshake;
    final request = SftpReadlinkPacket(_requestId.next, path);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendSymlink(
    String linkPath,
    String targetPath,
  ) async {
    await handshake;
    final request = SftpSymlinkPacket(_requestId.next, linkPath, targetPath);
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  Future<SftpResponsePacket> _sendExtended(SftpExtendedRequest payload) async {
    await handshake;
    final request = SftpExtendedPacket(_requestId.next, payload.encode());
    _sendPacket(request);
    return await _waitReply(request.requestId);
  }

  void _dispatchReply(SftpResponsePacket packet) {
    final completer = _replyWaiters.remove(packet.requestId);
    completer?.complete(packet);
  }

  Future<SftpResponsePacket> _waitReply(int requestId) {
    final completer = Completer<SftpResponsePacket>();
    _replyWaiters[requestId] = completer;
    return completer.future;
  }

  Future<void> _checkExtension(String name, String version) async {
    final handshake = await this.handshake;
    final extensionVersion = handshake.extensions[name];
    if (extensionVersion == null) {
      throw SftpExtensionUnsupportedError(name);
    }
    if (extensionVersion != version) {
      throw SftpExtensionVersionMismatchError(name, extensionVersion);
    }
  }

  void _handleData(SSHChannelData data) {
    // A malformed or oversized packet from the server must tear the SFTP
    // session down cleanly. This runs in a stream listener with no onError, so
    // an uncaught throw here would surface as an unhandled zone error and can
    // crash the isolate. Instead, fail every pending request and close.
    if (_ended != null) return;
    try {
      _buffer.add(data.bytes);
      _handlePackets();
    } catch (e, st) {
      _closeError(e, st);
    }
  }

  /// Max SFTP replies dispatched per event-loop turn. The transport's own
  /// yield governs only DECRYPT; decrypted payloads reach this client through
  /// the channel stream, and a single CHANNEL_DATA can carry many tiny replies
  /// (a server coalescing the acks of a many-small-files upload). Dispatching
  /// them all in one synchronous loop also completes every awaiting per-file
  /// continuation as one uninterruptible run. Bound the batch and continue on a
  /// MACROTASK so the platform pump (paint, input) gets a slice in between.
  static const int _repliesPerTurn = 32;
  bool _drainScheduled = false;

  void _handlePackets() {
    const lengthHeader = 4; // 4 bytes packet length header
    var dispatched = 0;
    while (_buffer.length >= lengthHeader) {
      if (dispatched >= _repliesPerTurn) {
        _scheduleDrain();
        return;
      }
      final length = _buffer.byteData.getUint32(0);
      if (length > _kMaxPacketLength) {
        // Before the server's first packet, this is no packet that is too
        // long: it is something that is no SFTP at all, read as a length
        // (any four letters of text are more than the cap).
        if (!_handshake.isCompleted) {
          throw SftpNotSftpError(_readable(_buffer.data));
        }
        throw SftpError(
            'SFTP packet length $length exceeds maximum $_kMaxPacketLength');
      }
      if (_buffer.length < lengthHeader + length) break;
      final packet = _buffer.consume(lengthHeader + length);
      final payload = Uint8List.sublistView(packet, lengthHeader);
      _handlePacket(payload);
      dispatched++;
    }
  }

  /// The start of [bytes] as someone can read it: its first line, at most
  /// eighty characters, with nothing in it that is not a character to show.
  static String _readable(Uint8List bytes) {
    final text = utf8.decode(
      Uint8List.sublistView(bytes, 0, min(bytes.length, 320)),
      allowMalformed: true,
    );
    final line = text.split(RegExp(r'[\r\n]')).firstWhere((l) => l.trim().isNotEmpty, orElse: () => '');
    final shown = line.replaceAll(RegExp(r'[\x00-\x1f\x7f\ufffd]'), '').trim();
    return shown.length <= 80 ? shown : shown.substring(0, 80);
  }

  /// Continue draining [_buffer] on the next macrotask (at most one pending).
  /// Mirrors the stream listener's error handling so a malformed reply in the
  /// deferred batch tears the client down the same way an immediate one does.
  void _scheduleDrain() {
    if (_drainScheduled) return;
    _drainScheduled = true;
    Future<void>.delayed(Duration.zero, () {
      _drainScheduled = false;
      if (_ended != null) return;
      try {
        _handlePackets();
      } catch (e, st) {
        _closeError(e, st);
      }
    });
  }

  void _handlePacket(Uint8List payload) {
    // A zero-length packet leaves nothing to read the type byte from; reject it
    // rather than throwing a bare RangeError on payload[0].
    if (payload.isEmpty) {
      throw SftpError('Empty SFTP packet');
    }
    final type = payload[0];
    switch (type) {
      case SftpVersionPacket.packetType:
        return _handleVersionPacket(payload);
      case SftpStatusPacket.packetType:
        return _handleStatusPacket(payload);
      case SftpHandlePacket.packetType:
        return _handleHandlePacket(payload);
      case SftpDataPacket.packetType:
        return _handleDataPacket(payload);
      case SftpNamePacket.packetType:
        return _handleNamePacket(payload);
      case SftpAttrsPacket.packetType:
        return _handleAttrsPacket(payload);
      case SftpExtendedReplyPacket.packetType:
        return _handleExtendedReplyPacket(payload);
      default:
        printDebug?.call('SftpClient._handlePacket: unknown packet: $type');
    }
  }

  void _handleVersionPacket(Uint8List payload) {
    final packet = SftpVersionPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');

    if (_handshake.isCompleted) {
      throw SftpError('A second version packet from the server');
    }
    if (packet.version == _kVersion) {
      final handshake = SftpHandsake(packet.version, packet.extensions);
      return _handshake.complete(handshake);
    }

    throw SftpError('Version mismatch: ${packet.version}');
  }

  void _handleStatusPacket(Uint8List payload) {
    final packet = SftpStatusPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleHandlePacket(Uint8List payload) {
    final packet = SftpHandlePacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleNamePacket(Uint8List payload) {
    final packet = SftpNamePacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleDataPacket(Uint8List payload) {
    final packet = SftpDataPacket.decode(payload);
    printTrace?.call('<- $_channel: len=${packet.data.length}');
    _dispatchReply(packet);
  }

  void _handleAttrsPacket(Uint8List payload) {
    final packet = SftpAttrsPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }

  void _handleExtendedReplyPacket(Uint8List payload) {
    final packet = SftpExtendedReplyPacket.decode(payload);
    printTrace?.call('<- $_channel: $packet');
    _dispatchReply(packet);
  }
}

class SftpFile {
  final Uint8List _handle;

  final SftpClient _client;

  SftpFile(this._client, this._handle);

  var _isClosed = false;

  bool get isClosed => _isClosed;

  /// Closes the file on the server. In a session that is over, or that ends
  /// with the close on its way, there is nothing left to close and nothing
  /// to fail: its handles went with it. (A close is often not waited for,
  /// and its failing with the session's own end was an error for nobody.)
  /// A close the server refuses fails as ever.
  Future<void> close() async {
    if (_isClosed) return;
    _isClosed = true;
    try {
      await _client._close(_handle);
    } catch (e) {
      // (Asked of a session that is over, the close is not sent and fails
      // with what ended the session, as every request does.)
      if (identical(e, _client._ended)) return;
      rethrow;
    }
  }

  Future<SftpFileAttrs> stat() async {
    _mustNotBeClosed();
    final reply = await _client._sendFStat(_handle);
    if (reply is SftpAttrsPacket) return reply.attrs;
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    throw SftpStatusError.fromStatus(reply);
  }

  Future<void> setStat(SftpFileAttrs attrs) async {
    _mustNotBeClosed();
    final reply = await _client._sendFSetStat(_handle, attrs);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  /// Reads the file from [offset], as a [Stream] of pieces: [length] bytes,
  /// or fewer where the file ends first. [onProgress] is called with the
  /// number of bytes read so far. Use [readBytes] for a single Uint8List.
  ///
  /// With no [length], the file is read to the size the server reports for
  /// it, or to where it ends if that is sooner (Linux reports a whole page
  /// for the few bytes of a file under /sys). A file that is being written
  /// is read as far as it went when its size was asked, and not followed.
  ///
  /// Where the server reports no size, or none at all, only its answer to a
  /// read says where the file ends, and the file is read to there: Linux
  /// reports no size for what the kernel makes up as it is read (everything
  /// under /proc), and taken at its word such a file came out empty. Nothing
  /// says how far to read ahead then: one piece is asked for, and for each
  /// that comes back whole twice as many may be on their way, up to
  /// [maxPendingRequests]. (A file of no reported size that is written
  /// faster than it is read is followed for as long as that goes on.)
  Stream<Uint8List> read({
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kReadChunkSize,
    int maxPendingRequests = _kReadMaxPendingRequests,
  }) async* {
    _mustNotBeClosed();
    if (chunkSize <= 0) {
      throw ArgumentError.value(chunkSize, 'chunkSize', 'must be positive');
    }
    if (maxPendingRequests <= 0) {
      throw ArgumentError.value(
        maxPendingRequests,
        'maxPendingRequests',
        'must be positive',
      );
    }
    if (length != null && length < 0) {
      throw SftpError('Length must be positive: $length');
    }

    // Where the reading stops whatever the file holds. Null where nothing
    // says: no length was asked for, and the server reports no size.
    int? end;
    if (length != null) {
      end = offset + length;
    } else {
      final size = (await stat()).size;
      if (size != null && size > 0) end = size;
    }

    final pendingReads = <({Future<Uint8List?> piece, int asked})>[];
    var nextOffset = offset;
    var bytesRead = 0;
    // How many pieces may be on their way at a time.
    var ahead = end == null ? 1 : maxPendingRequests;

    while (true) {
      while (pendingReads.length < ahead && (end == null || nextOffset < end)) {
        final asked = end == null ? chunkSize : min(chunkSize, end - nextOffset);
        // Asked for ahead of where the stream is. Where the stream ends
        // before it gets to this one (an earlier read failed, the file
        // ended, the session is over, whoever listened has gone), nobody
        // waits for it any more: its failing then is an error for nobody.
        // Waited for, it fails as any other.
        pendingReads.add((piece: _readChunk(asked, nextOffset)..ignore(), asked: asked));
        nextOffset += asked;
      }

      if (pendingReads.isEmpty) break;

      final next = pendingReads.removeAt(0);
      final chunk = await next.piece;
      if (chunk == null) break;
      if (chunk.isEmpty) {
        throw SftpError('Unexpected empty data chunk before EOF');
      }
      if (chunk.length > next.asked) {
        // What follows it was asked for by where this piece was to end:
        // taken as it is, bytes would be there twice, or missing.
        throw SftpError('The server sent ${chunk.length} bytes where ${next.asked} were asked for');
      }

      yield chunk;

      bytesRead += chunk.length;
      onProgress?.call(bytesRead);

      // Fewer bytes than were asked for: the file ends here. What was asked
      // for ahead of this is past its end, whatever came back for it.
      if (chunk.length < next.asked) break;
      if (end == null) ahead = min(ahead * 2, maxPendingRequests);
    }
  }

  /// Downloads this file into [destination].
  ///
  /// Returns the total number of bytes written.
  Future<int> downloadTo(
    StreamSink<List<int>> destination, {
    int? length,
    int offset = 0,
    void Function(int bytesRead)? onProgress,
    int chunkSize = _kDownloadChunkSize,
    int maxPendingRequests = _kDownloadMaxPendingRequests,
    bool closeDestination = false,
  }) async {
    _mustNotBeClosed();
    var bytesRead = 0;

    try {
      await destination.addStream(
        read(
          length: length,
          offset: offset,
          onProgress: (value) {
            bytesRead = value;
            onProgress?.call(value);
          },
          chunkSize: chunkSize,
          maxPendingRequests: maxPendingRequests,
        ),
      );
    } finally {
      if (closeDestination) {
        await destination.close();
      }
    }

    return bytesRead;
  }

  /// Reads at most [length] bytes from the file starting at [offset]. If
  /// [length] is null, reads until end of the file.
  /// Use [read] if you want to stream large file in chunks.
  Future<Uint8List> readBytes({int? length, int offset = 0}) async {
    final buffer = BytesBuilder(copy: false);
    await for (final chunk in read(length: length, offset: offset)) {
      buffer.add(chunk);
    }
    return buffer.takeBytes();
  }

  /// Writes [stream] to the file starting at [offset].
  ///
  /// Returns a [SftpFileWriter] that can be used to control the write
  /// operation or wait for it to complete.
  SftpFileWriter write(
    Stream<Uint8List> stream, {
    int offset = 0,
    void Function(int total)? onProgress,
  }) {
    return SftpFileWriter(this, stream, offset, onProgress);
  }

  /// Writes [data] to the file starting at [offset].
  Future<void> writeBytes(Uint8List data, {int offset = 0}) async {
    const maxChunkSize = 32 * 1024;
    var bytesSent = 0;
    final futures = <Future<void>>[];
    while (bytesSent < data.length) {
      final chunkSize = min(data.length - bytesSent, maxChunkSize);
      final chunkBegin = bytesSent;
      final chunkEnd = chunkBegin + chunkSize;
      final chunk = Uint8List.sublistView(data, chunkBegin, chunkEnd);
      futures.add(_writeChunk(chunk, offset: offset + bytesSent));
      bytesSent += chunkSize;
    }
    await Future.wait(futures);
  }

  /// Gets filesystem statistics that this file is on.
  ///
  /// **Note**: This is an extension to the SFTP protocol, supported by most
  /// openssh servers. A [SftpExtensionError] is thrown if the server does not
  /// support this extension.
  ///
  /// See also:
  ///
  /// * [SftpClient.statvfs] which takes a path instead of a file handle as
  ///   argument.
  Future<SftpStatVfs> statvfs() async {
    _mustNotBeClosed();
    await _client._checkExtension('fstatvfs@openssh.com', '2');
    final payload = SftpFstatVfsRequest(handle: _handle);
    final reply = await _client._sendExtended(payload);
    if (reply is SftpStatusPacket) throw SftpStatusError.fromStatus(reply);
    if (reply is! SftpExtendedReplyPacket) throw SftpError('Unexpected reply');
    final stat = SftpStatVfsReply.decode(reply.payload);
    return SftpStatVfs.fromReply(stat);
  }

  Future<void> _writeChunk(Uint8List data, {int offset = 0}) async {
    // print('_writeChunk: offset=$offset');
    _mustNotBeClosed();
    final reply = await _client._sendWrite(_handle, offset, data);
    if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
    SftpStatusError.check(reply);
  }

  Future<Uint8List?> _readChunk(int length, [int offset = 0]) async {
    _mustNotBeClosed();
    final first = await _client._sendRead(_handle, offset, length);
    if (first is! SftpDataPacket) {
      if (first is! SftpStatusPacket) throw SftpError('Unexpected reply');
      SftpStatusError.check(first); // throws on error; EOF/OK falls through
      return null;
    }
    // Fast path: the server returned the whole chunk (the usual case).
    if (first.data.length >= length || first.data.isEmpty) return first.data;

    // Short read. SSH_FXP_READ is explicitly allowed to return FEWER bytes
    // than requested, and the read loop above advances its offset by the full
    // requested length - so if we hand back a short buffer, the gap between
    // what arrived and the next offset is never re-requested and the download
    // is silently corrupted and truncated. Re-request the shortfall at the
    // advanced offset until the chunk is filled or the server signals EOF.
    final out = BytesBuilder();
    out.add(first.data);
    var got = first.data.length;
    while (got < length) {
      final reply = await _client._sendRead(_handle, offset + got, length - got);
      if (reply is SftpDataPacket) {
        if (reply.data.isEmpty) break;
        out.add(reply.data);
        got += reply.data.length;
        continue;
      }
      if (reply is! SftpStatusPacket) throw SftpError('Unexpected reply');
      SftpStatusError.check(reply); // throws on error; EOF ends the fill
      break;
    }
    return out.toBytes();
  }

  void _mustNotBeClosed() {
    if (isClosed) throw SftpError('File is closed');
  }

  @override
  String toString() => 'SftpFile(0x${hex.encode(_handle)})';
}

/// Handsake information received from the server.
class SftpHandsake {
  final int version;

  final Map<String, String> extensions;

  SftpHandsake(this.version, this.extensions);

  @override
  String toString() => 'SftpHandsake($version, $extensions)';
}
