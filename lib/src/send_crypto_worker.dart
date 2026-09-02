import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/algorithm/ssh_send_crypto.dart';
import 'package:zest_ssh_core/src/utils/secure_memory.dart';

/// A long-lived worker isolate that performs SSH send-side packet encryption
/// (ChaCha20-Poly1305 and AES-GCM) off the main isolate, so bulk SFTP uploads
/// no longer block the UI with synchronous crypto.
///
/// Correctness rests on three invariants, all enforced here:
///  1. The transport owns the sequence number and passes it per packet, so the
///     worker never derives a nonce independently (nonce reuse would be fatal).
///  2. One SendPort/ReceivePort pair plus a single-threaded worker gives FIFO:
///     replies arrive in submit order, so the transport writes ciphertext in
///     sequence order. A per-job monotonic id lets the transport assert this and
///     fail closed on any violation.
///  3. Key material crosses as a fresh copy (never a view of a buffer the main
///     isolate zeroes on rekey) and is zeroed in the worker on install/dispose.
///
/// The worker runs the SAME [encryptChaChaPacket]/[encryptGcmPacket] functions
/// as the inline fallback, so its output is byte-identical by construction.
class SendCryptoWorker {
  SendCryptoWorker._(this._onDone, this._onError);

  Isolate? _isolate;
  SendPort? _toWorker;
  final ReceivePort _fromWorker = ReceivePort();
  final ReceivePort _onErrorPort = ReceivePort();
  final ReceivePort _onExitPort = ReceivePort();
  final Completer<void> _ready = Completer<void>();
  final Completer<void> _disposeAck = Completer<void>();
  bool _disposed = false;

  final void Function(int jobId, Uint8List ciphertext) _onDone;
  final void Function(String message) _onError;

  /// Kills an orphaned worker isolate if its wrapper is garbage-collected
  /// without an explicit dispose (e.g. a transport abandoned without close), so
  /// a live send key cannot linger in a leaked isolate heap.
  static final Finalizer<Isolate> _finalizer =
      Finalizer((iso) => iso.kill(priority: Isolate.immediate));

  /// Spawn and hand-shake the worker. Throws if the isolate cannot start; the
  /// caller then falls back to inline encryption (the offload is a pure
  /// optimization, never required for correctness).
  static Future<SendCryptoWorker> spawn({
    required void Function(int jobId, Uint8List ciphertext) onDone,
    required void Function(String message) onError,
  }) async {
    final w = SendCryptoWorker._(onDone, onError);
    w._fromWorker.listen(w._handleFromWorker);
    w._onErrorPort.listen((e) {
      final detail = e is List && e.isNotEmpty ? e.first : e;
      w._fail('worker isolate error: $detail');
    });
    w._onExitPort.listen((_) => w._fail('worker isolate exited unexpectedly'));
    w._isolate = await Isolate.spawn(
      _sendCryptoWorkerEntry,
      w._fromWorker.sendPort,
      onError: w._onErrorPort.sendPort,
      onExit: w._onExitPort.sendPort,
      debugName: 'ssh-send-crypto',
    );
    if (w._isolate != null) _finalizer.attach(w, w._isolate!, detach: w);
    await w._ready.future;
    return w;
  }

  void _handleFromWorker(dynamic message) {
    // First message is the handshake: the worker's own SendPort.
    if (message is SendPort) {
      _toWorker = message;
      if (!_ready.isCompleted) _ready.complete();
      return;
    }
    final list = message as List;
    switch (list[0] as String) {
      case 'done':
        if (!_disposed) _onDone(list[1] as int, list[2] as Uint8List);
      case 'error':
        _fail('send crypto worker: ${list[2]}');
      case 'disposed':
        if (!_disposeAck.isCompleted) _disposeAck.complete();
    }
  }

  void _fail(String message) {
    if (_disposed) return;
    _onError(message);
  }

  /// Install a key generation. [mode] is `chacha` or `gcm`. [key]/[iv] MUST be
  /// fresh copies (never views of a buffer the main isolate zeroes on rekey).
  /// Travels on the same FIFO port as encrypt jobs, so it is applied strictly
  /// after every job submitted before it (the in-band rekey barrier).
  void installKey({
    required int epoch,
    required String mode,
    required Uint8List key,
    required Uint8List iv,
  }) {
    _toWorker?.send(['install', epoch, mode, key, iv]);
  }

  /// Enqueue one encrypt job. Returns immediately; the ciphertext arrives via
  /// the [onDone] callback in submit order.
  void encrypt({
    required int jobId,
    required int epoch,
    required int seq,
    required int packetLength,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    _toWorker?.send(['encrypt', jobId, epoch, seq, packetLength, plaintext, aad]);
  }

  /// Zero keys in the worker and tear it down.
  void dispose() {
    if (_disposed) return;
    _disposed = true;
    _finalizer.detach(this);
    _toWorker?.send(const ['dispose']);
    // Let the worker zero its keys and ack before the hard-kill backstop, so
    // the kill cannot pre-empt the scrub; kill anyway if no ack arrives.
    _disposeAck.future
        .timeout(const Duration(milliseconds: 500))
        .catchError((Object _) {})
        .whenComplete(() {
      _isolate?.kill(priority: Isolate.immediate);
      _isolate = null;
      _fromWorker.close();
      _onErrorPort.close();
      _onExitPort.close();
    });
  }
}

/// Worker isolate entrypoint. Single-threaded FIFO drain of jobs: each `encrypt`
/// runs one synchronous crypto call and replies before the next message is
/// handled, which is what makes reply order equal submit order.
void _sendCryptoWorkerEntry(SendPort toMain) {
  final rx = ReceivePort();
  toMain.send(rx.sendPort); // handshake

  var epoch = -1;
  var mode = '';
  var key = Uint8List(0);
  var iv = Uint8List(0);

  rx.listen((message) {
    final list = message as List;
    switch (list[0] as String) {
      case 'install':
        if (key.isNotEmpty) zeroBytes(key);
        epoch = list[1] as int;
        mode = list[2] as String;
        key = list[3] as Uint8List;
        iv = list[4] as Uint8List;
      case 'encrypt':
        final jobId = list[1] as int;
        final jobEpoch = list[2] as int;
        final seq = list[3] as int;
        final packetLength = list[4] as int;
        final plaintext = list[5] as Uint8List;
        final aad = list[6] as Uint8List?;
        // The epoch guard catches a key swap that landed one packet early/late:
        // encrypting under the wrong key generation is a hard error, never a
        // silent wrong-key packet.
        if (jobEpoch != epoch) {
          toMain.send(
              ['error', jobId, 'epoch mismatch: job $jobEpoch vs installed $epoch']);
          return;
        }
        try {
          final wire = mode == 'chacha'
              ? encryptChaChaPacket(key, seq, plaintext, packetLength)
              : encryptGcmPacket(key, iv, seq, aad!, plaintext);
          toMain.send(['done', jobId, wire]);
        } catch (e) {
          toMain.send(['error', jobId, '$e']);
        }
      case 'dispose':
        if (key.isNotEmpty) zeroBytes(key);
        if (iv.isNotEmpty) zeroBytes(iv);
        toMain.send(const ['disposed']);
        rx.close();
    }
  });
}
