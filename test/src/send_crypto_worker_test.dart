import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_cipher_chacha20_poly1305.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_send_crypto.dart';
import 'package:zest_ssh_core/src/send_crypto_worker.dart';

/// Deterministic filler (a plain LCG, NOT crypto) so every run exercises the
/// same bytes and byte-identity is reproducible.
Uint8List _seeded(int len, int seed) {
  final out = Uint8List(len);
  var x = (seed & 0xffffffff) | 1;
  for (var i = 0; i < len; i++) {
    x = (1103515245 * x + 12345) & 0xffffffff;
    out[i] = (x >> 16) & 0xff;
  }
  return out;
}

void main() {
  group('SendCryptoWorker', () {
    late SendCryptoWorker worker;
    final pending = <int, Completer<Uint8List>>{};
    late List<String> errors;
    var jobCounter = 0;

    setUp(() async {
      pending.clear();
      errors = <String>[];
      jobCounter = 0;
      worker = await SendCryptoWorker.spawn(
        onDone: (jobId, ct) => pending.remove(jobId)?.complete(ct),
        onError: errors.add,
      );
    });

    tearDown(() => worker.dispose());

    Future<Uint8List> viaWorker({
      required int epoch,
      required int seq,
      required Uint8List plaintext,
      Uint8List? aad,
    }) {
      final jobId = jobCounter++;
      final c = Completer<Uint8List>();
      pending[jobId] = c;
      worker.encrypt(
        jobId: jobId,
        epoch: epoch,
        seq: seq,
        packetLength: plaintext.length,
        plaintext: plaintext,
        aad: aad,
      );
      return c.future;
    }

    test('ChaCha20-Poly1305: worker output byte-identical to inline + decrypts',
        () async {
      final key = _seeded(64, 1);
      worker.installKey(
          epoch: 0, mode: 'chacha', key: Uint8List.fromList(key), iv: Uint8List(0));
      for (final len in [1, 8, 15, 16, 31, 100, 1024, 32768]) {
        for (final seq in [0, 1, 42, 0xffffffff]) {
          final plaintext = _seeded(len, len * 31 + seq);
          final inline = encryptChaChaPacket(key, seq, plaintext, plaintext.length);
          final wire = await viaWorker(epoch: 0, seq: seq, plaintext: plaintext);
          expect(wire, equals(inline), reason: 'len=$len seq=$seq');
          // The offloaded ciphertext must decrypt back to the plaintext.
          final rt = SSHCipherChaCha20Poly1305(key: key).decrypt(
            wire.sublist(0, 4),
            wire.sublist(4, wire.length - 16),
            wire.sublist(wire.length - 16),
            seq,
          );
          expect(rt, equals(plaintext), reason: 'round-trip len=$len seq=$seq');
        }
      }
      expect(errors, isEmpty);
    });

    test('AES-GCM: worker output byte-identical to inline', () async {
      final key = _seeded(32, 2);
      final iv = _seeded(12, 3);
      worker.installKey(
          epoch: 0,
          mode: 'gcm',
          key: Uint8List.fromList(key),
          iv: Uint8List.fromList(iv));
      for (final len in [16, 32, 100, 1024, 32768]) {
        for (final seq in [0, 1, 42]) {
          final plaintext = _seeded(len, len + seq);
          final aad = Uint8List(4)..buffer.asByteData().setUint32(0, len);
          final inline = encryptGcmPacket(key, iv, seq, aad, plaintext);
          final wire =
              await viaWorker(epoch: 0, seq: seq, plaintext: plaintext, aad: aad);
          expect(wire, equals(inline), reason: 'gcm len=$len seq=$seq');
        }
      }
      expect(errors, isEmpty);
    });

    test('epoch mismatch fails closed (no wrong-key packet emitted)', () async {
      final key = _seeded(64, 4);
      worker.installKey(
          epoch: 5, mode: 'chacha', key: Uint8List.fromList(key), iv: Uint8List(0));
      final jobId = jobCounter++;
      final c = Completer<Uint8List>();
      pending[jobId] = c;
      worker.encrypt(
          jobId: jobId, epoch: 4, seq: 0, packetLength: 64, plaintext: _seeded(64, 9));
      await Future<void>.delayed(const Duration(milliseconds: 300));
      expect(c.isCompleted, isFalse, reason: 'must not emit a wrong-epoch packet');
      expect(errors, isNotEmpty);
      expect(errors.first, contains('epoch mismatch'));
    });

    test('FIFO: replies arrive strictly in submit order', () async {
      final key = _seeded(64, 7);
      worker.installKey(
          epoch: 0, mode: 'chacha', key: Uint8List.fromList(key), iv: Uint8List(0));
      final order = <int>[];
      final futures = <Future<void>>[];
      for (var seq = 0; seq < 64; seq++) {
        final jobId = jobCounter++;
        final c = Completer<Uint8List>();
        pending[jobId] = c;
        worker.encrypt(
            jobId: jobId,
            epoch: 0,
            seq: seq,
            packetLength: 512,
            plaintext: _seeded(512, seq));
        futures.add(c.future.then((_) => order.add(jobId)));
      }
      await Future.wait(futures);
      expect(order, equals(List.generate(64, (i) => i)));
    });

    test('key swap across epochs stays byte-identical after reinstall', () async {
      final k0 = _seeded(64, 11);
      final k1 = _seeded(64, 22);
      worker.installKey(
          epoch: 0, mode: 'chacha', key: Uint8List.fromList(k0), iv: Uint8List(0));
      final p0 = _seeded(300, 100);
      final w0 = await viaWorker(epoch: 0, seq: 3, plaintext: p0);
      expect(w0, equals(encryptChaChaPacket(k0, 3, p0, p0.length)));
      // Rekey to a new epoch/key; the in-band install applies after w0.
      worker.installKey(
          epoch: 1, mode: 'chacha', key: Uint8List.fromList(k1), iv: Uint8List(0));
      final p1 = _seeded(300, 200);
      final w1 = await viaWorker(epoch: 1, seq: 0, plaintext: p1);
      expect(w1, equals(encryptChaChaPacket(k1, 0, p1, p1.length)));
      expect(errors, isEmpty);
    });
  });
}
