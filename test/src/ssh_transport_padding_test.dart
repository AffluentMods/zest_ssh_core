import 'dart:async';
import 'dart:mirrors';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_cipher_chacha20_poly1305.dart';
import 'package:zest_ssh_core/src/ssh_packet.dart';

/// Padding validation of INCOMING packets must follow the framing that is
/// actually in force, not the one merely negotiated. Before NEWKEYS the KEX
/// reply is cleartext (5-byte header alignment) even when ChaCha20 / GCM
/// was agreed; only once remote keys are applied does the AEAD rule (the
/// 4-byte length excluded) apply. Regression for the ECDH P-256 + Ed25519
/// reply that the old check rejected with "Invalid padding length".
void main() {
  final transportLibrary = reflectClass(SSHTransport).owner as LibraryMirror;
  Symbol sym(String name) => MirrorSystem.getSymbol(name, transportLibrary);
  void setPrivate(SSHTransport t, String field, Object? value) =>
      reflect(t).setField(sym(field), value);
  void verify(SSHTransport t, int payloadLength, int paddingLength) =>
      reflect(t).invoke(sym('_verifyPacketPadding'), [payloadLength, paddingLength]);

  SSHTransport makeTransport() {
    final socket = _NullSocket();
    return SSHTransport(socket, isServer: false);
  }

  test('a cleartext reply uses the 5-byte header rule once ChaCha is negotiated',
      () {
    final t = makeTransport();
    setPrivate(t, '_serverCipherType', SSHCipherType.chacha20poly1305);
    // The OpenSSH 10.2 ECDH P-256 reply (Ed25519 host key): 220 payload
    // bytes padded with 7, since 4 + 1 + 220 + 7 = 232 is 8-aligned. The old
    // check applied the AEAD rule (1 + 220 + pad) and demanded 11.
    expect(() => verify(t, 220, 7), returnsNormally);
    // Every payload length: the sender's own minimum must be accepted.
    for (var payload = 1; payload < 300; payload++) {
      final minimum = SSHPacket.paddingLength(payload, align: 8);
      expect(() => verify(t, payload, minimum), returnsNormally,
          reason: 'payload $payload, pad $minimum');
      // More padding than the minimum is fine too (up to 255).
      expect(() => verify(t, payload, minimum + 8), returnsNormally);
    }
    // Under the header rule 4 + 1 + 219 + 7 = 231 is misaligned.
    expect(() => verify(t, 219, 7), throwsA(isA<SSHPacketError>()));
  });

  test('an encrypted ChaCha packet uses the AEAD rule (length excluded)', () {
    final t = makeTransport();
    setPrivate(t, '_serverCipherType', SSHCipherType.chacha20poly1305);
    setPrivate(t, '_remoteCipherKey', Uint8List(64));
    setPrivate(t, '_remoteIV', Uint8List(0));
    setPrivate(t, '_remoteChaCha', SSHCipherChaCha20Poly1305(key: Uint8List(64)));
    // 1 + 220 + 7 = 228 is not 8-aligned; 1 + 220 + 11 = 232 is.
    expect(() => verify(t, 220, 7), throwsA(isA<SSHPacketError>()));
    expect(() => verify(t, 220, 11), returnsNormally);
  });

  test('padding below four bytes is always rejected', () {
    final t = makeTransport();
    expect(() => verify(t, 20, 3), throwsA(isA<SSHPacketError>()));
  });
}

/// A socket that never delivers anything and swallows everything written
/// (the transport's version string on construction), so the padding check
/// can be exercised through reflection without a peer.
class _NullSocket extends SSHSocket {
  final _incoming = StreamController<Uint8List>();
  final _outgoing = StreamController<List<int>>()..stream.listen((_) {});
  @override
  Stream<Uint8List> get stream => _incoming.stream;
  @override
  StreamSink<List<int>> get sink => _outgoing.sink;
  @override
  Future<void> get done => _incoming.done;
  @override
  Future<void> close() async {
    await _outgoing.close();
    await _incoming.close();
  }

  @override
  void destroy() {}
}
