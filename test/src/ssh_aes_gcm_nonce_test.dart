import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_send_crypto.dart';
import 'package:zest_ssh_core/src/message/msg_request.dart';

import 'played_server.dart';

/// AES-GCM packets are counted from the keys.
///
/// Under aes-gcm@openssh.com every packet has a nonce of its own: the one
/// the keys give, counted on by one for each packet since those keys were
/// taken into use (RFC 5647, 7.1, and OpenSSH counts so). This package
/// counted by the number of the packet. The two are the same where packet
/// numbers start again with the keys, which they do under the strict key
/// exchange and not otherwise. With a server that does not have the strict
/// exchange (OpenSSH before 9.6 where it was not added later, and much that
/// is not OpenSSH), the client's first packet under keys went out with the
/// nonce three further on, since three packets had gone before in the clear,
/// and the server's first was read with the one three further on: neither
/// side could read the other, and the connection ended where it began.
///
/// The server is played (played_server.dart). That the played server counts
/// as OpenSSH does is held by the OpenSSH client of the machine
/// (played_server_openssh_test.dart), with the strict exchange and without.
void main() {
  /// A client that offers whatever a played server here proposes.
  SSHClient wide(SSHSocket socket) => SSHClient(
        socket,
        username: 'deploy',
        algorithms: const SSHAlgorithms(
          kex: [SSHKexType.x25519],
          hostkey: [SSHHostkeyType.ed25519],
          cipher: [
            SSHCipherType.aes256gcm,
            SSHCipherType.aes128gcm,
            SSHCipherType.chacha20poly1305,
            SSHCipherType.aes256ctr,
          ],
          mac: [SSHMacType.hmacSha256],
        ),
        keepAliveInterval: null,
      );

  Future<PlayedServer> signedIn(PlayedSuite suite, {PlayedSuite? toClient, required bool strict}) async {
    final server = await PlayedServer.signedIn(
        client: (socket, _) => wide(socket), suite: suite, toClient: toClient, strict: strict);
    addTearDown(server.client.close);
    return server;
  }

  /// Each side asks the other something and reads its answer, [times] over:
  /// several packets each way, every one under the next nonce.
  Future<void> bothWays(PlayedServer server, {int times = 3}) async {
    for (var i = 0; i < times; i++) {
      server.send([SSH_Message_Global_Request(requestName: 'keepalive@openssh.com', wantReply: true).encode()]);
      await server.next(SSH_Message_Request_Failure.messageId);
      final answered = server.client.ping();
      await server.next(SSH_Message_Global_Request.messageId);
      server.send([SSH_Message_Request_Success(Uint8List(0)).encode()]);
      await answered.timeout(PlayedServer.patience);
    }
    expect(server.client.isClosed, isFalse);
  }

  const gcm128 = PlayedSuite(SSHCipherType.aes128gcm);

  group('the nonce of a packet', () {
    final iv = Uint8List.fromList([1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 250]);

    test('the first packet under keys has the nonce the keys give', () {
      expect(sshAeadNonceForSequence(iv, 0), iv);
      expect(sshAeadNonceForSequence(iv, 0), isNot(same(iv)), reason: 'a nonce of its own, the keys\' stays as it is');
    });

    test('each packet after it has the next: the last eight bytes are counted on, and no others', () {
      expect(sshAeadNonceForSequence(iv, 1), [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 251]);
      expect(sshAeadNonceForSequence(iv, 5), [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 255]);
      expect(sshAeadNonceForSequence(iv, 6), [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 1, 0]);
      expect(sshAeadNonceForSequence(iv, 0x10000), [1, 2, 3, 4, 0, 0, 0, 0, 0, 1, 0, 250]);
      expect(iv, [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 250]);
    });

    test('a count that passes the end of its eight bytes starts at nought, and leaves the first four alone', () {
      final last = Uint8List.fromList([9, 8, 7, 6, 255, 255, 255, 255, 255, 255, 255, 255]);
      expect(sshAeadNonceForSequence(last, 1), [9, 8, 7, 6, 0, 0, 0, 0, 0, 0, 0, 0]);
      expect(sshAeadNonceForSequence(last, 3), [9, 8, 7, 6, 0, 0, 0, 0, 0, 0, 0, 2]);
    });

    test('keys that give no twelve bytes are refused, and for that', () {
      final refused = throwsA(isA<ArgumentError>().having((e) => e.name, 'what was wrong', 'iv'));
      expect(() => sshAeadNonceForSequence(Uint8List(16), 0), refused);
      expect(() => sshAeadNonceForSequence(Uint8List(8), 0), refused);
      expect(() => sshAeadNonceForSequence(Uint8List(0), 0), refused);
    });
  });

  group('a server that does not have the strict key exchange', () {
    for (final suite in [PlayedSuite.gcm, gcm128]) {
      test('$suite: the client signs in, and each side reads the other', () async {
        final server = await signedIn(suite, strict: false);
        await bothWays(server);
      });
    }

    // One direction at a time, so that each count is held by itself.
    test('only what the client sends is under aes-gcm: signed in, and new keys', () async {
      final server = await signedIn(PlayedSuite.gcm, toClient: PlayedSuite.ctr, strict: false);
      await bothWays(server);
      await server.rekey();
      await bothWays(server);
    });

    test('only what the client is sent is under aes-gcm: signed in, and new keys', () async {
      final server = await signedIn(PlayedSuite.ctr, toClient: PlayedSuite.gcm, strict: false);
      await bothWays(server);
      await server.rekey();
      await bothWays(server);
    });

    test('new keys: the count starts again with them, while the numbers of the packets go on', () async {
      final server = await signedIn(PlayedSuite.gcm, strict: false);
      await bothWays(server);
      await server.rekey();
      await bothWays(server);
      await server.rekey();
      await bothWays(server, times: 5);
    });
  });

  group('a server that has the strict key exchange, as before', () {
    for (final suite in [PlayedSuite.gcm, gcm128]) {
      test('$suite: signed in, new keys twice, and each side reads the other throughout', () async {
        final server = await signedIn(suite, strict: true);
        await bothWays(server);
        await server.rekey();
        await bothWays(server);
        await server.rekey();
        await bothWays(server);
      });
    }
  });

  // The other cipher that checks its packets by itself goes by the number of
  // the packet, and has to go on doing so: without the strict exchange that
  // number does not start again with new keys.
  group('chacha20-poly1305 goes by the number of the packet', () {
    for (final strict in [true, false]) {
      test('${strict ? 'with' : 'without'} the strict key exchange: signed in, new keys twice', () async {
        final server = await signedIn(PlayedSuite.chacha, strict: strict);
        await bothWays(server);
        await server.rekey();
        await bothWays(server);
        await server.rekey();
        await bothWays(server);
      });
    }
  });
}
