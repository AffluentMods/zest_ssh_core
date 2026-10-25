import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';

import 'played_server.dart';

/// A packet that does not pass its check ends the connection, and is said as
/// that: the same whatever protects the packets, and with nothing in the
/// words that is made with the session's keys.
///
/// Every packet under keys carries a check value: a MAC, or the tag of a
/// cipher that checks its packets by itself. A packet that was changed on
/// the way, by a line that is failing or by whoever sits on it, does not
/// pass, and the connection ends there. What the client said of it depended
/// on the cipher: "MAC mismatch, expected: [...], actual: [...]" with both
/// check values in it, the right one for the changed packet among them,
/// which is made with the session's key; "AEAD authentication failed"; or
/// "Malformed packet: SSHMacMismatchException: ...". An application could
/// not tell such an end from a packet that could not be read. And with a
/// cipher that has a MAC of the older kind, a changed packet was looked
/// into before its MAC was checked: where its padding did not fit, the
/// client said that, with the numbers it had found, and whoever changed the
/// packet learned something of what it held.
///
/// With a server played by the test, which changes what it sends.
void main() {
  const suites = [PlayedSuite.ctr, PlayedSuite.ctrEtm, PlayedSuite.cbc, PlayedSuite.gcm, PlayedSuite.chacha];
  const offered = SSHAlgorithms(
    kex: [SSHKexType.x25519],
    hostkey: [SSHHostkeyType.ed25519],
    cipher: [
      SSHCipherType.chacha20poly1305,
      SSHCipherType.aes256gcm,
      SSHCipherType.aes256ctr,
      SSHCipherType.aes256cbc,
    ],
    mac: [SSHMacType.hmacSha256Etm, SSHMacType.hmacSha256],
  );

  /// A client signed in to a played server under [suite], with a session
  /// open on it: how its connection ends once the server has sent what
  /// [damaged] makes of two packets of the session's output, after one that
  /// is as it should be; and what the session printed.
  Future<({Object? endedWith, List<String> printed})> sent(
    PlayedSuite suite, {
    required bool strict,
    required void Function(List<Uint8List> packets) damaged,
  }) async {
    final server = await PlayedServer.signedIn(
      client: (socket, _) => SSHClient(socket, username: 'deploy', algorithms: offered, keepAliveInterval: null),
      suite: suite,
      strict: strict,
    );
    addTearDown(server.client.close);
    Object? endedWith;
    final ended = server.client.done.then((_) {}, onError: (Object e) {
      endedWith = e;
    });
    final opening = server.client.shell();
    final channel = await server.confirmChannel();
    expect((await channel.nextRequest()).requestType, 'pty-req');
    server.send([channel.success]);
    expect((await channel.nextRequest()).requestType, 'shell');
    server.send([channel.success]);
    final session = await opening.timeout(PlayedServer.patience);
    final printed = <String>[];
    session.stdout.listen((data) => printed.add(String.fromCharCodes(data)), onError: (Object _) {});
    server.send([channel.data('before ')]);
    server.sendChanged([channel.data('changed '), channel.data('after')], damaged);
    await ended.timeout(PlayedServer.patience);
    await server.settle();
    return (endedWith: endedWith, printed: printed);
  }

  /// The two things that are said of a packet that was changed on the way.
  const didNotPass = 'A packet from the other side did not pass its check: it was changed or damaged on the way, or '
      'the two sides do not protect their packets the same way';
  const noSuchLength =
      'A packet from the other side has a length that no packet has: it was changed or damaged on the way, or '
      'the two sides do not protect their packets the same way';

  /// The connection ended over a packet that was changed on the way: said
  /// as that ([itsLength]: by its length, which is read before a packet can
  /// be checked), marked as that, and nothing of it used.
  void expectDamaged(({Object? endedWith, List<String> printed}) outcome, {bool itsLength = false}) {
    expect(
      outcome.endedWith,
      isA<SSHPacketError>()
          .having((e) => e.message, 'what it says', itsLength ? noSuchLength : didNotPass)
          .having((e) => e.damaged, 'changed on the way', isTrue),
    );
    expect(outcome.printed.join(), 'before ', reason: 'nothing of the packet, or of what came after it, is used');
  }

  for (final strict in [true, false]) {
    final how = strict ? 'the strict exchange' : 'no strict exchange';
    for (final suite in suites) {
      group('$suite, $how', () {
        test('the last bit of the check value changed', () async {
          expectDamaged(await sent(suite, strict: strict, damaged: (packets) {
            packets[0][packets[0].length - 1] ^= 0x01;
          }));
        });

        test('the first bit of the check value changed', () async {
          expectDamaged(await sent(suite, strict: strict, damaged: (packets) {
            packets[0][packets[0].length - suite.checkLength] ^= 0x80;
          }));
        });

        test('a bit of what the packet carries changed', () async {
          expectDamaged(await sent(suite, strict: strict, damaged: (packets) {
            packets[0][packets[0].length - suite.checkLength - 12] ^= 0x10;
          }));
        });

        test('the byte that says how long its padding is changed, each bit of it in turn', () async {
          // (The fifth byte of a packet: behind the four of its length. Under aes256-cbc a change of it makes
          // noise of the whole first block, the length with it.)
          for (var bit = 0; bit < 8; bit++) {
            expectDamaged(
              await sent(suite, strict: strict, damaged: (packets) {
                packets[0][4] ^= 1 << bit;
              }),
              itsLength: identical(suite, PlayedSuite.cbc),
            );
          }
        });

        test('the check value of the packet after it in its place', () async {
          expectDamaged(await sent(suite, strict: strict, damaged: (packets) {
            final from = packets[1].length - suite.checkLength;
            packets[0].setRange(packets[0].length - suite.checkLength, packets[0].length, packets[1], from);
          }));
        });

        test('its length made one that no packet has', () async {
          // The first bit of the four bytes of its length: two thousand million more, or noise.
          expectDamaged(
            await sent(suite, strict: strict, damaged: (packets) {
              packets[0][0] ^= 0x80;
            }),
            itsLength: true,
          );
        });
      });
    }
  }

  // With a MAC of the older kind the packet is encrypted whole and the MAC
  // is made of what it was before: the client has to decrypt it to check
  // it. Nothing of what it then holds is looked into before it has passed.
  group('aes256-ctr with hmac-sha2-256', () {
    for (final strict in [true, false]) {
      final how = strict ? 'the strict exchange' : 'no strict exchange';

      test('a padding made longer than its packet, $how: it did not pass its check, and nothing is said of its '
          'padding', () async {
        final outcome = await sent(PlayedSuite.ctr, strict: strict, damaged: (packets) {
          packets[0][4] ^= 0x80;
        });
        expect('${outcome.endedWith}', isNot(contains('adding')), reason: 'what it says: ${outcome.endedWith}');
        expectDamaged(outcome);
      });

      test('a length made one more or eight more, which is no whole number of blocks, $how: no packet has it',
          () async {
        for (final more in [0x01, 0x08]) {
          expectDamaged(
            await sent(PlayedSuite.ctr, strict: strict, damaged: (packets) {
              packets[0][3] ^= more;
            }),
            itsLength: true,
          );
        }
      });
    }
  });

  test('a packet that is as it should be is read, under each suite: what the session printed', () async {
    for (final suite in suites) {
      final server = await PlayedServer.signedIn(
        client: (socket, _) => SSHClient(socket, username: 'deploy', algorithms: offered, keepAliveInterval: null),
        suite: suite,
      );
      addTearDown(server.client.close);
      final opening = server.client.shell();
      final channel = await server.confirmChannel();
      await channel.nextRequest();
      server.send([channel.success]);
      await channel.nextRequest();
      server.send([channel.success]);
      final session = await opening.timeout(PlayedServer.patience);
      final printed = <String>[];
      session.stdout.listen((data) => printed.add(String.fromCharCodes(data)));
      server.send([channel.data('before ')]);
      server.sendChanged([channel.data('unchanged '), channel.data('after')], (packets) {});
      await server.settle();
      expect(printed.join(), 'before unchanged after', reason: '$suite');
      expect(server.client.isClosed, isFalse, reason: '$suite');
    }
  });

  test('what is said of it has nothing in it that a check value is made of, and no number', () async {
    for (final suite in suites) {
      final outcome = await sent(suite, strict: true, damaged: (packets) {
        packets[0][packets[0].length - 1] ^= 0x01;
      });
      final text = '${outcome.endedWith}';
      expect(text, isNot(contains('[')), reason: '$suite: $text');
      expect(RegExp(r'\d').hasMatch(text), isFalse, reason: '$suite: $text');
    }
    expect(RegExp(r'\d').hasMatch(noSuchLength), isFalse);
  });

  test('before any keys are in force, a packet said to be longer than any is said as that, and is no packet that '
      'was changed under keys', () async {
    final server = PlayedServer();
    final transport =
        SSHTransport(server.socket, algorithms: PlayedServer.algorithms, onVerifyHostKey: (type, key) => true);
    addTearDown(transport.close);
    Object? endedWith;
    final ended = transport.done.then((_) {}, onError: (Object e) {
      endedWith = e;
    });
    // A version line, and four bytes that say a hundred thousand bytes follow.
    server.sendRaw([...latin1.encode('${PlayedServer.version}\r\n'), 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00]);
    await ended.timeout(PlayedServer.patience);
    expect(
      endedWith,
      isA<SSHPacketError>()
          .having((e) => e.message, 'what it says', 'Packet too long: 100000')
          .having((e) => e.damaged, 'changed on the way', isFalse),
    );
  });

  test('an error of a packet is of one that was changed on the way only where it says so', () {
    expect(SSHPacketError('Malformed packet: no length').damaged, isFalse);
    expect(SSHPacketError('x', damaged: true).damaged, isTrue);
    expect('${SSHPacketError('x', damaged: true)}', 'SSHPacketError(x)');
    // (SSH_Message_Channel_Data is what the session's output goes out as.)
    expect(SSH_Message_Channel_Data.messageId, 94);
  });
}
