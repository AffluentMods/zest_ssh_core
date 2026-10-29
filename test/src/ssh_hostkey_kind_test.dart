// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ecdsa.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ed25519.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

import 'played_server.dart';

/// A host key is of the kind that was agreed on, or it is refused.
///
/// The two sides agree on the kind of host key the server will show (RFC
/// 4253, 7.1), and the client takes no other. This transport read whatever
/// key came by what was agreed on, and that held it to the kind only as far
/// as reading went: an ECDSA key is read the same for each of its three
/// curves, so a server that had agreed on one curve was taken with a key of
/// another, and a client that leaves a curve out of what it offers was shown
/// a key of that curve all the same. A key of another kind altogether did
/// not read, and ended the connection as a "Malformed packet" with the
/// words of whatever failed inside, where a host key of the wrong kind is a
/// host key that is refused. The same for a signature that says it is of
/// another kind than its key, and for bytes that are no key at all.
///
/// With a server played by the test, which shows the key and the signature a
/// test gives it under the name it is told to agree on.
void main() {
  /// What a client here offers for the kind of host key: all of them.
  const everyKind = [
    SSHHostkeyType.ed25519,
    SSHHostkeyType.rsaSha512,
    SSHHostkeyType.rsaSha256,
    SSHHostkeyType.ecdsa521,
    SSHHostkeyType.ecdsa384,
    SSHHostkeyType.ecdsa256,
  ];

  SSHKeyPair fromFile(String path) => SSHKeyPair.fromPem(File('test/fixtures/$path').readAsStringSync()).single;

  final ed25519 = fromFile('ssh-ed25519/ssh_host_ed25519_key');
  final rsa = fromFile('ssh-rsa/ssh_host_rsa_key');
  final ecdsa = {
    for (final curve in ['nistp256', 'nistp384', 'nistp521'])
      'ecdsa-sha2-$curve': fromFile('ecdsa-sha2-$curve/ssh_host_ecdsa_key'),
  };

  /// A transport that is shown [hostKey] by a played server: how its
  /// connection ended, whether anybody was asked about the key, whether it
  /// said the connection was ready, and what it sent after its proposal and
  /// its start of the exchange.
  Future<({Object? endedWith, int asked, int ready, List<int> sentAfter})> shown(PlayedHostKey hostKey,
      {List<SSHHostkeyType> offered = everyKind}) async {
    final server = PlayedServer(hostKey: hostKey);
    var asked = 0;
    var ready = 0;
    final transport = SSHTransport(
      server.socket,
      algorithms: SSHAlgorithms(
        kex: const [SSHKexType.x25519],
        hostkey: offered,
        cipher: const [SSHCipherType.aes256ctr],
        mac: const [SSHMacType.hmacSha256],
      ),
      onVerifyHostKey: (type, key) {
        asked++;
        return true;
      },
      onReady: () => ready++,
    );
    addTearDown(transport.close);
    Object? endedWith;
    final ended = transport.done.then((_) {}, onError: (Object e) {
      endedWith = e;
    });
    // The played server waits for the client's NEWKEYS, which does not come
    // where the key is refused: the client's end of the connection is what
    // is waited for then.
    final exchanged = server.exchangeKeys().then((_) => true, onError: (Object _) => false);
    if (await Future.any([exchanged, ended.then((_) => false)])) {
      await server.settle();
    } else {
      await ended.timeout(PlayedServer.patience);
    }
    return (
      endedWith: endedWith,
      asked: asked,
      ready: ready,
      sentAfter: [
        for (final payload in server.takeSent())
          if (payload[0] != SSH_Message_KexInit.messageId) payload[0],
      ],
    );
  }

  Matcher refusedSaying(List<String> words) => isA<SSHHostkeyError>()
      .having((e) => e.message, 'what it says', allOf([for (final word in words) contains(word)]));

  void expectRefused(({Object? endedWith, int asked, int ready, List<int> sentAfter}) outcome, List<String> words) {
    expect(outcome.endedWith, refusedSaying(words));
    expect(outcome.asked, 0, reason: 'a key that is refused is not put to anybody');
    expect(outcome.ready, 0);
    expect(outcome.sentAfter, isEmpty, reason: 'no NEWKEYS for a key that was refused');
  }

  group('a key of the kind that was agreed on is taken', () {
    for (final (pair, agreed) in [
      (ed25519, 'ssh-ed25519'),
      (rsa, 'rsa-sha2-256'),
      for (final entry in ecdsa.entries) (entry.value, entry.key),
    ]) {
      test(agreed, () async {
        final outcome = await shown(PlayedHostKey.of(pair, algorithm: agreed));
        expect(outcome.endedWith, isNull);
        expect(outcome.asked, 1);
        expect(outcome.ready, 1);
      });
    }
  });

  group('an ECDSA key of another curve than the one agreed on is refused', () {
    for (final agreed in ecdsa.keys) {
      for (final other in ecdsa.keys.where((curve) => curve != agreed)) {
        test('$agreed agreed on, a key of $other shown, which signs as its own kind does', () async {
          expectRefused(await shown(PlayedHostKey.of(ecdsa[other]!, algorithm: agreed)), [other, agreed]);
          expect(
            ((await shown(PlayedHostKey.of(ecdsa[other]!, algorithm: agreed))).endedWith as SSHHostkeyError).message,
            'The server showed a host key of the kind "$other", and "$agreed" was agreed on',
          );
        });
      }
    }

    test('a client that offers one curve only is not shown a key of another under its name', () async {
      final outcome = await shown(
        PlayedHostKey.of(ecdsa['ecdsa-sha2-nistp256']!, algorithm: 'ecdsa-sha2-nistp521'),
        offered: const [SSHHostkeyType.ecdsa521],
      );
      expectRefused(outcome, ['ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp521']);
    });
  });

  group('a key of another kind altogether is refused as that', () {
    for (final (pair, itsKind, agreed) in [
      (rsa, 'ssh-rsa', 'ssh-ed25519'),
      (ed25519, 'ssh-ed25519', 'rsa-sha2-256'),
      (ed25519, 'ssh-ed25519', 'ecdsa-sha2-nistp256'),
      (rsa, 'ssh-rsa', 'ecdsa-sha2-nistp384'),
      (ecdsa['ecdsa-sha2-nistp256']!, 'ecdsa-sha2-nistp256', 'ssh-ed25519'),
      (ecdsa['ecdsa-sha2-nistp521']!, 'ecdsa-sha2-nistp521', 'rsa-sha2-512'),
    ]) {
      test('$agreed agreed on, a key of the kind $itsKind shown', () async {
        // An RSA key is "ssh-rsa" under each of the three names an RSA signature has.
        final agreedKind = agreed.startsWith('rsa-sha2-') ? 'ssh-rsa' : agreed;
        expectRefused(await shown(PlayedHostKey.of(pair, algorithm: agreed)), [itsKind, agreedKind]);
      });
    }
  });

  group('a signature that says it is of another kind than its key is refused', () {
    test('an ECDSA key of the curve agreed on, with a signature under another curve\'s name', () async {
      final pair = ecdsa['ecdsa-sha2-nistp256']!;
      final key = PlayedHostKey('ecdsa-sha2-nistp256', pair.toPublicKey().encode(), (hash) {
        final own = SSHEcdsaSignature.decode(pair.sign(hash).encode());
        return SSHEcdsaSignature('ecdsa-sha2-nistp384', own.r, own.s).encode();
      });
      expectRefused(await shown(key), ['signature', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp256']);
    });

    test('an Ed25519 key with a signature under another name', () async {
      final key = PlayedHostKey('ssh-ed25519', ed25519.toPublicKey().encode(), (hash) {
        final own = SSHEd25519Signature.decode(ed25519.sign(hash).encode());
        return (SSHMessageWriter()
              ..writeUtf8('ssh-rsa')
              ..writeString(own.signature))
            .takeBytes();
      });
      expectRefused(await shown(key), ['signature']);
    });
  });

  // A key of the right kind that did not sign this exchange is the one thing
  // a host key is there to tell: it is said as that, whatever the library
  // that checks the signature does to say no.
  group('a signature that is not the key\'s own of this exchange is refused as that', () {
    for (final (pair, agreed) in [
      (ed25519, 'ssh-ed25519'),
      (rsa, 'rsa-sha2-256'),
      for (final entry in ecdsa.entries) (entry.value, entry.key),
    ]) {
      test('$agreed: the key\'s signature of something else', () async {
        final key = PlayedHostKey(agreed, pair.toPublicKey().encode(),
            (hash) => pair.sign(Uint8List.fromList(hash.reversed.toList())).encode());
        expectRefused(await shown(key), ['Signature verification failed']);
      });
    }

    test('an Ed25519 signature of the right length that is no signature, and one of ten bytes', () async {
      for (final bytes in [Uint8List(64)..fillRange(0, 64, 0x5A), Uint8List(10)]) {
        final key = PlayedHostKey('ssh-ed25519', ed25519.toPublicKey().encode(),
            (hash) => SSHEd25519Signature(bytes).encode());
        expectRefused(await shown(key), ['Signature verification failed']);
      }
    });

    test('an RSA signature under another of its three names than the one agreed on: refused for its kind',
        () async {
      final key = PlayedHostKey('rsa-sha2-512', rsa.toPublicKey().encode(), (hash) => rsa.sign(hash).encode());
      // (The key pair signs under rsa-sha2-256.)
      expectRefused(await shown(key), ['signature', 'rsa-sha2-256', 'rsa-sha2-512']);
    });
  });

  group('bytes that are no key are refused as a host key that could not be read', () {
    for (final (blob, what) in [
      (Uint8List(0), 'nothing'),
      (Uint8List.fromList([0, 0, 0]), 'three bytes'),
      (Uint8List.fromList([0, 0, 0, 200, 1, 2, 3]), 'a name that is said to be longer than what follows'),
      ((SSHMessageWriter()..writeUtf8('ssh-ed25519')).takeBytes(), 'the name of a kind and nothing after it'),
      (
        (SSHMessageWriter()
              ..writeUtf8('ssh-ed25519')
              ..writeString(Uint8List(7)))
            .takeBytes(),
        'an Ed25519 key of seven bytes'
      ),
    ]) {
      test(what, () async {
        final outcome = await shown(PlayedHostKey('ssh-ed25519', blob, (hash) => ed25519.sign(hash).encode()));
        expectRefused(outcome, ['The host key or its signature could not be read']);
      });
    }
  });

  test('the kind a key says it is of is a server\'s own text: said with nothing in it that is no letter of a name, '
      'and no longer than a name is', () async {
    final escape = String.fromCharCode(0x1b);
    final name = 'ssh-$escape[31med25519\r\n${'x' * 300}';
    final blob = (SSHMessageWriter()
          ..writeString(Uint8List.fromList(utf8.encode(name)))
          ..writeString(Uint8List(32)))
        .takeBytes();
    final outcome = await shown(PlayedHostKey('ssh-ed25519', blob, (hash) => ed25519.sign(hash).encode()));
    expect(outcome.endedWith, isA<SSHHostkeyError>());
    final said = (outcome.endedWith as SSHHostkeyError).message;
    expect(said, isNot(contains(escape)));
    expect(said, isNot(contains('\r')));
    expect(said, isNot(contains('\n')));
    expect(said.length, lessThan(240));
    expect(said, contains('ssh-ed25519'), reason: 'the kind that was agreed on is said');
  });
}
