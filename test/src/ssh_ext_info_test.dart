// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_ext_info.dart';
import 'package:zest_ssh_core/src/message/msg_service.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

import 'played_server.dart';
import 'real_openssh_server.dart';

/// What a server says of itself, asked for and kept.
///
/// A server can say which kinds of signature it takes from a key that signs
/// in, and more, once its keys are in force (SSH_MSG_EXT_INFO, RFC 8308). It
/// says so to a client that asks: one that names "ext-info-c" in its first
/// proposal. The client did not ask, so it never knew, and an RSA key
/// signed in one way whatever a server takes. Had a server said it all the
/// same, the connection would have ended: the message comes right after the
/// server's NEWKEYS, while the host key is still being looked at, where the
/// client takes nothing but the four messages that may come at any time.
///
/// With a played server, which says what a test has it say; and with a real
/// OpenSSH server (the first one tool/test_sshd.sh starts, on
/// 127.0.0.1:2299), skipped where that server is not running.
void main() {
  /// SSH_MSG_EXT_INFO with the kinds of signature a server takes, and with
  /// [more] entries after it, each a name and a value.
  Uint8List says(List<String>? takes, {Map<String, String> more = const {}}) => SSH_Message_ExtInfo({
        if (takes != null) 'server-sig-algs': latin1.encode(takes.join(',')),
        for (final entry in more.entries) entry.key: latin1.encode(entry.value),
      }).encode();

  const openSsh = ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'rsa-sha2-512', 'rsa-sha2-256'];

  group('a client and a played server', () {
    /// A client on a played server: the two, and what was seen of the
    /// client. The host key is approved at once, or when [approve] says.
    (SSHTransport, PlayedServer, _Seen) start({
      bool strict = true,
      PlayedSuite? suite,
      FutureOr<bool> Function()? approve,
    }) {
      final server = PlayedServer(strict: strict, suite: suite ?? PlayedSuite.ctr);
      final seen = _Seen();
      final client = SSHTransport(
        server.socket,
        algorithms: server.speaks,
        onVerifyHostKey: (type, key) => approve == null ? true : approve(),
        onReady: () => seen.ready = true,
        onPacket: (packet) => seen.handedUp.add(packet[0]),
        onExtInfo: () => seen.told++,
        printDebug: (line) => seen.said.add('$line'),
      );
      addTearDown(client.close);
      unawaited(client.done.then<void>((_) {
        seen.ended = true;
      }, onError: (Object error) {
        seen.ended = true;
        seen.endedWith = error;
      }));
      return (client, server, seen);
    }

    /// Each side reads the other: a message from the server is handed up,
    /// and one from the client reaches the server.
    Future<void> expectBothRead(SSHTransport client, PlayedServer server, _Seen seen) async {
      final before = seen.handedUp.length;
      server.send([SSH_Message_Service_Accept('ssh-userauth').encode()]);
      await server.settle();
      expect(seen.handedUp.skip(before), [SSH_Message_Service_Accept.messageId]);
      client.sendPacket(SSH_Message_Service_Request('ssh-userauth').encode());
      expect(SSH_Message_Service_Request.decode(await server.next(SSH_Message_Service_Request.messageId)).serviceName,
          'ssh-userauth');
      expect((seen.ended, seen.endedWith), (false, null));
    }

    test('the first proposal asks the server to say what it has to say of itself, and no later one does', () async {
      final (_, server, seen) = start();
      await server.exchangeKeys();
      await server.rekey();
      expect(server.clientProposals, hasLength(2));
      final first = server.clientProposals[0].kexAlgorithms;
      final second = server.clientProposals[1].kexAlgorithms;
      expect(first.sublist(first.length - 2), ['ext-info-c', 'kex-strict-c-v00@openssh.com']);
      expect(second, first.sublist(0, first.length - 2), reason: 'the exchanges it has, and neither of the two names');
      expect((seen.ready, seen.ended), (true, false));
    });

    test('said right after NEWKEYS, in the same read, while the host key is still looked at: kept, handed to nobody, '
        'and the connection is made once the key is approved', () async {
      final approval = Completer<bool>();
      final (client, server, seen) = start(approve: () => approval.future);
      final exchange = server.exchangeKeys(afterNewKeys: [
        says(openSsh, more: {'ping@openssh.com': '0'}),
      ]);
      await server.settle();
      expect((seen.ready, seen.ended, seen.endedWith), (false, false, null));
      approval.complete(true);
      await exchange;
      await server.settle();
      expect((seen.ready, seen.ended, seen.endedWith), (true, false, null));
      expect(client.serverSignatureAlgorithms, openSsh);
      expect(client.serverExtensions, ['server-sig-algs', 'ping@openssh.com']);
      expect(seen.told, 1);
      expect(seen.handedUp, isEmpty);
      expect(
        seen.said,
        contains('SSHTransport: the server says of itself: server-sig-algs, ping@openssh.com; signatures it takes: '
            'ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-512, rsa-sha2-256'),
      );
      // The client says nothing of itself.
      expect(await server.sent(SSH_Message_ExtInfo.messageId), isFalse);
      await expectBothRead(client, server, seen);
      // What it holds cannot be changed by whoever is handed it.
      expect(() => client.serverSignatureAlgorithms!.add('ssh-rsa'), throwsUnsupportedError);
      expect(() => client.serverExtensions.add('another'), throwsUnsupportedError);
    });

    for (final (name, suite) in [
      ('aes256-ctr with hmac-sha2-256', PlayedSuite.ctr),
      ('aes256-ctr with hmac-sha2-256-etm', PlayedSuite.ctrEtm),
      ('aes256-cbc with hmac-sha2-256', PlayedSuite.cbc),
      ('aes256-gcm', PlayedSuite.gcm),
      ('chacha20-poly1305', PlayedSuite.chacha),
    ]) {
      for (final strict in [true, false]) {
        test('the first packet under the server\'s new keys, in one read with its NEWKEYS: $name, '
            '${strict ? 'the strict exchange' : 'no strict exchange'}', () async {
          final (client, server, seen) = start(strict: strict, suite: suite);
          await server.exchangeKeys(afterNewKeys: [says(openSsh)]);
          await server.settle();
          expect((seen.ready, seen.ended, seen.endedWith), (true, false, null));
          expect(client.serverSignatureAlgorithms, openSsh);
          expect(seen.handedUp, isEmpty);
          await expectBothRead(client, server, seen);
        });
      }
    }

    test('said in a read of its own, once the connection is ready: kept, and handed to nobody', () async {
      final (client, server, seen) = start();
      await server.exchangeKeys();
      await server.settle();
      expect(client.serverSignatureAlgorithms, isNull);
      server.send([says(openSsh)]);
      await server.settle();
      expect(client.serverSignatureAlgorithms, openSsh);
      expect(seen.told, 1);
      expect(seen.handedUp, isEmpty);
      await expectBothRead(client, server, seen);
    });

    test('a server that says nothing: nothing is known of what it takes', () async {
      final (client, server, seen) = start();
      await server.exchangeKeys();
      await server.settle();
      expect((seen.ready, seen.told), (true, 0));
      expect(client.serverSignatureAlgorithms, isNull);
      expect(client.serverExtensions, isEmpty);
    });

    test('a list with nothing in it is a server that takes no signature, which is not one that has not said',
        () async {
      final (client, server, _) = start();
      await server.exchangeKeys(afterNewKeys: [says(const [])]);
      await server.settle();
      expect(client.serverSignatureAlgorithms, isEmpty);
      expect(client.serverSignatureAlgorithms, isNotNull);
      expect(client.serverExtensions, ['server-sig-algs']);
    });

    test('said again: what it says last holds, also where that is nothing of signatures', () async {
      final (client, server, seen) = start();
      await server.exchangeKeys(afterNewKeys: [says(openSsh)]);
      await server.settle();
      expect(client.serverSignatureAlgorithms, openSsh);
      server.send([
        says(const ['rsa-sha2-256']),
      ]);
      await server.settle();
      expect(client.serverSignatureAlgorithms, ['rsa-sha2-256']);
      server.send([
        says(null, more: {'ping@openssh.com': '0'}),
      ]);
      await server.settle();
      expect(client.serverSignatureAlgorithms, isNull);
      expect(client.serverExtensions, ['ping@openssh.com']);
      expect((seen.told, seen.ended), (3, false));
      expect(seen.handedUp, isEmpty);
    });

    test('what stands where a name belongs and is none is not kept, and is in nothing the client says', () async {
      final tooLong = 'x' * 65;
      final asLongAsANameMayBe = 'y' * 64;
      final bell = String.fromCharCode(7);
      final high = String.fromCharCode(0xE9);
      final (client, server, seen) = start();
      await server.exchangeKeys(afterNewKeys: [
        says(
          ['ssh-ed25519', '', 'rsa sha2', tooLong, 'rsa-sha2-256', '${bell}rsa', 'caf$high', asLongAsANameMayBe],
          more: {'with a blank': '1', 'ping@openssh.com': '0', '$bell$bell': '2', tooLong: '3', 'caf$high': '4'},
        ),
      ]);
      await server.settle();
      expect((seen.ready, seen.endedWith), (true, null));
      expect(client.serverSignatureAlgorithms, ['ssh-ed25519', 'rsa-sha2-256', asLongAsANameMayBe]);
      expect(client.serverExtensions, ['server-sig-algs', 'ping@openssh.com']);
      final all = seen.said.join('\n');
      for (final notAName in ['rsa sha2', tooLong, bell, high, 'with a blank']) {
        expect(all, isNot(contains(notAName)));
      }
    });

    test('as many entries as a message may have are taken; one more, and one that is cut short, end the connection '
        'as any packet that cannot be read', () async {
      Uint8List entries(int count, {int said = -1}) {
        final writer = SSHMessageWriter()
          ..writeUint8(SSH_Message_ExtInfo.messageId)
          ..writeUint32(said < 0 ? count : said);
        for (var i = 0; i < count; i++) {
          writer
            ..writeUtf8('n$i')
            ..writeUtf8('');
        }
        return writer.takeBytes();
      }

      final (client, server, seen) = start();
      await server.exchangeKeys(afterNewKeys: [entries(SSH_Message_ExtInfo.maxExtensions)]);
      await server.settle();
      expect((seen.ready, seen.endedWith), (true, null));
      expect(client.serverExtensions, hasLength(1024));

      final (_, tooMany, sawTooMany) = start();
      await tooMany.exchangeKeys(afterNewKeys: [entries(1025)]).then((_) {}, onError: (Object _) {});
      await tooMany.settle();
      expect(sawTooMany.endedWith, isA<SSHPacketError>().having((e) => e.message, 'what it says', contains('1025')));

      final (cut, cutShort, sawCutShort) = start();
      await cutShort.exchangeKeys(afterNewKeys: [entries(1, said: 2)]).then((_) {}, onError: (Object _) {});
      await cutShort.settle();
      expect(sawCutShort.endedWith, isA<SSHPacketError>());
      expect(cut.serverExtensions, isEmpty);
    });

    test('said before the server\'s keys are in force, where anybody on the line can say it: not taken', () async {
      // A server that names no strict exchange, with the key approved at once: the message comes in the clear,
      // so the connection ends (it was handed up as any message nobody knows), and nothing is kept of it.
      final (client, server, seen) = start(strict: false);
      await server.exchangeKeys(beforeNewKeys: [says(openSsh)]).then((_) {}, onError: (Object _) {});
      await server.settle();
      expect(seen.endedWith, isA<SSHStateError>());
      expect('${seen.endedWith}', contains('message id 7 in the clear'));
      expect(seen.handedUp, isEmpty);
      expect((client.serverSignatureAlgorithms, seen.told), (null, 0));
      expect(client.serverExtensions, isEmpty);

      // The same while the key is still being looked at: the connection ends, as it did.
      final approval = Completer<bool>();
      final (waiting, slow, sawSlow) = start(strict: false, approve: () => approval.future);
      await slow.exchangeKeys(beforeNewKeys: [says(openSsh)]).then((_) {}, onError: (Object _) {});
      await slow.settle();
      expect(sawSlow.endedWith, isA<SSHStateError>());
      expect('${sawSlow.endedWith}', contains('message id 7 before host-key verification completed'));
      expect(waiting.serverSignatureAlgorithms, isNull);

      // And in a strict exchange it is what does not belong there.
      final (strictly, strictServer, sawStrict) = start();
      await strictServer.exchangeKeys(beforeNewKeys: [says(openSsh)]).then((_) {}, onError: (Object _) {});
      await strictServer.settle();
      expect(sawStrict.endedWith,
          isA<SSHHandshakeError>().having((e) => e.strictOrderBroken, 'the strict order broken', isTrue));
      expect(strictly.serverSignatureAlgorithms, isNull);
    });

    test('whoever signs in is told: the kinds of signature the server takes, and the names of what it said', () async {
      final server = PlayedServer();
      final client = SSHClient(server.socket, username: 'deploy', algorithms: server.speaks, keepAliveInterval: null);
      addTearDown(client.close);
      await server.exchangeKeys(afterNewKeys: [
        says(openSsh, more: {'publickey-hostbound@openssh.com': '0'}),
      ]);
      await server.next(SSH_Message_Service_Request.messageId);
      server.send([SSH_Message_Service_Accept('ssh-userauth').encode()]);
      await server.next(SSH_Message_Userauth_Request.messageId);
      server.send([SSH_Message_Userauth_Success().encode()]);
      await client.authenticated;
      expect(client.serverSignatureAlgorithms, openSsh);
      expect(client.diagnostics.serverExtensions, ['server-sig-algs', 'publickey-hostbound@openssh.com']);

      final silent = await PlayedServer.signedIn();
      addTearDown(silent.client.close);
      expect(silent.client.serverSignatureAlgorithms, isNull);
      expect(silent.client.diagnostics.serverExtensions, isEmpty);
    });
  });

  group('the message', () {
    test('is read as it is written, and says of itself the names it has', () {
      final message = SSH_Message_ExtInfo.decode(says(openSsh, more: {'ping@openssh.com': '0'}));
      expect(message.extensions.keys, ['server-sig-algs', 'ping@openssh.com']);
      expect(latin1.decode(message.extensions['ping@openssh.com']!), '0');
      expect(message.serverSignatureAlgorithms, openSsh);
      expect(message.names, ['server-sig-algs', 'ping@openssh.com']);
      expect(message.encode().first, 7);
      expect(message.encode(), says(openSsh, more: {'ping@openssh.com': '0'}));
      expect('$message', 'SSH_Message_ExtInfo(server-sig-algs, ping@openssh.com)');
      expect(SSH_Message_ExtInfo.decode(says(null)).serverSignatureAlgorithms, isNull);
      expect(SSH_Message_ExtInfo.decode(says(null)).names, isEmpty);
    });

    test('says of itself only what is a name', () {
      final message = SSH_Message_ExtInfo({
        'server-sig-algs': latin1.encode('ssh-ed25519'),
        'with a blank': latin1.encode('1'),
        'ping@openssh.com': latin1.encode('0'),
      });
      expect('$message', 'SSH_Message_ExtInfo(server-sig-algs, ping@openssh.com)');
      expect('${SSH_Message_ExtInfo.decode(message.encode())}', 'SSH_Message_ExtInfo(server-sig-algs, ping@openssh.com)');
    });

    test('a name that comes twice has the value that came last', () {
      final twice = (SSHMessageWriter()
            ..writeUint8(7)
            ..writeUint32(2)
            ..writeUtf8('server-sig-algs')
            ..writeUtf8('ssh-rsa')
            ..writeUtf8('server-sig-algs')
            ..writeUtf8('rsa-sha2-512'))
          .takeBytes();
      expect(SSH_Message_ExtInfo.decode(twice).serverSignatureAlgorithms, ['rsa-sha2-512']);
      expect(SSH_Message_ExtInfo.decode(twice).names, ['server-sig-algs']);
    });

    test('what a name is: one to sixty-four printable characters of US-ASCII, with no blank and no comma', () {
      for (final name in ['a', 'ssh-ed25519', 'sk-ssh-ed25519@openssh.com', '!', '~', 'y' * 64]) {
        expect(SSH_Message_ExtInfo.isName(name), isTrue, reason: name);
      }
      for (final notAName in [
        '',
        'y' * 65,
        'rsa sha2',
        'a,b',
        'a${String.fromCharCode(0x7F)}',
        'a${String.fromCharCode(0x1F)}',
        'a${String.fromCharCode(0x80)}',
        'a\tb',
      ]) {
        expect(SSH_Message_ExtInfo.isName(notAName), isFalse, reason: notAName.codeUnits.toString());
      }
    });
  });

  group('a real OpenSSH server', () {
    final real = RealOpenSshServer.fromEnvironment();
    String? unavailable;

    setUpAll(() async => unavailable = await real.unavailable());

    test('says which kinds of signature it takes, the two of RSA with SHA-2 among them, and is signed in to',
        () async {
      if (unavailable != null) return markTestSkipped(unavailable!);
      final client = SSHClient(
        await SSHSocket.connect(real.host, real.port, timeout: const Duration(seconds: 5)),
        username: real.user,
        identities: SSHKeyPair.fromPem(File(real.keyPath).readAsStringSync()),
      );
      addTearDown(client.close);
      await client.authenticated.timeout(const Duration(seconds: 20));
      expect(client.serverSignatureAlgorithms, containsAll(['ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256']));
      expect(client.diagnostics.serverExtensions, contains('server-sig-algs'));
      expect(utf8.decode(await client.run('echo signed-in')), contains('signed-in'));
    }, timeout: const Timeout(Duration(seconds: 60)));
  });
}

/// What was seen of a client.
class _Seen {
  var ready = false;
  var ended = false;
  Object? endedWith;

  /// The numbers of the messages it handed up.
  final handedUp = <int>[];

  /// How often it said that the server has said something of itself.
  var told = 0;

  /// Its debug lines.
  final said = <String>[];
}
