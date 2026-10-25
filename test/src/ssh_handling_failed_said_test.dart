import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_service.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';

import 'played_server.dart';

/// What a connection ends with when something is thrown while what came
/// over it is handled, and the thing thrown is none of the package's own
/// errors.
///
/// Whatever it was, the connection ended as a "Malformed packet": also
/// where the packet was a good one and what failed was the client's own
/// handler of it, or something an application had asked to be told of; and
/// also where no packet had come yet, in the exchange of versions. Whoever
/// read the error went looking for what the server had sent wrong.
///
/// Now it is said by what is known of it. A packet that cannot be taken
/// off the line, or has no message in it, is a malformed packet. Once the
/// message in a packet is known by its number, what is thrown is said of
/// that message: it could not be read or handled. And what is thrown in
/// the exchange of versions is said of that.
void main() {
  /// A transport on a played server, with what the test has it do: what its
  /// connection ended with (null: it is still open after [then]).
  Future<Object?> endedWith({
    void Function(Uint8List payload)? onPacket,
    void Function(String local, String remote)? onVersionExchange,
    Future<void> Function(PlayedServer server)? then,
  }) async {
    final server = PlayedServer();
    final transport = SSHTransport(
      server.socket,
      algorithms: PlayedServer.algorithms,
      onVerifyHostKey: (type, key) => true,
      onPacket: onPacket,
      onVersionExchange: onVersionExchange,
    );
    addTearDown(transport.close);
    Object? ended;
    var over = false;
    unawaited(transport.done.then<void>((_) => over = true, onError: (Object error) {
      over = true;
      ended = error;
    }));
    // Where the client ends the connection during the exchange, the played server waits for the rest in vain.
    await server.exchangeKeys().then((_) {}, onError: (Object _) {});
    await then?.call(server);
    await server.settle();
    expect(over, ended != null, reason: 'a connection that ended did so with an error');
    return ended;
  }

  test('a packet with no message in it is a malformed packet, as before', () async {
    final ended = await endedWith(then: (server) async => server.send([Uint8List(0)]));
    expect(ended, isA<SSHPacketError>());
    expect((ended! as SSHPacketError).message, startsWith('Malformed packet: '));
    expect((ended as SSHPacketError).damaged, isFalse);

    // Also where it comes in one read with a good message before it: it is not said of that message.
    final handed = <int>[];
    final after = await endedWith(
      onPacket: (payload) => handed.add(payload[0]),
      then: (server) async => server.send([SSH_Message_Service_Accept('ssh-userauth').encode(), Uint8List(0)]),
    );
    expect(handed, [SSH_Message_Service_Accept.messageId]);
    expect(after, isA<SSHPacketError>());
    expect((after! as SSHPacketError).message, startsWith('Malformed packet: '));
  });

  test('what the handler of a good message fails with is said of that message by its number, and not as a '
      'malformed packet', () async {
    final handed = <int>[];
    final ended = await endedWith(
      onPacket: (payload) {
        handed.add(payload[0]);
        throw StateError('the application could not take it');
      },
      then: (server) async => server.send([SSH_Message_Service_Accept('ssh-userauth').encode()]),
    );
    expect(handed, [SSH_Message_Service_Accept.messageId]);
    expect(ended, isA<SSHPacketError>());
    expect((ended! as SSHPacketError).message,
        'Message 6 could not be read or handled: Bad state: the application could not take it');
    expect((ended as SSHPacketError).damaged, isFalse);
  });

  test('one of the package\'s own errors that a handler throws ends the connection as it is', () async {
    final thrown = SSHStateError('not now');
    final ended = await endedWith(
      onPacket: (payload) => throw thrown,
      then: (server) async => server.send([SSH_Message_Service_Accept('ssh-userauth').encode()]),
    );
    expect(ended, same(thrown));
  });

  test('a handler that throws nothing leaves the connection open, and is handed every message', () async {
    final handed = <int>[];
    final ended = await endedWith(
      onPacket: (payload) => handed.add(payload[0]),
      then: (server) async => server.send([
        SSH_Message_Service_Accept('ssh-userauth').encode(),
        SSH_Message_Userauth_Success().encode(),
      ]),
    );
    expect(ended, isNull);
    expect(handed, [SSH_Message_Service_Accept.messageId, SSH_Message_Userauth_Success.messageId]);
  });

  test('what is thrown in the exchange of versions is said of that: no packet has come yet', () async {
    final ended = await endedWith(
      onVersionExchange: (local, remote) => throw StateError('nobody was there to be told'),
    );
    expect(ended, isA<SSHHandshakeError>());
    expect((ended! as SSHHandshakeError).message,
        'The version exchange failed: Bad state: nobody was there to be told');
    expect((ended as SSHHandshakeError).strictOrderBroken, isFalse);
  });

  group('a client that signs in', () {
    /// A client at a played server that has taken it as far as the sign-in,
    /// with [onBanner] for what it does with a server's banner: how the
    /// sign-in ended once [server] has done what the test has it do.
    Future<Object?> signInEnded(
      void Function(PlayedServer server) then, {
      void Function(String banner)? onBanner,
    }) async {
      final server = PlayedServer();
      final client = SSHClient(
        server.socket,
        username: 'deploy',
        algorithms: PlayedServer.algorithms,
        keepAliveInterval: null,
        onUserauthBanner: onBanner,
        onPasswordRequest: () => 'not-a-real-password',
      );
      addTearDown(client.close);
      final ended = client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
      await server.greet();
      await server.next(SSH_Message_Userauth_Request.messageId);
      then(server);
      return ended.timeout(PlayedServer.patience);
    }

    test('a banner that the application cannot take: the sign-in is cut off by that, said of the banner\'s message',
        () async {
      final ended = await signInEnded(
        (server) => server.send([SSH_Message_Userauth_Banner(message: 'Welcome to web-01', language: '').encode()]),
        onBanner: (banner) => throw FormatException('this is no banner I know', banner),
      );
      expect(ended, isA<SSHAuthAbortError>());
      final reason = (ended! as SSHAuthAbortError).reason;
      expect(reason, isA<SSHPacketError>());
      expect((reason! as SSHPacketError).message,
          startsWith('Message 53 could not be read or handled: FormatException'));
    });

    test('a message that is cut short: said of that message, which could not be read', () async {
      // A refusal with nothing after its number: the list of ways the server takes is missing.
      final ended = await signInEnded((server) => server.send([
            Uint8List.fromList([SSH_Message_Userauth_Failure.messageId]),
          ]));
      expect(ended, isA<SSHAuthAbortError>());
      final reason = (ended! as SSHAuthAbortError).reason;
      expect(reason, isA<SSHPacketError>());
      expect((reason! as SSHPacketError).message, startsWith('Message 51 could not be read or handled: RangeError'));
    });

    test('a banner that the application takes: the sign-in goes on', () async {
      final banners = <String>[];
      final ended = await signInEnded(
        (server) => server.send([
          SSH_Message_Userauth_Banner(message: 'Welcome to web-01', language: '').encode(),
          SSH_Message_Userauth_Success().encode(),
        ]),
        onBanner: banners.add,
      );
      expect(ended, isNull);
      expect(banners, ['Welcome to web-01']);
    });
  });
}
