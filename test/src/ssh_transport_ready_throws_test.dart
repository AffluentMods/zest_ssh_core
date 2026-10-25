import 'dart:async';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

import 'played_failing_socket.dart';
import 'played_server.dart';

/// What is thrown once a host's key was approved ends the connection.
///
/// When the key a server showed is approved, the transport sends its
/// NEWKEYS, puts its own keys in force and says that the connection is
/// ready; whoever holds it then sends its first request. All of that runs
/// in what follows the approval, which may come much later than the
/// server's answer (a person was asked). What was thrown there had nowhere
/// to go: the write of NEWKEYS failing on a socket that had gone, or the
/// first request not going out. It ended up as an error nobody had asked
/// for, with the connection left open: whoever waited for the sign-in
/// waited until their own patience ran out, and was told nothing of why.
///
/// With a played server, and a client that fails in each of those places.
void main() {
  /// A client on a played server through its first exchange, with [onReady]
  /// for what it does once the connection is ready and [through] for the
  /// socket it writes to: what its connection ended with (null with [ended]
  /// false: it is still open), and what was thrown into nowhere meanwhile.
  Future<({bool ended, Object? endedWith, List<Object> intoNowhere})> exchanged({
    void Function()? onReady,
    SSHSocket Function(SSHSocket socket)? through,
  }) async {
    final server = PlayedServer();
    final intoNowhere = <Object>[];
    var ended = false;
    Object? endedWith;
    final played = Completer<void>();
    runZonedGuarded(() async {
      final client = SSHTransport(
        through?.call(server.socket) ?? server.socket,
        algorithms: PlayedServer.algorithms,
        onVerifyHostKey: (type, key) => true,
        onReady: onReady,
      );
      addTearDown(client.close);
      unawaited(client.done.then<void>((_) {
        ended = true;
      }, onError: (Object error) {
        ended = true;
        endedWith = error;
      }));
      // Where the client's NEWKEYS does not come, the played server waits for it in vain.
      await server.exchangeKeys().then((_) {}, onError: (Object _) {});
      await server.settle();
      played.complete();
    }, (error, stack) => intoNowhere.add(error));
    await played.future.timeout(PlayedServer.patience * 2);
    return (ended: ended, endedWith: endedWith, intoNowhere: intoNowhere);
  }

  test('nothing thrown: the connection is ready and open', () async {
    var ready = 0;
    final outcome = await exchanged(onReady: () => ready++);
    expect((ready, outcome.ended), (1, false));
    expect(outcome.intoNowhere, isEmpty);
  });

  test('what whoever holds the connection throws when it is told that it is ready ends the connection, with what '
      'was thrown in the words', () async {
    final outcome = await exchanged(onReady: () => throw StateError('the first request could not go out'));
    expect(outcome.intoNowhere, isEmpty, reason: 'it was thrown into nowhere');
    expect(outcome.ended, isTrue, reason: 'the connection was left open');
    expect(
      outcome.endedWith,
      isA<SSHStateError>().having((e) => e.message, 'what it says', contains('the first request could not go out')),
    );
  });

  test('an error of this package\'s own, thrown there, ends the connection as it is', () async {
    final thrown = SSHStateError('Transport is closed');
    final outcome = await exchanged(onReady: () => throw thrown);
    expect(outcome.intoNowhere, isEmpty);
    expect(outcome.endedWith, same(thrown));
  });

  test('the write of NEWKEYS failing on a socket that has gone ends the connection, and it is not said to be '
      'ready', () async {
    var ready = 0;
    // The client writes its version, its proposal and its start of the exchange; the fourth write is its NEWKEYS.
    final outcome = await exchanged(
      onReady: () => ready++,
      through: (socket) => WritesFail(socket, from: 4),
    );
    expect(outcome.intoNowhere, isEmpty, reason: 'it was thrown into nowhere');
    expect(outcome.ended, isTrue, reason: 'the connection was left open');
    expect(outcome.endedWith,
        isA<SSHStateError>().having((e) => e.message, 'what it says', contains(WritesFail.said)));
    expect(ready, 0);
  });
}
