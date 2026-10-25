import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_request.dart';

import 'played_openssh_client.dart';
import 'played_server.dart';

/// The played server speaks what OpenSSH speaks.
///
/// Tests of this package play a server to its client (played_server.dart),
/// for what no real server can be made to do. What such a test shows is only
/// as true as the played server's own reading of the protocol, so here the
/// played server is held to a client that was not written with it: the
/// OpenSSH client of the machine. For each suite the played server can
/// speak, with the strict key exchange and without it, the OpenSSH client
/// goes through a key exchange with it, signs in, has a command run and is
/// told how it ended: each side reads what the other sends. And it is asked
/// for new keys under another suite: it sends its part of that exchange as
/// it sent everything before, and what follows under what was agreed on.
///
/// The client signs in with nothing (the way called "none", which the played
/// server accepts), and looks at no key and no file of whoever runs the
/// tests: its own account of what it did is checked for that. Where a
/// machine has no OpenSSH client these tests are skipped.
void main() {
  final clients = OpenSshClient.found();
  if (clients.isEmpty) {
    test('the played server speaks what OpenSSH speaks', () {}, skip: 'this machine has no OpenSSH client');
    return;
  }

  const suites = [PlayedSuite.ctr, PlayedSuite.ctrEtm, PlayedSuite.cbc, PlayedSuite.gcm, PlayedSuite.chacha];

  /// The client signs in and asks for its command, which the server starts.
  Future<PlayedChannel> commandStarted(OpenSshRun run) async {
    await run.server.letIn();
    final channel = await run.server.confirmChannel();
    final asked = await channel.nextRequest();
    expect(asked.requestType, 'exec');
    run.server.send([channel.success]);
    return channel;
  }

  /// The client is asked something, and its answer is read: each side reads
  /// the other under the keys in force now. Then it is told that its command
  /// ended well, and ends well itself, having found no fault with anything
  /// it was sent.
  ///
  /// (What the client says last, that it closes its channel and leaves, is
  /// not waited for: a connection that its other end closes right after can
  /// lose that on the way, and now and then it did.)
  Future<void> endedWell(OpenSshRun run, PlayedChannel channel) async {
    run.server.send([SSH_Message_Global_Request(requestName: 'keepalive@openssh.com', wantReply: true).encode()]);
    await run.server.next(SSH_Message_Request_Failure.messageId);
    run.server.send([channel.exitStatus(0), channel.eof, channel.close]);
    expect(await run.exitCode, 0, reason: run.said.join('\n'));
    expect(run.said, contains(contains('Exit status 0')));
    expect(run.lookedAtOthersKeys, 0, reason: 'the client looked at a key that is not of the run');
  }

  for (final client in clients) {
    group('the OpenSSH client $client', () {
      OpenSshRun? run;
      tearDown(() async => run?.end());

      for (final strict in [true, false]) {
        final how = strict ? 'the strict exchange' : 'no strict exchange';

        for (final suite in suites) {
          test('$suite, $how: the two read each other, from the key exchange to the end of a command', () async {
            final ours = run = await client.connect(offers: [suite], suite: suite, strict: strict);
            final channel = await commandStarted(ours);
            expect(ours.agreedOn, (toServer: suite.cipher.name, toClient: suite.cipher.name));
            await endedWell(ours, channel);
          }, skip: client.speaks([suite]) ? null : 'this client does not have ${suite.cipher.name}');
        }

        for (final from in suites) {
          for (final to in suites) {
            if (identical(from, to)) continue;
            test('$from, then new keys under $to, $how: the client\'s part of the exchange comes as before, '
                'and what follows under the new', () async {
              final ours = run = await client.connect(offers: [from, to], suite: from, strict: strict);
              final channel = await commandStarted(ours);
              await ours.server.rekey(suite: to);
              expect(ours.agreedOn, (toServer: to.cipher.name, toClient: to.cipher.name));
              await endedWell(ours, channel);
            }, skip: client.speaks([from, to]) ? null : 'this client does not have both');
          }
        }

        test('one suite for what the client sends and another for what it is sent, then the two the other way '
            'round, $how', () async {
          final ours = run = await client.connect(
              offers: [PlayedSuite.chacha, PlayedSuite.ctrEtm],
              suite: PlayedSuite.chacha,
              toClient: PlayedSuite.ctrEtm,
              strict: strict);
          final channel = await commandStarted(ours);
          expect(ours.agreedOn, (toServer: PlayedSuite.chacha.cipher.name, toClient: PlayedSuite.ctrEtm.cipher.name));
          await ours.server.rekey(suite: PlayedSuite.ctrEtm, toClient: PlayedSuite.chacha);
          expect(ours.agreedOn, (toServer: PlayedSuite.ctrEtm.cipher.name, toClient: PlayedSuite.chacha.cipher.name));
          await endedWell(ours, channel);
        }, skip: client.speaks([PlayedSuite.chacha, PlayedSuite.ctrEtm]) ? null : 'this client does not have both');

        test('new keys four times over, $how: each time under what was agreed on then', () async {
          const order = [PlayedSuite.gcm, PlayedSuite.chacha, PlayedSuite.ctr, PlayedSuite.gcm];
          final ours = run = await client.connect(offers: order, suite: order.first, strict: strict);
          final channel = await commandStarted(ours);
          for (final suite in order.skip(1)) {
            await ours.server.rekey(suite: suite);
            expect(ours.agreedOn.toServer, suite.cipher.name);
          }
          // And once more under the same suite, which is what a server does.
          await ours.server.rekey();
          await endedWell(ours, channel);
        }, skip: client.speaks([PlayedSuite.gcm, PlayedSuite.chacha, PlayedSuite.ctr]) ? null : 'this client does not have all');
      }
    });
  }
}
