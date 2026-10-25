import 'dart:async';

import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_errors.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:test/test.dart';

/// A request on a channel that asked for a reply waited for it for ever when
/// the channel ended first: the connection dropped, or the server closed the
/// channel without answering. Whoever had asked (for a terminal, a shell, a
/// command, a subsystem) never heard anything again, and whatever waited on
/// them hung. Such a request now ends with an error when its channel does,
/// and the error says which of the two it was.
void main() {
  /// A channel as the client makes one, and what it sent.
  (SSHChannelController, List<SSHMessage>) make() {
    final sent = <SSHMessage>[];
    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 32768,
      localInitialWindowSize: 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 32768,
      remoteInitialWindowSize: 1024,
      sendMessage: sent.add,
    );
    return (controller, sent);
  }

  /// How [asked] ended, or 'waiting' when it has not after a moment.
  Future<Object?> endOf(Future<bool> asked) =>
      asked.then<Object?>((answer) => answer, onError: (Object e) => e).timeout(
            const Duration(milliseconds: 300),
            onTimeout: () => 'waiting',
          );

  /// A request that failed because the server closed its channel.
  final closedUnanswered = isA<SSHChannelRequestError>()
      .having((e) => e.message, 'message', 'The channel closed before the request was answered');

  test('a request is answered as before: yes, no, each in its turn', () async {
    final (controller, sent) = make();
    final pty = controller.sendPtyReq();
    final shell = controller.sendShell();
    expect(sent.whereType<SSH_Message_Channel_Request>(), hasLength(2));
    controller.handleMessage(SSH_Message_Channel_Success(recipientChannel: 1));
    controller.handleMessage(SSH_Message_Channel_Failure(recipientChannel: 1));
    expect(await endOf(pty), isTrue);
    expect(await endOf(shell), isFalse);
    controller.destroy();
  });

  test('an X11 request carries the screen it was asked for, as a number', () async {
    final (controller, sent) = make();
    final asked = controller.sendX11Req(authenticationCookie: '00112233445566778899aabbccddeeff', screenNumber: 3);
    final request = sent.whereType<SSH_Message_Channel_Request>().single;
    expect(request.requestType, 'x11-req');
    expect(request.x11ScreenNumber, 3);
    expect(request.wantReply, isTrue);
    controller.handleMessage(SSH_Message_Channel_Failure(recipientChannel: 1));
    expect(await endOf(asked), isFalse);
    controller.destroy();
  });

  test('the connection ended: every request still waiting ends with what ended it', () async {
    final (controller, _) = make();
    final asked = [
      ('a terminal', controller.sendPtyReq()),
      ('a shell', controller.sendShell()),
      ('a command', controller.sendExec('uptime')),
      ('an environment variable', controller.sendEnv('LANG', 'C')),
      ('X11 forwarding', controller.sendX11Req(authenticationCookie: '00112233445566778899aabbccddeeff')),
      ('agent forwarding', controller.sendAgentForwardingRequest()),
      ('a subsystem', controller.sendSubsystem('sftp')),
    ];
    // (What the client does with each of its channels when the transport ends.)
    final ended = SSHSocketError('Connection reset by peer');
    controller.destroy(ended);
    for (final (what, wait) in asked) {
      expect(await endOf(wait), same(ended), reason: what);
    }
    // And so does one made later, of which nothing is sent.
    expect(await endOf(controller.sendShell()), same(ended));
  });

  test('the server closes the channel without answering: a request that failed, the connection being there',
      () async {
    final (controller, _) = make();
    final subsystem = controller.sendSubsystem('sftp');
    controller.handleMessage(SSH_Message_Channel_Close(recipientChannel: 1));
    expect(await endOf(subsystem), closedUnanswered);
  });

  test('torn down from this side with a request waiting: the same', () async {
    final (controller, _) = make();
    final shell = controller.sendShell();
    controller.destroy();
    expect(await endOf(shell), closedUnanswered);
  });

  test('closed from this side, a request waits until the server has closed too, and ends then', () async {
    final (controller, _) = make();
    final shell = controller.sendShell();
    unawaited(controller.close());
    expect(await endOf(shell), 'waiting', reason: 'the server may still answer');
    controller.handleMessage(SSH_Message_Channel_Close(recipientChannel: 1));
    expect(await endOf(shell), closedUnanswered);
  });

  test('a request answered before the channel ended keeps its answer', () async {
    final (controller, _) = make();
    final shell = controller.sendShell();
    controller.handleMessage(SSH_Message_Channel_Success(recipientChannel: 1));
    controller.destroy();
    expect(await endOf(shell), isTrue);
  });

  test('a request made after the channel ended fails at once, and nothing is sent for a channel that is gone',
      () async {
    final (controller, sent) = make();
    controller.destroy();
    final before = sent.length;
    final closed = isA<SSHStateError>().having((e) => e.message, 'message', 'Channel is closed');
    expect(await endOf(controller.sendShell()), closed);
    expect(await endOf(controller.sendEnv('LANG', 'C')), closed);
    expect(sent, hasLength(before));
  });

  test('a channel the server closes still ends as it did: its stream is done, and so is the channel', () async {
    final (controller, sent) = make();
    final drained = controller.channel.stream.drain<void>();
    controller.handleMessage(SSH_Message_Channel_Close(recipientChannel: 1));
    await drained.timeout(const Duration(seconds: 2));
    await controller.channel.done.timeout(const Duration(seconds: 2));
    expect(sent.whereType<SSH_Message_Channel_Close>(), hasLength(1), reason: 'our own close answers theirs');
  });

  test('an answer nobody waits for any more is dropped, and ends nothing', () async {
    final (controller, _) = make();
    final shell = controller.sendShell();
    controller.destroy();
    expect(await endOf(shell), closedUnanswered);
    // (It was on its way when the channel ended.)
    expect(() => controller.handleMessage(SSH_Message_Channel_Success(recipientChannel: 1)), returnsNormally);
  });

  test('torn down twice, the first reason stands', () async {
    final (controller, _) = make();
    final shell = controller.sendShell();
    final ended = SSHSocketError('Connection reset by peer');
    controller
      ..destroy(ended)
      ..destroy(SSHStateError('later'));
    expect(await endOf(shell), same(ended));
    expect(await endOf(controller.sendShell()), same(ended));
  });
}
