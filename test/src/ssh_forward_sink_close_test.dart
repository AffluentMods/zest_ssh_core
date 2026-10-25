import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_forward.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// A forwarded connection has two ways, and each ends by itself: whoever
/// has sent all it has says so by closing [SSHForwardChannel.sink], and can
/// still be sent what the other side has. Whoever hands such a connection
/// on has to know when its own end is over, since ending the channel before
/// that cuts off what was still waiting to be sent. Closing the sink says
/// when: its future completes once everything written before has been sent.
void main() {
  /// A forwarded channel as the client makes one, where the other side
  /// takes [remoteWindow] bytes to begin with, and what it sent.
  (SSHChannelController, SSHForwardChannel, List<SSHMessage>) make({int remoteWindow = 1000}) {
    final sent = <SSHMessage>[];
    final controller = SSHChannelController(
      localId: 1,
      localMaximumPacketSize: 32768,
      localInitialWindowSize: 1024,
      remoteId: 2,
      remoteMaximumPacketSize: 32768,
      remoteInitialWindowSize: remoteWindow,
      sendMessage: sent.add,
    );
    addTearDown(controller.destroy);
    return (controller, SSHForwardChannel(controller.channel), sent);
  }

  int bytesIn(List<SSHMessage> sent) =>
      sent.whereType<SSH_Message_Channel_Data>().fold(0, (sum, message) => sum + message.data.length);

  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 20));

  /// Waits until [holds], for no longer than five seconds.
  Future<void> until(bool Function() holds) async {
    final clock = Stopwatch()..start();
    while (!holds() && clock.elapsed < const Duration(seconds: 5)) {
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
  }

  test('closing the sink is over when everything written has been sent, and not while some of it waits for the '
      'other side to take more; then the other side is told that no more comes', () async {
    final (controller, channel, sent) = make();
    channel.sink.add(Uint8List(1200));
    channel.sink.add(Uint8List(1200));
    channel.sink.add(Uint8List(600));
    var sentWhenClosed = -1;
    final closed = channel.sink.close().then((_) => sentWhenClosed = bytesIn(sent));

    // The other side takes a thousand bytes, and no more for now.
    await until(() => bytesIn(sent) == 1000);
    await settle();
    expect(bytesIn(sent), 1000);
    expect(sent.whereType<SSH_Message_Channel_EOF>(), isEmpty);
    expect(sentWhenClosed, -1, reason: 'two thousand bytes still wait');

    // It takes a little more: still not all of it.
    controller.handleMessage(SSH_Message_Channel_Window_Adjust(recipientChannel: 1, bytesToAdd: 500));
    await until(() => bytesIn(sent) == 1500);
    await settle();
    expect(bytesIn(sent), 1500);
    expect(sentWhenClosed, -1);

    // And then the rest.
    controller.handleMessage(SSH_Message_Channel_Window_Adjust(recipientChannel: 1, bytesToAdd: 5000));
    await closed.timeout(const Duration(seconds: 5));
    expect(sentWhenClosed, 3000, reason: 'all of it had been sent when the close was over');
    await until(() => sent.last is SSH_Message_Channel_EOF);
    expect(bytesIn(sent), 3000);
    expect(sent.last, isA<SSH_Message_Channel_EOF>());
    await settle();

    // The channel itself goes on: the other side has not said that it is done.
    expect(sent.whereType<SSH_Message_Channel_Close>(), isEmpty);
  });

  test('with nothing in the way, too: all of it has been sent by the time closing the sink is over, so a channel '
      'that is ended right then has cut nothing off', () async {
    final (controller, channel, sent) = make(remoteWindow: 1 << 20);
    for (final size in [1200, 40000, 400000, 600]) {
      channel.sink.add(Uint8List(size));
    }
    await channel.sink.close().timeout(const Duration(seconds: 5));
    controller.destroy();
    expect(bytesIn(sent), 1200 + 40000 + 400000 + 600);
    // Ending it says that no more comes, and closes the channel.
    expect(sent.whereType<SSH_Message_Channel_EOF>(), hasLength(1));
    expect(sent.last, isA<SSH_Message_Channel_Close>());
  });

  test('nothing was written: the other side is told that no more comes', () async {
    final (_, channel, sent) = make();
    await channel.sink.close().timeout(const Duration(seconds: 5));
    await until(() => sent.isNotEmpty);
    expect(sent.single, isA<SSH_Message_Channel_EOF>());
  });

  test('a channel that ends while some of it waits: closing the sink is over then', () async {
    // Ended from this side.
    final (controller, channel, _) = make();
    channel.sink.add(Uint8List(5000));
    await settle();
    final closed = channel.sink.close();
    controller.destroy();
    await closed.timeout(const Duration(seconds: 5));

    // Closed by the other side.
    final (controller2, channel2, _) = make();
    channel2.sink.add(Uint8List(5000));
    await settle();
    final closed2 = channel2.sink.close();
    controller2.handleMessage(SSH_Message_Channel_Close(recipientChannel: 1));
    await closed2.timeout(const Duration(seconds: 5));
  });
}
