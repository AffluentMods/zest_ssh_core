import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:test/test.dart';

/// Regression tests from the 1.8.2 security audit: channel teardown and
/// flow-control hardening. Both are availability findings (no crypto or trust
/// impact) that the audit established with throwaway probes; these make them
/// permanent.
void main() {
  group('destroy() on a dead transport (audit: leaked done futures)', () {
    test('completes done and does not throw when the EOF send fails',
        () async {
      // Simulates an unexpected disconnect: the transport is already closed
      // by the time SSHClient tears its channels down, so every send throws.
      final controller = SSHChannelController(
        localId: 1,
        localMaximumPacketSize: 1024,
        localInitialWindowSize: 1024,
        remoteId: 2,
        remoteMaximumPacketSize: 1024,
        remoteInitialWindowSize: 1024,
        sendMessage: (_) => throw StateError('Transport is closed'),
      );

      // Before the fix _sendEOFIfNeeded had no try/catch (unlike
      // _sendCloseIfNeeded), so destroy() threw here, `done` never completed,
      // and SSHClient._closeChannels aborted before the remaining channels
      // were destroyed.
      expect(controller.destroy, returnsNormally);
      await expectLater(controller.channel.done, completes);
    });
  });

  group(
      'upload loop with a hostile remoteMaximumPacketSize '
      '(audit: unbounded empty CHANNEL_DATA spin)', () {
    SSHChannelController make(int remoteMax, List<SSHMessage> sent) =>
        SSHChannelController(
          localId: 1,
          localMaximumPacketSize: 32768,
          localInitialWindowSize: 1024,
          remoteId: 2,
          remoteMaximumPacketSize: remoteMax,
          remoteInitialWindowSize: 1024,
          sendMessage: sent.add,
        );

    test('a sane packet size sends the data exactly once (control)', () async {
      final sent = <SSHMessage>[];
      final controller = make(1024, sent);
      controller.channel.addData(Uint8List(100));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final data = sent.whereType<SSH_Message_Channel_Data>().toList();
      expect(data, hasLength(1));
      expect(data.single.data.length, 100);
      controller.destroy();
    });

    test('a packet size of 0 sends NOTHING instead of spinning forever',
        () async {
      // Constructing the controller directly bypasses the acceptance floor in
      // SSHClient, so this exercises the loop's own guard. Before the fix
      // read(0) returned an empty view without consuming the chunk and the
      // loop emitted empty CHANNEL_DATA without bound (the audit probe counted
      // over a million in one run); this test would then fail by timeout.
      final sent = <SSHMessage>[];
      final controller = make(0, sent);
      controller.channel.addData(Uint8List(100));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(sent.whereType<SSH_Message_Channel_Data>(), isEmpty);
      controller.destroy();
    });
  });
}
