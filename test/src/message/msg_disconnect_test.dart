import 'package:zest_ssh_core/src/message/msg_disconnect.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:test/test.dart';

/// SSH_MSG_DISCONNECT: the reason codes of RFC 4253 section 11.1, and a
/// message that reads back what was written, with or without a language tag.
void main() {
  test(
      'each reason has the code RFC 4253 gives it, in order, and words of its own',
      () {
    expect([for (final r in SSHDisconnectReason.values) r.code],
        List.generate(15, (i) => i + 1));
    final words = {for (final r in SSHDisconnectReason.values) r.description};
    expect(words, hasLength(SSHDisconnectReason.values.length));
    expect(words.every((w) => w.isNotEmpty), isTrue);
    expect(SSHDisconnectReason.byApplication.description, 'By application');
  });

  test('a disconnect for a reason reads back as that reason', () {
    final sent =
        SSH_Message_Disconnect.fromReason(SSHDisconnectReason.byApplication);
    final bytes = sent.encode();
    expect(bytes.first, SSH_Message_Disconnect.messageId);
    final back = SSH_Message_Disconnect.decode(bytes);
    expect((back.reasonCode, back.description, back.languageTag),
        (11, 'By application', ''));
    expect(back.toString(), contains('reasonCode: 11'));
  });

  test('a language tag is kept, and one left out reads as none', () {
    final tagged = SSH_Message_Disconnect(
        reasonCode: 2, description: 'bad packet', languageTag: 'en');
    expect(SSH_Message_Disconnect.decode(tagged.encode()).languageTag, 'en');

    // Some servers end the message after the description.
    final writer = SSHMessageWriter()
      ..writeUint8(SSH_Message_Disconnect.messageId)
      ..writeUint32(14)
      ..writeUtf8('No more auth methods available');
    final short = SSH_Message_Disconnect.decode(writer.takeBytes());
    expect((short.reasonCode, short.description, short.languageTag),
        (14, 'No more auth methods available', ''));
  });
}
