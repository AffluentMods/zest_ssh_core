import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/message/msg_disconnect.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// Text a server writes for a person to read: its notice before sign-in, a
/// question it asks, why it ends the connection, why it refuses something.
/// The protocol wants it in UTF-8, and servers send what their files hold:
/// a notice kept in an older encoding has bytes that are no UTF-8. One such
/// byte was taken for a packet that cannot be read, and ended the
/// connection: a host with such a notice could not be signed in to at all.
/// (OpenSSH's own client shows whatever came.) Such text is now read as far
/// as it can be, with a mark where a byte could not be.
void main() {
  // "Zugang nur für Befugte" as ISO 8859-1 writes it: the u with two dots is
  // the single byte 0xFC, which is no UTF-8.
  final latin1 = Uint8List.fromList([...'Zugang nur f'.codeUnits, 0xfc, ...'r Befugte'.codeUnits]);
  // Where a byte could not be read: U+FFFD, the replacement character.
  final mark = String.fromCharCode(0xfffd);
  final shown = 'Zugang nur f${mark}r Befugte';
  final tag = Uint8List.fromList([0x64, 0x65, 0xff]);

  SSHMessageWriter message(int id) => SSHMessageWriter()..writeUint8(id);

  test('the notice before sign-in', () {
    final bytes = (message(SSH_Message_Userauth_Banner.messageId)
          ..writeString(latin1)
          ..writeString(tag))
        .takeBytes();
    final banner = SSH_Message_Userauth_Banner.decode(bytes);
    expect(banner.message, shown);
    expect(banner.language, 'de$mark');
  });

  test('a question the server asks at sign-in: its title, what it says, and each prompt', () {
    final bytes = (message(SSH_Message_Userauth_InfoRequest.messageId)
          ..writeString(latin1)
          ..writeString(latin1)
          ..writeString(tag)
          ..writeUint32(2)
          ..writeString(latin1)
          ..writeBool(false)
          ..writeUtf8('Code: ')
          ..writeBool(true))
        .takeBytes();
    final request = SSH_Message_Userauth_InfoRequest.decode(bytes);
    expect(request.name, shown);
    expect(request.instruction, shown);
    expect(request.prompts.map((p) => p.promptText), [shown, 'Code: ']);
    expect(request.prompts.map((p) => p.echo), [false, true]);
  });

  test('the request for a new password', () {
    final bytes = (message(SSH_Message_Userauth_Passwd_ChangeReq.messageId)
          ..writeString(latin1)
          ..writeString(tag))
        .takeBytes();
    expect(SSH_Message_Userauth_Passwd_ChangeReq.decode(bytes).prompt, shown);
  });

  test('why the server ends the connection', () {
    final bytes = (message(SSH_Message_Disconnect.messageId)
          ..writeUint32(11)
          ..writeString(latin1)
          ..writeString(tag))
        .takeBytes();
    final disconnect = SSH_Message_Disconnect.decode(bytes);
    expect(disconnect.reasonCode, 11);
    expect(disconnect.description, shown);
  });

  test('why the server opens no channel', () {
    final bytes = (message(SSH_Message_Channel_Open_Failure.messageId)
          ..writeUint32(3)
          ..writeUint32(1)
          ..writeString(latin1)
          ..writeString(tag))
        .takeBytes();
    final failure = SSH_Message_Channel_Open_Failure.decode(bytes);
    expect(failure.recipientChannel, 3);
    expect(failure.reasonCode, 1);
    expect(failure.description, shown);
  });

  test('what a program that was killed is said to have ended with', () {
    final bytes = (message(SSH_Message_Channel_Request.messageId)
          ..writeUint32(3)
          ..writeUtf8('exit-signal')
          ..writeBool(false)
          ..writeUtf8('TERM')
          ..writeBool(false)
          ..writeString(latin1)
          ..writeString(tag))
        .takeBytes();
    final request = SSH_Message_Channel_Request.decode(bytes);
    expect(request.exitSignalName, 'TERM');
    expect(request.errorMessage, shown);
  });

  test('why an SFTP server refuses something', () {
    final bytes = (message(SftpStatusPacket.packetType)
          ..writeUint32(7)
          ..writeUint32(4)
          ..writeString(latin1)
          ..writeString(tag))
        .takeBytes();
    final status = SftpStatusPacket.decode(bytes);
    expect(status.requestId, 7);
    expect(status.code, 4);
    expect(status.message, shown);
  });

  test('text that is UTF-8 is read as it was, in any alphabet', () {
    // German with its u with two dots (U+00FC), and a line in Cyrillic.
    final notice = 'Nur f${String.fromCharCode(0xfc)}r Befugte. '
        '${String.fromCharCodes([0x422, 0x43e, 0x43b, 0x44c, 0x43a, 0x43e, 0x20, 0x434, 0x43b, 0x44f])}.';
    final bytes = SSH_Message_Userauth_Banner(message: notice, language: 'de').encode();
    final banner = SSH_Message_Userauth_Banner.decode(bytes);
    expect(banner.message, notice);
    expect(banner.language, 'de');
  });
}
