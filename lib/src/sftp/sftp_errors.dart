// SPDX-License-Identifier: MIT
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/sftp/sftp_status_code.dart';

class SftpError {
  final String message;

  SftpError(this.message);

  @override
  String toString() {
    return 'SftpError: $message';
  }
}

class SftpAbortError implements SftpError {
  @override
  final String message;

  SftpAbortError(this.message);

  @override
  String toString() {
    return 'SftpAbortError: $message';
  }
}

/// What the server sent first is no SFTP. Most often it is text: something
/// the account's shell prints when a session starts (a line in a start-up
/// file), which comes down the channel ahead of the SFTP server's first
/// packet. OpenSSH's own client says "Received message too long" of it. The
/// session is over when this is thrown.
class SftpNotSftpError implements SftpError {
  /// The start of what came, as far as it reads as text: its first line, at
  /// most eighty characters.
  final String received;

  SftpNotSftpError(this.received);

  @override
  String get message =>
      'The server sent something that is no SFTP where its SFTP server was to answer '
      '(most often text the shell of the account prints when a session starts): "$received"';

  @override
  String toString() {
    return 'SftpNotSftpError: $message';
  }
}

class SftpStatusError implements SftpError {
  final int code;

  @override
  final String message;

  SftpStatusError(this.code, this.message);

  SftpStatusError.fromStatus(SftpStatusPacket status)
      : code = status.code,
        message = status.message;

  static void check(SftpStatusPacket status) {
    if (status.code != SftpStatusCode.ok && status.code != SftpStatusCode.eof) {
      throw SftpStatusError.fromStatus(status);
    }
  }

  @override
  String toString() {
    return 'SftpStatusError: $message(code $code)';
  }
}

/* sealed */ abstract class SftpExtensionError implements SftpError {}

class SftpExtensionUnsupportedError implements SftpExtensionError {
  final String extension;

  @override
  String get message => 'Extension "$extension" is not supported';

  SftpExtensionUnsupportedError(this.extension);

  @override
  String toString() {
    return 'SftpExtensionUnsupportedError: $message';
  }
}

class SftpExtensionVersionMismatchError implements SftpExtensionError {
  final String extension;

  final String version;

  @override
  String get message =>
      'Extension "$extension" of version $version is not supported';

  SftpExtensionVersionMismatchError(this.extension, this.version);

  @override
  String toString() {
    return 'SftpExtensionVersionMismatchError: $message';
  }
}
