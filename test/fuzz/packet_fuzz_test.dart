import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/sftp/sftp_packet.dart';
import 'package:zest_ssh_core/src/ssh_pem.dart';

void main() {
  final rng = Random(42); // Deterministic seed for reproducibility

  group('SFTP packet parser fuzzing', () {
    final decoders = <String, Object Function(Uint8List)>{
      'SftpInitPacket': SftpInitPacket.decode,
      'SftpVersionPacket': SftpVersionPacket.decode,
      'SftpOpenPacket': SftpOpenPacket.decode,
      'SftpClosePacket': SftpClosePacket.decode,
      'SftpReadPacket': SftpReadPacket.decode,
      'SftpWritePacket': SftpWritePacket.decode,
      'SftpLStatPacket': SftpLStatPacket.decode,
      'SftpFStatPacket': SftpFStatPacket.decode,
      'SftpSetStatPacket': SftpSetStatPacket.decode,
      'SftpFSetStatPacket': SftpFSetStatPacket.decode,
      'SftpOpenDirPacket': SftpOpenDirPacket.decode,
      'SftpReadDirPacket': SftpReadDirPacket.decode,
      'SftpRemovePacket': SftpRemovePacket.decode,
      'SftpMkdirPacket': SftpMkdirPacket.decode,
      'SftpRmdirPacket': SftpRmdirPacket.decode,
      'SftpRealpathPacket': SftpRealpathPacket.decode,
      'SftpStatPacket': SftpStatPacket.decode,
      'SftpRenamePacket': SftpRenamePacket.decode,
      'SftpReadlinkPacket': SftpReadlinkPacket.decode,
      'SftpSymlinkPacket': SftpSymlinkPacket.decode,
      'SftpStatusPacket': SftpStatusPacket.decode,
      'SftpHandlePacket': SftpHandlePacket.decode,
      'SftpDataPacket': SftpDataPacket.decode,
      'SftpNamePacket': SftpNamePacket.decode,
      'SftpAttrsPacket': SftpAttrsPacket.decode,
      'SftpExtendedPacket': SftpExtendedPacket.decode,
      'SftpExtendedReplyPacket': SftpExtendedReplyPacket.decode,
    };

    for (var i = 0; i < 1000; i++) {
      test('random input #$i does not crash', () {
        final length = rng.nextInt(1024);
        final bytes = Uint8List.fromList(
          List.generate(length, (_) => rng.nextInt(256)),
        );

        for (final entry in decoders.entries) {
          try {
            entry.value(bytes);
          } on FormatException {
            // Expected for random input
          } on RangeError {
            // Expected for truncated input
          } on ArgumentError {
            // Expected for invalid arguments
          } on StateError {
            // Expected for invalid state
          } on TypeError {
            // Expected for null safety issues with random data
          } on UnimplementedError {
            // Expected for unrecognized types
          } on UnsupportedError {
            // Expected for unsupported features
          }
          // Any OTHER exception type = bug
        }
      });
    }
  });

  group('PEM parser fuzzing', () {
    for (var i = 0; i < 500; i++) {
      test('random PEM-like input #$i does not crash', () {
        final length = rng.nextInt(512);
        final chars = List.generate(length, (_) => rng.nextInt(128));
        final input = String.fromCharCodes(chars);

        try {
          SSHPem.decode(input);
        } on FormatException {
          // Expected for random input
        } on RangeError {
          // Expected for truncated input
        } on ArgumentError {
          // Expected for invalid arguments
        } on StateError {
          // Expected for invalid state
        }
      });
    }
  });
}
