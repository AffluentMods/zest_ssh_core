import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/message/msg_debug.dart';
import 'package:zest_ssh_core/src/message/msg_disconnect.dart';
import 'package:zest_ssh_core/src/message/msg_ignore.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/message/msg_kex_dh.dart';
import 'package:zest_ssh_core/src/message/msg_kex_ecdh.dart';
import 'package:zest_ssh_core/src/message/msg_request.dart';
import 'package:zest_ssh_core/src/message/msg_service.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';

void main() {
  final rng = Random(42); // Deterministic seed for reproducibility

  // Map of message type name -> decoder function
  final decoders = <String, Object Function(Uint8List)>{
    'SSH_Message_Disconnect': SSH_Message_Disconnect.decode,
    'SSH_Message_Ignore': SSH_Message_Ignore.decode,
    'SSH_Message_Debug': SSH_Message_Debug.decode,
    'SSH_Message_Service_Request': SSH_Message_Service_Request.decode,
    'SSH_Message_Service_Accept': SSH_Message_Service_Accept.decode,
    'SSH_Message_KexInit': SSH_Message_KexInit.decode,
    'SSH_Message_KexECDH_Init': SSH_Message_KexECDH_Init.decode,
    'SSH_Message_KexECDH_Reply': SSH_Message_KexECDH_Reply.decode,
    'SSH_Message_KexDH_Init': SSH_Message_KexDH_Init.decode,
    'SSH_Message_KexDH_Reply': SSH_Message_KexDH_Reply.decode,
    'SSH_Message_KexDH_GexRequest': SSH_Message_KexDH_GexRequest.decode,
    'SSH_Message_KexDH_GexGroup': SSH_Message_KexDH_GexGroup.decode,
    'SSH_Message_KexDH_GexInit': SSH_Message_KexDH_GexInit.decode,
    'SSH_Message_KexDH_GexReply': SSH_Message_KexDH_GexReply.decode,
    'SSH_Message_Userauth_Request': SSH_Message_Userauth_Request.decode,
    'SSH_Message_Userauth_Failure': SSH_Message_Userauth_Failure.decode,
    'SSH_Message_Userauth_Success': SSH_Message_Userauth_Success.decode,
    'SSH_Message_Userauth_Banner': SSH_Message_Userauth_Banner.decode,
    'SSH_Message_Userauth_InfoRequest': SSH_Message_Userauth_InfoRequest.decode,
    'SSH_Message_Userauth_InfoResponse':
        SSH_Message_Userauth_InfoResponse.decode,
    'SSH_Message_Global_Request': SSH_Message_Global_Request.decode,
    'SSH_Message_Request_Success': SSH_Message_Request_Success.decode,
    'SSH_Message_Request_Failure': SSH_Message_Request_Failure.decode,
    'SSH_Message_Channel_Open': SSH_Message_Channel_Open.decode,
    'SSH_Message_Channel_Confirmation':
        SSH_Message_Channel_Confirmation.decode,
    'SSH_Message_Channel_Open_Failure':
        SSH_Message_Channel_Open_Failure.decode,
    'SSH_Message_Channel_Window_Adjust':
        SSH_Message_Channel_Window_Adjust.decode,
    'SSH_Message_Channel_Data': SSH_Message_Channel_Data.decode,
    'SSH_Message_Channel_Extended_Data':
        SSH_Message_Channel_Extended_Data.decode,
    'SSH_Message_Channel_EOF': SSH_Message_Channel_EOF.decode,
    'SSH_Message_Channel_Close': SSH_Message_Channel_Close.decode,
    'SSH_Message_Channel_Request': SSH_Message_Channel_Request.decode,
    'SSH_Message_Channel_Success': SSH_Message_Channel_Success.decode,
    'SSH_Message_Channel_Failure': SSH_Message_Channel_Failure.decode,
  };

  group('SSH message decoder fuzzing', () {
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
            // Expected for unrecognized method names
          } on UnsupportedError {
            // Expected for unsupported features
          }
          // Any OTHER exception type = bug
        }
      });
    }
  });

  group('SSH message decoder fuzzing - per type', () {
    for (final entry in decoders.entries) {
      group(entry.key, () {
        for (var i = 0; i < 100; i++) {
          test('random input #$i does not crash', () {
            final length = rng.nextInt(512);
            final bytes = Uint8List.fromList(
              List.generate(length, (_) => rng.nextInt(256)),
            );

            try {
              entry.value(bytes);
            } on FormatException {
              // Expected
            } on RangeError {
              // Expected
            } on ArgumentError {
              // Expected
            } on StateError {
              // Expected
            } on TypeError {
              // Expected
            } on UnimplementedError {
              // Expected
            } on UnsupportedError {
              // Expected
            }
          });
        }
      });
    }
  });

  group('SSH message decoder fuzzing - empty and minimal inputs', () {
    for (final entry in decoders.entries) {
      test('${entry.key} handles empty input', () {
        try {
          entry.value(Uint8List(0));
        } on FormatException {
          // Expected
        } on RangeError {
          // Expected
        } on ArgumentError {
          // Expected
        } on StateError {
          // Expected
        } on TypeError {
          // Expected
        } on UnimplementedError {
          // Expected
        } on UnsupportedError {
          // Expected
        }
      });

      test('${entry.key} handles single byte', () {
        for (var b = 0; b < 256; b++) {
          try {
            entry.value(Uint8List.fromList([b]));
          } on FormatException {
            // Expected
          } on RangeError {
            // Expected
          } on ArgumentError {
            // Expected
          } on StateError {
            // Expected
          } on TypeError {
            // Expected
          } on UnimplementedError {
            // Expected
          } on UnsupportedError {
            // Expected
          }
        }
      });
    }
  });
}
