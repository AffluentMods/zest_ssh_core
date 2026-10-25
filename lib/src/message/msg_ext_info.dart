// ignore_for_file: camel_case_types

import 'dart:convert';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/ssh_message.dart';

/// What a side says of itself once its keys are in force
/// (SSH_MSG_EXT_INFO, RFC 8308, 2.3): entries of a name and a value, each
/// value read by whoever knows its name.
///
/// A server sends it to a client whose first proposal named "ext-info-c".
/// The one entry that is read here is "server-sig-algs" (RFC 8308, 3.1):
/// the kinds of signature the server takes from a key that signs in.
class SSH_Message_ExtInfo extends SSHMessage {
  static const messageId = 7;

  /// The most entries a message may have. (OpenSSH refuses 1024 and more.)
  static const maxExtensions = 1024;

  /// The name under which a server lists the kinds of signature it takes.
  static const serverSigAlgs = 'server-sig-algs';

  /// The entries by their names, in the order they came, each value as it
  /// came. A name that comes twice has the value that came last.
  final Map<String, Uint8List> extensions;

  SSH_Message_ExtInfo(this.extensions);

  factory SSH_Message_ExtInfo.decode(Uint8List bytes) {
    final reader = SSHMessageReader(bytes);
    reader.skip(1);
    final count = reader.readUint32();
    if (count > maxExtensions) {
      throw FormatException('SSH_MSG_EXT_INFO with $count entries, where at most $maxExtensions are taken');
    }
    final extensions = <String, Uint8List>{};
    for (var i = 0; i < count; i++) {
      // (Read byte for byte: what stands where a name belongs and is none
      // is passed over by [names], and is no packet that cannot be read.)
      final name = latin1.decode(reader.readString());
      extensions[name] = reader.readString();
    }
    return SSH_Message_ExtInfo(extensions);
  }

  /// The names of the entries, in the order they came, as far as they are
  /// names ([isName]).
  List<String> get names => [
        for (final name in extensions.keys)
          if (isName(name)) name,
      ];

  /// The kinds of signature the server says it takes ("server-sig-algs"),
  /// in its order, as far as they are names ([isName]). Null where it does
  /// not say; empty where it says that it takes none.
  List<String>? get serverSignatureAlgorithms {
    final list = extensions[serverSigAlgs];
    if (list == null) return null;
    return [
      for (final name in latin1.decode(list).split(','))
        if (isName(name)) name,
    ];
  }

  /// Whether [text] is what the protocol calls a name (RFC 4251, 6): one to
  /// sixty-four printable characters of US-ASCII, with no blank and no
  /// comma among them. What a server puts where a name belongs is its own
  /// text, and may be anything; only a name is kept of it, so nothing else
  /// of a server's making reaches a log or a screen by this message.
  static bool isName(String text) =>
      text.isNotEmpty && text.length <= 64 && text.codeUnits.every((c) => c > 0x20 && c < 0x7F && c != 0x2C);

  @override
  Uint8List encode() {
    final writer = SSHMessageWriter();
    writer.writeUint8(messageId);
    writer.writeUint32(extensions.length);
    extensions.forEach((name, value) {
      writer.writeString(latin1.encode(name));
      writer.writeString(value);
    });
    return writer.takeBytes();
  }

  @override
  String toString() {
    return 'SSH_Message_ExtInfo(${names.join(', ')})';
  }
}
