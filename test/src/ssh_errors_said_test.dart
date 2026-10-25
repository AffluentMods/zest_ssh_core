import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_algorithm.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/zest_ssh_core.dart';

import 'said/errors_said.dart';
import 'said/things_said.dart';

/// What the package prints of its own things is the same in a program built
/// with its names obfuscated as it is in a test.
///
/// An error printed the name the program has for its type (`runtimeType`)
/// and its message: "SSHAuthFailError(All authentication methods failed)".
/// A program built obfuscated, as a released app most often is, has another
/// name for nearly every type, so that the same error printed
/// "Ei(All authentication methods failed)" there. Whoever read the text
/// read that: a person, in a log or under an error's details, and a program
/// that looks for the name in it to tell one failure from another, which
/// found it in every test and never in the app as it was released.
///
/// The errors were the first to spell their names out. The other things
/// that began their text with the program's name did so after them: the
/// algorithms a connection agreed on, which the client's debug lines print
/// ("SSHTransport._kexType: SSHKexType(curve25519-sha256)" was
/// "SSHTransport._kexType: Fz(curve25519-sha256)" in a released app's
/// connection log), some of the messages a trace prints, the keys, and a
/// few more; and a jump host's channel, which wrote no text of its own, so
/// that a line that names the connection said "Instance of" that name.
void main() {
  test('each says its own name', () {
    for (final (error, text) in errorsSaid()) {
      expect('$error', text);
    }
  });

  test('and is asked for it as such', () {
    expect(SSHAuthFailError('x').typeName, 'SSHAuthFailError');
    expect(SSHKeyDecryptError('x').typeName, 'SSHKeyDecryptError');
    expect(SSHMacMismatchException().typeName, 'SSHMacMismatchException');
  });

  test('a kind made from another says the name of what it was made from, and one that spells none out the name of '
      'its family', () {
    // (Each of these said the name of the class written here: what the program calls it.)
    expect('${_Aa('Hostkey verification failed')}', 'SSHHostkeyError(Hostkey verification failed)');
    expect('${_Bb('Invalid passphrase')}', 'SSHKeyDecryptError(Invalid passphrase, null)');
    expect('${_Cc()}', 'SSHMacMismatchException: MAC verification failed on received packet');
    expect('${_Dd('of no kind')}', 'SSHError(of no kind)');
    expect('${_Ee()}', 'SSHException: of no kind');
  });

  test('none is missing here: every class of the two files that can be made is among them', () {
    final said = [for (final (_, text) in errorsSaid()) text];
    for (final file in _files) {
      final declared = RegExp(r'^class (\w+)', multiLine: true).allMatches(File(file).readAsStringSync());
      expect(declared, isNotEmpty, reason: file);
      for (final name in declared.map((m) => m[1]!)) {
        expect(said.where((text) => text.startsWith('$name(') || text.startsWith('$name: ')), isNotEmpty,
            reason: '$name of $file is not among the errors that are held to what they print');
      }
    }
  });

  group('the other things that print a name for themselves', () {
    late ({List<(Object, String)> things, void Function() close}) said;

    setUp(() {
      said = thingsSaid();
      addTearDown(said.close);
    });

    test('each says its own name', () {
      for (final (thing, text) in said.things) {
        expect('$thing', text);
      }
    });

    test('the four kinds of algorithm are asked for theirs as such, and a kind that spells none out says the name '
        'of its family', () {
      expect(SSHKexType.x25519.typeName, 'SSHKexType');
      expect(SSHHostkeyType.ed25519.typeName, 'SSHHostkeyType');
      expect(SSHCipherType.aes256ctr.typeName, 'SSHCipherType');
      expect(SSHMacType.hmacSha256.typeName, 'SSHMacType');
      expect('${const _Ff()}', 'SSHAlgorithm(of no kind)');
    });

    test('a channel says its own number and the one the other side gave it, where it said its own twice', () {
      final channel = SSHChannelController(
        localId: 3,
        localMaximumPacketSize: 32768,
        localInitialWindowSize: 2097152,
        remoteId: 7,
        remoteInitialWindowSize: 0,
        remoteMaximumPacketSize: 32768,
        sendMessage: (_) {},
      ).channel;
      expect(channel.channelId, 3);
      expect(channel.remoteChannelId, 7);
      expect('$channel', 'SSHChannel(3:7)');
    });

    test('the answers to a server\'s questions are counted in what the message prints, and not printed', () {
      final answers = said.things.map((said) => said.$1).whereType<SSH_Message_Userauth_InfoResponse>().single;
      expect(answers.responses, ['not-a-real-one', '123456']);
      expect('$answers', isNot(contains('not-a-real-one')));
      expect('$answers', isNot(contains('123456')));
      expect('$answers', contains('responses.length=2'));
    });
  });

  test('and nothing in the package asks the program for a name', () {
    final files = Directory('lib').listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.dart'));
    expect(files.length, greaterThan(80));
    for (final file in files) {
      final code = LineSplitter.split(file.readAsStringSync()).where((line) => !line.trimLeft().startsWith('//'));
      expect(code.where((line) => line.contains('runtimeType')), isEmpty, reason: file.path);
    }
  });

  test('in a program built with its names obfuscated, as a released app is', () async {
    final sdk = File(Platform.resolvedExecutable).parent.path;
    final dart = '$sdk${Platform.pathSeparator}dart${Platform.isWindows ? '.exe' : ''}';
    final out = await Directory.systemTemp.createTemp('zest_ssh_core_said');
    addTearDown(() async {
      try {
        await out.delete(recursive: true);
      } on FileSystemException {
        // Still held by whatever looks at a new program on this system.
      }
    });
    final program = '${out.path}${Platform.pathSeparator}said${Platform.isWindows ? '.exe' : ''}';
    final built = await Process.run(dart, [
      'compile',
      'exe',
      '--extra-gen-snapshot-options=--obfuscate',
      '-o',
      program,
      'test/src/said/errors_said_main.dart',
    ]);
    expect(built.exitCode, 0, reason: 'the program was not built:\n${built.stdout}\n${built.stderr}');

    final ran = await Process.run(program, const []);
    expect(ran.exitCode, 0, reason: '${ran.stderr}');
    final lines = LineSplitter.split(ran.stdout as String).toList();
    // It was built obfuscated: a type of its own is called something else there. (Else what follows holds nothing.)
    expect('${const NamedByTheProgram()}', 'NamedByTheProgram');
    expect(lines.first, isNot('NamedByTheProgram'), reason: 'the program was not built with its names obfuscated');
    final things = lines.indexOf(thingsFollow);
    expect(things, greaterThan(0), reason: 'the program did not get as far as the other things');
    expect(lines.sublist(1, things), [for (final (_, text) in errorsSaid()) text]);
    final said = thingsSaid();
    addTearDown(said.close);
    expect(lines.sublist(things + 1), [for (final (_, text) in said.things) text]);
  }, timeout: const Timeout(Duration(minutes: 5)));
}

const _files = ['lib/src/ssh_errors.dart', 'lib/src/exceptions/ssh_exceptions.dart'];

class _Aa extends SSHHostkeyError {
  _Aa(super.message);
}

class _Bb extends SSHKeyDecryptError {
  _Bb(super.message);
}

class _Cc extends SSHMacMismatchException {}

class _Dd with SSHMessageError implements SSHError {
  _Dd(this.message);

  @override
  final String message;
}

class _Ee extends SSHException {
  @override
  String get message => 'of no kind';

  @override
  Object? get cause => null;
}

class _Ff extends SSHAlgorithm {
  const _Ff();

  @override
  String get name => 'of no kind';
}
