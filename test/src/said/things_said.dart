// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/message/msg_kex_dh.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_userauth.dart';
import 'package:zest_ssh_core/zest_ssh_core.dart';

/// What else of the package prints a name for itself, each with what it
/// prints: the messages, the algorithms, the keys and the few other things
/// whose text began with the name the program has for their type
/// (`runtimeType`), and a jump host's channel, which wrote no text of its
/// own and so printed "Instance of" that name. Read by the test that holds
/// them to it as the tests run, and by the program that prints them built
/// with its names obfuscated (errors_said_main.dart).
///
/// One of them belongs to a client, so [close] ends that client: it is on
/// a line that leads nowhere.
({List<(Object, String)> things, void Function() close}) thingsSaid() {
  final client = SSHClient(_NoLine(), username: 'deploy');
  final channel = SSHChannelController(
    localId: 3,
    localMaximumPacketSize: 32768,
    localInitialWindowSize: 2097152,
    remoteId: 7,
    remoteInitialWindowSize: 0,
    remoteMaximumPacketSize: 32768,
    sendMessage: (_) {},
  ).channel;
  final one = BigInt.one;
  return (
    things: [
      // What a trace prints of the messages (message/).
      (
        SSH_Message_KexDH_GexGroup(p: BigInt.from(23), g: BigInt.two),
        'SSH_Message_KexDH_GexGroup(p: 23, g: 2)',
      ),
      (
        SSH_Message_KexDH_GexReply(
          hostPublicKey: Uint8List.fromList([1, 2]),
          f: BigInt.from(5),
          signature: Uint8List.fromList([3]),
        ),
        'SSH_Message_KexDH_GexReply(hostPublicKey: [1, 2], f: 5, signature: [3])',
      ),
      (
        SSH_Message_Userauth_InfoRequest(
          name: 'Sign in',
          instruction: 'Answer below',
          lang: '',
          prompts: [SSHUserInfoPrompt('Password: ', false)],
        ),
        'SSH_Message_Userauth_InfoRequest(name: Sign in, instruction: Answer below, lang: , '
            'prompts: [SSHUserInfoPrompt(prompt: Password: , echo: false)])',
      ),
      // (How many answers, and none of them: an answer is a password or a code.)
      (
        SSH_Message_Userauth_InfoResponse(responses: ['not-a-real-one', '123456']),
        'SSH_Message_Userauth_InfoResponse(responses.length=2)',
      ),
      (SSHUserInfoPrompt('Code: ', true), 'SSHUserInfoPrompt(prompt: Code: , echo: true)'),

      // What the client's debug lines print of what was agreed on (algorithm/).
      (SSHKexType.x25519Iana, 'SSHKexType(curve25519-sha256)'),
      (SSHHostkeyType.ed25519, 'SSHHostkeyType(ssh-ed25519)'),
      (SSHCipherType.aes256ctr, 'SSHCipherType(aes256-ctr)'),
      (SSHMacType.hmacSha256, 'SSHMacType(hmac-sha2-256)'),

      // The keys and what a key file is made of (ssh_key_pair.dart, ssh_pem.dart).
      (
        OpenSSHKeyPairs.unencrypted(publicKeys: [Uint8List(4)], privateKeyBlob: Uint8List(8)),
        'OpenSSHKeyPairs{cipher: none, kdf: none, kdfOptions: null, keys.length: 1}',
      ),
      (
        OpenSSHBcryptKdfOptions(Uint8List.fromList('salt'.codeUnits), 16),
        'OpenSSHBcryptKdfOptions{salt: salt, rounds: 16}',
      ),
      (OpenSSHRsaKeyPair(one, one, one, one, one, one, 'deploy key'), 'OpenSSHRsaKeyPair(comment: "deploy key")'),
      (
        OpenSSHEd25519KeyPair(Uint8List(32), Uint8List(64), 'deploy key'),
        'OpenSSHEd25519KeyPair(comment: "deploy key")',
      ),
      (OpenSSHEd448KeyPair(Uint8List(57), Uint8List(57), 'deploy key'), 'OpenSSHEd448KeyPair(comment: "deploy key")'),
      (
        OpenSSHEcdsaKeyPair('nistp256', Uint8List(65), one, 'deploy key'),
        'OpenSSHEcdsaKeyPair(comment: "deploy key")',
      ),
      (
        RsaKeyPairDEKInfo('AES-128-CBC', Uint8List.fromList([0xab, 0xcd])),
        'RsaKeyPairDEKInfo(algorithm: AES-128-CBC, iv: abcd)',
      ),
      (RsaPrivateKey(BigInt.zero, one, one, one, one, one, one, one, one), 'RsaPrivateKey(version: 0)'),
      (SSHPem('RSA PRIVATE KEY', const {}, Uint8List(3)), 'SSHPem(RSA PRIVATE KEY, length: 3)'),

      // A file's mode, a port the server listens on for the client, and a jump host's channel.
      (const SftpFileMode.value(420), 'SftpFileMode(644)'),
      (SSHRemoteForward(client, '0.0.0.0', 8080, null), 'SSHRemoteForward(0.0.0.0:8080)'),
      (SSHForwardChannel(channel), 'SSHForwardChannel(SSHChannel(3:7))'),
    ],
    close: client.close,
  );
}

/// The line the program writes between the errors and the other things.
const thingsFollow = '-- and the other things --';

/// A line that leads nowhere: nothing comes from it, and what is written to
/// it is dropped.
class _NoLine implements SSHSocket {
  _NoLine() {
    _written.stream.listen((_) {});
  }

  final _coming = StreamController<Uint8List>();
  final _written = StreamController<List<int>>();

  @override
  Stream<Uint8List> get stream => _coming.stream;

  @override
  StreamSink<List<int>> get sink => _written.sink;

  @override
  Future<void> get done => _written.done;

  @override
  Future<void> flush() async {}

  @override
  Future<void> close() async {
    await _written.close();
  }

  @override
  void destroy() {
    _coming.close();
    _written.close();
  }

  @override
  String toString() => 'NoLine';
}
