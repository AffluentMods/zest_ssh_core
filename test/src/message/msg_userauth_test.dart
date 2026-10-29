// SPDX-License-Identifier: MIT
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

/// The messages of a sign-in are read as they are written.
///
/// A request to sign in with a key was read without the flag that says
/// whether a signature follows, so that nothing after the flag was read as
/// what it is; a request to change a password was read with the old and the
/// new one exchanged; and a list of names with nothing in it, as a server
/// sends that takes no way of signing in any more, was read as one name
/// that is empty.
void main() {
  SSH_Message_Userauth_Request again(SSH_Message_Userauth_Request request) =>
      SSH_Message_Userauth_Request.decode(request.encode());

  test('a request to sign in, of each kind', () {
    final none = again(SSH_Message_Userauth_Request.none(user: 'deploy'));
    expect((none.methodName, none.user, none.serviceName), ('none', 'deploy', 'ssh-connection'));

    final password = again(SSH_Message_Userauth_Request.password(user: 'deploy', password: 'the password'));
    expect((password.methodName, password.password, password.oldPassword), ('password', 'the password', null));

    final changed = again(SSH_Message_Userauth_Request.newPassword(
        user: 'deploy', oldPassword: 'the old one', newPassword: 'the new one'));
    expect((changed.methodName, changed.oldPassword, changed.password), ('password', 'the old one', 'the new one'));

    final questions = again(SSH_Message_Userauth_Request.keyboardInteractive(user: 'deploy'));
    expect((questions.methodName, questions.user), ('keyboard-interactive', 'deploy'));
  });

  test('a request to sign in with a key: with its signature, and asking whether the key would do', () {
    final key = Uint8List.fromList(List<int>.generate(51, (i) => i));
    final signature = Uint8List.fromList(List<int>.generate(83, (i) => 255 - i));

    final signed = again(SSH_Message_Userauth_Request.publicKey(
        username: 'deploy', publicKeyAlgorithm: 'ssh-ed25519', publicKey: key, signature: signature));
    expect((signed.methodName, signed.user, signed.publicKeyAlgorithm), ('publickey', 'deploy', 'ssh-ed25519'));
    expect(signed.publicKey, key);
    expect(signed.signature, signature);

    final asking = again(SSH_Message_Userauth_Request.publicKey(
        username: 'deploy', publicKeyAlgorithm: 'ssh-ed25519', publicKey: key, signature: null));
    expect(asking.publicKey, key);
    expect(asking.signature, isNull);
  });

  test('a refusal: the ways the server still takes, and whether what was tried was one step of several', () {
    SSH_Message_Userauth_Failure refusal(List<String> takes, {bool partly = false}) =>
        SSH_Message_Userauth_Failure.decode(
            SSH_Message_Userauth_Failure(methodsLeft: takes, partialSuccess: partly).encode());

    final two = refusal(['publickey', 'keyboard-interactive']);
    expect(two.methodsLeft, ['publickey', 'keyboard-interactive']);
    expect(two.partialSuccess, isFalse);
    final step = refusal(['password'], partly: true);
    expect(step.methodsLeft, ['password']);
    expect(step.partialSuccess, isTrue);
    // One that takes nothing any more.
    expect(refusal(const []).methodsLeft, isEmpty);
  });

  test('a list of names: none, one, several', () {
    List<String> read(List<String> names) =>
        SSHMessageReader((SSHMessageWriter()..writeNameList(names)).takeBytes()).readNameList();
    expect(read(const []), isEmpty);
    expect(read(['none']), ['none']);
    expect(read(['aes256-ctr', 'aes128-ctr', 'chacha20-poly1305@openssh.com']),
        ['aes256-ctr', 'aes128-ctr', 'chacha20-poly1305@openssh.com']);
  });
}
