// SPDX-License-Identifier: MIT
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_userauth.dart' show SSHUserInfoPrompt;

import 'played_server.dart';

/// What a client writes for whoever follows it (its debug lines and its
/// trace) holds no password and none of the answers to a server's
/// questions.
///
/// A trace prints every message the client sends. The message that carries
/// the answers to a server's questions printed the answers: a password, a
/// one-time code. (The message that carries a password prints the account
/// and the way of signing in, and never did print the password.)
void main() {
  test('a sign-in with a password and then answers: neither is in what the client writes of itself, and the trace '
      'says how many answers went', () async {
    final server = PlayedServer();
    final written = <String>[];
    final client = SSHClient(
      server.socket,
      username: 'deploy',
      algorithms: PlayedServer.algorithms,
      keepAliveInterval: null,
      printDebug: (line) => written.add('debug: $line'),
      printTrace: (line) => written.add('trace: $line'),
      onPasswordRequest: () => 'not-a-real-password',
      onUserInfoRequest: (request) => ['not-a-real-answer', '123456'],
    );
    addTearDown(client.close);
    final ended = client.authenticated.then<Object?>((_) => null, onError: (Object e) => e);
    await server.greet();

    Future<SSH_Message_Userauth_Request> asks() async =>
        SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));
    void refuse(List<String> takes) =>
        server.send([SSH_Message_Userauth_Failure(methodsLeft: takes, partialSuccess: false).encode()]);

    expect((await asks()).methodName, 'none');
    refuse(['password', 'keyboard-interactive']);
    final password = await asks();
    expect(password.methodName, 'password');
    expect(password.password, 'not-a-real-password');
    refuse(['keyboard-interactive']);
    expect((await asks()).methodName, 'keyboard-interactive');
    server.send([
      SSH_Message_Userauth_InfoRequest(
        name: '',
        instruction: '',
        lang: '',
        prompts: [SSHUserInfoPrompt('Password: ', false), SSHUserInfoPrompt('Verification code: ', true)],
      ).encode(),
    ]);
    // The answers went to the server as they were given.
    final answers =
        SSH_Message_Userauth_InfoResponse.decode(await server.next(SSH_Message_Userauth_InfoResponse.messageId));
    expect(answers.responses, ['not-a-real-answer', '123456']);
    server.send([SSH_Message_Userauth_Success().encode()]);
    expect(await ended, isNull);

    final all = written.join('\n');
    expect(all, isNot(contains('not-a-real-password')));
    expect(all, isNot(contains('not-a-real-answer')));
    expect(all, isNot(contains('123456')));
    // The trace did say that the two went: both messages are in it, and what the server asked.
    expect(written.where((line) => line.startsWith('trace: ') && line.contains('methodName: password')), hasLength(1));
    expect(
      written.where((line) => line.startsWith('trace: ') && line.contains('SSH_Message_Userauth_InfoResponse')),
      [endsWith('SSH_Message_Userauth_InfoResponse(responses.length=2)')],
    );
    expect(written.where((line) => line.contains('Verification code: ')), hasLength(1));
  });
}
