import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';

/// Agent forwarding, and a server's no to it. With an agent to forward, the
/// client asked for agent forwarding at the start of every session and gave
/// the session up when the server said no. A server says no for one of two
/// reasons, and neither is one to give a session up for:
///
/// It has set the agent up already. OpenSSH does that once for a connection,
/// for every session on it, and says no to doing it twice: so on a server
/// that allows agent forwarding, the first session of a connection started,
/// and every one after it failed.
///
/// Or it allows none (`AllowAgentForwarding no`, or a key marked
/// `no-agent-forwarding`): such a server could not be used at all with an
/// agent set, for a shell or for a command.
///
/// OpenSSH's own client does not wait for the answer. This one goes on now
/// whatever the answer, keeps it for the connection, and tells whoever set
/// the agent of a real refusal, once.
///
/// Against a real OpenSSH server (tool/test_sshd.sh, 127.0.0.1:2299), which
/// takes one key with everything allowed and one marked
/// `no-agent-forwarding`. Skipped when it is not running.
void main() {
  final env = Platform.environment;
  final host = env['ZESTSSH_TEST_SSHD_HOST'] ?? '127.0.0.1';
  final port = int.tryParse(env['ZESTSSH_TEST_SSHD_PORT'] ?? '') ?? 2299;
  final user = env['ZESTSSH_TEST_SSHD_USER'] ?? env['USERNAME'] ?? env['USER'] ?? '';
  final dir = env['ZESTSSH_TEST_SSHD_DIR'] ??
      (Platform.isWindows ? '//wsl.localhost/Ubuntu/home/$user/zestssh-sshd-test' : '${env['HOME']}/zestssh-sshd-test');
  final freeKey = env['ZESTSSH_TEST_SSHD_KEY'] ?? '$dir/client_ed25519';
  final noAgentKey = env['ZESTSSH_TEST_SSHD_NOAGENT_KEY'] ?? '$dir/client_noagent_ed25519';

  Future<bool> serverUp() async {
    try {
      final s = await Socket.connect(host, port, timeout: const Duration(seconds: 2));
      s.destroy();
      return File(freeKey).existsSync() && File(noAgentKey).existsSync();
    } catch (_) {
      return false;
    }
  }

  /// A client signed in with the key at [keyPath], forwarding an agent that
  /// holds that key when [withAgent]. With it: how often it asked the server
  /// for agent forwarding, and how often it was told of a refusal.
  Future<(SSHClient, int Function() asked, int Function() told)> connect(String keyPath, {bool withAgent = true}) async {
    final identities = SSHKeyPair.fromPem(File(keyPath).readAsStringSync());
    var asked = 0;
    var told = 0;
    final client = SSHClient(
      await SSHSocket.connect(host, port),
      username: user,
      identities: identities,
      agentHandler: withAgent ? SSHKeyPairAgent(identities) : null,
      onAgentForwardingRefused: () => told++,
      printTrace: (line) {
        if (line != null && line.startsWith('->') && line.contains('requestType: auth-agent-req@openssh.com')) asked++;
      },
    );
    await client.authenticated;
    return (client, () => asked, () => told);
  }

  Future<String> run(SSHClient client, String command) async =>
      utf8.decode(await client.run(command).timeout(const Duration(seconds: 15))).trim();

  /// What a shell with no terminal says to [line], and that it ends.
  Future<String> inShell(SSHClient client, String line) async {
    final shell = await client.shell(pty: null).timeout(const Duration(seconds: 15));
    final said = utf8.decodeStream(shell.stdout);
    shell.write(utf8.encode('$line\nexit\n'));
    await shell.done.timeout(const Duration(seconds: 15));
    return (await said.timeout(const Duration(seconds: 15))).trim();
  }

  test('a server that gives agent forwarding: every session of the connection starts, the agent answers in each, '
      'and nobody is told of a refusal', () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    final (client, asked, told) = await connect(freeKey);
    addTearDown(client.close);
    // The server's own tool asks the forwarded agent what it holds. (The
    // second session and every one after it failed: the server sets the
    // agent up once for the connection and says no to doing it again.)
    for (var session = 1; session <= 3; session++) {
      expect(await run(client, 'ssh-add -l'), contains('ED25519'), reason: 'command $session');
    }
    expect(await inShell(client, 'ssh-add -l'), contains('ED25519'));
    expect(told(), 0, reason: 'a no to setting it up twice is no refusal');
    expect(client.agentForwardingRefused, isFalse);
    // Asked for the first session, and for the second: its no stands for the
    // connection, and the server is not asked for the two after it.
    expect(asked(), 2);
  });

  test('a shell as the first session of a connection asks for the agent too, and has it', () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    final (client, asked, told) = await connect(freeKey);
    addTearDown(client.close);
    expect(await inShell(client, 'ssh-add -l'), contains('ED25519'));
    expect(asked(), 1);
    expect(told(), 0);
  });

  test('two sessions started at once on such a server: both start, the agent answers in both', () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    final (client, asked, told) = await connect(freeKey);
    addTearDown(client.close);
    final both = await Future.wait([run(client, 'ssh-add -l'), run(client, 'ssh-add -l')]);
    expect(both, everyElement(contains('ED25519')));
    expect(asked(), 2);
    expect(told(), 0);
    expect(client.agentForwardingRefused, isFalse);
    expect(await run(client, 'ssh-add -l'), contains('ED25519'));
    expect(asked(), 2, reason: 'not asked a third time');
  });

  test('a server that refuses it: the session goes on without it, a command and a shell, and its owner is told, once',
      () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    final (client, asked, told) = await connect(noAgentKey);
    addTearDown(client.close);
    expect(client.agentForwardingRefused, isFalse, reason: 'nothing was asked yet');
    expect(await run(client, 'echo still-here'), 'still-here');
    expect(client.agentForwardingRefused, isTrue);
    expect(told(), 1);
    // No agent is there for what runs on the server.
    expect(await run(client, 'echo "[\$SSH_AUTH_SOCK]"'), '[]');
    expect(await inShell(client, 'echo shell-here'), 'shell-here');
    expect(await run(client, 'echo once-more'), 'once-more');
    // The server is not asked again for every session, having said no.
    expect(asked(), 1);
    expect(told(), 1);
  });

  test('two sessions started at once on a server that refuses: both go on, and the owner is still told once', () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    final (client, asked, told) = await connect(noAgentKey);
    addTearDown(client.close);
    final both = await Future.wait([run(client, 'echo one'), run(client, 'echo two')]);
    expect(both, ['one', 'two']);
    expect(asked(), 2, reason: 'neither had its answer when the other asked');
    expect(told(), 1);
    expect(client.agentForwardingRefused, isTrue);
  });

  test('with no agent to forward nothing is asked, and nothing is refused', () async {
    if (!await serverUp()) {
      markTestSkipped('the test OpenSSH server is not running');
      return;
    }
    for (final key in [freeKey, noAgentKey]) {
      final (client, asked, told) = await connect(key, withAgent: false);
      addTearDown(client.close);
      expect(await run(client, 'echo "[\$SSH_AUTH_SOCK]"'), '[]');
      expect(asked(), 0);
      expect(told(), 0);
      expect(client.agentForwardingRefused, isFalse);
    }
  });
}
