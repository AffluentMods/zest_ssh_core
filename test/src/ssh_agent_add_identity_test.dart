import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' show SHA256Digest;
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

import '../test_utils.dart';

/// Giving a key to an ssh-agent (SSHAgentProtocol.addIdentityRequest):
/// the request laid out as draft-miller-ssh-agent says, and, where WSL is
/// there, taken by OpenSSH's own ssh-agent: a fresh agent on a socket of
/// its own, started for the test and stopped after it (never the agent of
/// the person running the tests), which `ssh-add -l` then lists the key in,
/// by its fingerprint and comment, and forgets once a lifetime is up.
void main() {
  group('the request', () {
    test('an Ed25519 key: type 17, its type, public and private halves, then the comment', () {
      final key = SSHKeyPair.fromPem(fixture('ssh-ed25519/id_ed25519')).single as OpenSSHEd25519KeyPair;
      final r = SSHMessageReader(SSHAgentProtocol.addIdentityRequest(key, comment: 'deploy'));
      expect(r.readUint8(), 17);
      expect(r.readUtf8(), 'ssh-ed25519');
      expect(r.readString(), key.publicKey);
      expect(r.readString(), key.privateKey);
      expect(r.readUtf8(), 'deploy');
      expect(r.isDone, isTrue);
    });

    test('with a lifetime: type 25, and the lifetime constraint in whole seconds after the comment', () {
      final key = SSHKeyPair.fromPem(fixture('ssh-ed25519/id_ed25519')).single;
      final r = SSHMessageReader(
          SSHAgentProtocol.addIdentityRequest(key, comment: 'x', lifetime: const Duration(hours: 8)));
      expect(r.readUint8(), 25);
      r.readUtf8();
      r.readString();
      r.readString();
      expect(r.readUtf8(), 'x');
      expect(r.readUint8(), 1);
      expect(r.readUint32(), 8 * 3600);
      expect(r.isDone, isTrue);
    });

    test('an RSA key from a PEM file: n, e, d, iqmp, p, q, in that order', () {
      final key = SSHKeyPair.fromPem(fixture('ssh-rsa/id_rsa')).single as RsaPrivateKey;
      final r = SSHMessageReader(SSHAgentProtocol.addIdentityRequest(key));
      expect(r.readUint8(), 17);
      expect(r.readUtf8(), 'ssh-rsa');
      expect([for (var i = 0; i < 6; i++) r.readMpint()], [key.n, key.e, key.d, key.coefficient, key.p, key.q]);
      expect(r.readUtf8(), '');
    });

    test('an ECDSA key: its curve, its point and its private number', () {
      final key = SSHKeyPair.fromPem(fixture('ecdsa-sha2-nistp384/id_ecdsa')).single as OpenSSHEcdsaKeyPair;
      final r = SSHMessageReader(SSHAgentProtocol.addIdentityRequest(key));
      r.readUint8();
      expect(r.readUtf8(), 'ecdsa-sha2-nistp384');
      expect(r.readUtf8(), 'nistp384');
      expect(r.readString(), key.q);
      expect(r.readMpint(), key.d);
    });

    test('a comment is kept on one line', () {
      final key = SSHKeyPair.fromPem(fixture('ssh-ed25519/id_ed25519')).single;
      final r = SSHMessageReader(SSHAgentProtocol.addIdentityRequest(key, comment: 'a\nb'));
      r.readUint8();
      r.readUtf8();
      r.readString();
      r.readString();
      expect(r.readUtf8(), 'a b');
    });
  });

  group("OpenSSH's ssh-agent takes it (WSL)", () {
    late bool wsl;
    setUpAll(() async {
      try {
        final r = await Process.run('wsl', ['-d', 'Ubuntu', '-e', 'sh', '-c', 'command -v ssh-agent && command -v python3'])
            .timeout(const Duration(seconds: 20));
        wsl = r.exitCode == 0;
      } catch (_) {
        wsl = false;
      }
    });

    /// Starts an agent of its own, gives it [request] (framed), and prints
    /// the agent's answer's type, then `ssh-add -l` at once and after
    /// [waitSeconds]. The agent is stopped at the end, whatever happened.
    Future<List<String>> run(Uint8List request, {int waitSeconds = 0}) async {
      final script = r'''
set -u
d=$(mktemp -d); trap 'kill $SSH_AGENT_PID 2>/dev/null; rm -rf "$d"' EXIT
eval "$(ssh-agent -a "$d/agent.sock")" >/dev/null
base64 -d > "$d/req"
python3 - "$d/agent.sock" "$d/req" <<'PY'
import socket, struct, sys
s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
body = open(sys.argv[2], 'rb').read()
s.sendall(struct.pack('>I', len(body)) + body)
n = struct.unpack('>I', s.recv(4))[0]
print('answer', s.recv(n)[0])
PY
echo listed; ssh-add -l 2>&1
sleep "$1"
echo later; ssh-add -l 2>&1
''';
      final p = await Process.start('wsl', ['-d', 'Ubuntu', '-e', 'bash', '-c', script, 'bash', '$waitSeconds']);
      p.stdin.write(base64.encode(request));
      await p.stdin.close();
      final out = await p.stdout.transform(utf8.decoder).join();
      await p.exitCode;
      return const LineSplitter().convert(out);
    }

    String fingerprintOf(SSHKeyPair key) {
      final digest = SHA256Digest().process(key.toPublicKey().encode());
      return 'SHA256:${base64.encode(digest).replaceAll('=', '')}';
    }

    for (final (name, pem) in [
      ('ed25519', () => fixture('ssh-ed25519/id_ed25519')),
      ('ecdsa', () => fixture('ecdsa-sha2-nistp256/id_ecdsa')),
      ('rsa (PEM)', () => fixture('ssh-rsa/id_rsa')),
      ('rsa (OpenSSH)', () => fixture('ssh-rsa/id_rsa.openssh')),
    ]) {
      test('$name: the agent says yes, and lists the key by its fingerprint and comment', () async {
        if (!wsl) return markTestSkipped('WSL is not available');
        final key = SSHKeyPair.fromPem(pem()).single;
        final lines = await run(SSHAgentProtocol.addIdentityRequest(key, comment: 'zestssh test key'));
        expect(lines.first, 'answer ${SSHAgentProtocol.success}');
        final listed = lines.sublist(lines.indexOf('listed') + 1, lines.indexOf('later'));
        expect(listed, hasLength(1));
        expect(listed.single, contains(fingerprintOf(key)));
        expect(listed.single, contains('zestssh test key'));
      });
    }

    test('with a lifetime the agent forgets the key once it is up', () async {
      if (!wsl) return markTestSkipped('WSL is not available');
      final key = SSHKeyPair.fromPem(fixture('ssh-ed25519/id_ed25519')).single;
      final lines = await run(
        SSHAgentProtocol.addIdentityRequest(key, comment: 'brief', lifetime: const Duration(seconds: 1)),
        waitSeconds: 3,
      );
      expect(lines.first, 'answer ${SSHAgentProtocol.success}');
      expect(lines[lines.indexOf('listed') + 1], contains('brief'));
      expect(lines.sublist(lines.indexOf('later') + 1).join('\n'), contains('no identities'));
    });
  });
}
