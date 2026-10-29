// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';

import 'played_server.dart';

/// A key exchange whose two sides have no algorithm of one kind in common
/// says what each side offered of it.
///
/// It ended with "No matching cipher algorithm" and nothing else: neither
/// what this side had offered nor what the other side had. Whoever read
/// the error, a person or the application that has to say what to do
/// about it, could not tell a server that wants something older from one
/// that wants something this side never has, and had to ask the server
/// with another program.
///
/// The error carries both lists now, in the order each side offered them
/// in. What it prints is what it printed: the other side's names are its
/// own text, and whoever shows them keeps of them what a name can be.
void main() {
  // What the client of these tests offers: two of each kind, so that an order can be told.
  const mine = SSHAlgorithms(
    kex: [SSHKexType.x25519Iana, SSHKexType.nistp256],
    hostkey: [SSHHostkeyType.ed25519, SSHHostkeyType.rsaSha512],
    cipher: [SSHCipherType.aes256ctr, SSHCipherType.aes128ctr],
    mac: [SSHMacType.hmacSha256, SSHMacType.hmacSha512],
  );

  /// A proposal for the key exchange as another side makes it: what it is
  /// not told is something the client of these tests has. The two marks
  /// that are no key exchanges are among its key exchanges, as [marks] has
  /// them (a server's, where nothing is said).
  Uint8List proposal({
    List<String> kex = const ['curve25519-sha256'],
    List<String> hostKeys = const ['ssh-ed25519'],
    List<String> fromClient = const ['aes256-ctr'],
    List<String> toClient = const ['aes256-ctr'],
    List<String> macFromClient = const ['hmac-sha2-256'],
    List<String> macToClient = const ['hmac-sha2-256'],
    List<String> marks = const ['ext-info-s', 'kex-strict-s-v00@openssh.com'],
  }) =>
      SSH_Message_KexInit(
        kexAlgorithms: [...kex, ...marks],
        serverHostKeyAlgorithms: hostKeys,
        encryptionClientToServer: fromClient,
        encryptionServerToClient: toClient,
        macClientToServer: macFromClient,
        macServerToClient: macToClient,
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

  /// What a connection ended with whose other side proposed [theirs], for
  /// a transport that offers [algorithms] and plays a client, or a server.
  Future<Object?> endedWith(Uint8List theirs, {SSHAlgorithms algorithms = mine, bool isServer = false}) async {
    final other = PlayedServer();
    final transport = SSHTransport(
      other.socket,
      isServer: isServer,
      algorithms: algorithms,
      onVerifyHostKey: (type, key) => true,
    );
    addTearDown(transport.close);
    Object? ended;
    unawaited(transport.done.then<void>((_) {}, onError: (Object error) {
      ended = error;
    }));
    // The proposal of the test comes first, and what the played side sends after it is not looked at where
    // the connection has ended; the played side waits for the rest in vain then.
    await other.exchangeKeys(first: [theirs]).then((_) {}, onError: (Object _) {});
    await other.settle();
    return ended;
  }

  test('each kind of algorithm: the error says which, what this side offered and what the other side offered, '
      'each in its order', () async {
    for (final (theirs, message, offered, otherSide) in [
      (
        proposal(kex: ['diffie-hellman-group1-sha1', 'made-up-exchange']),
        'No matching key exchange algorithm',
        ['curve25519-sha256', 'ecdh-sha2-nistp256'],
        ['diffie-hellman-group1-sha1', 'made-up-exchange'],
      ),
      (
        proposal(hostKeys: ['ssh-dss', 'made-up-key']),
        'No matching host key algorithm',
        ['ssh-ed25519', 'rsa-sha2-512'],
        ['ssh-dss', 'made-up-key'],
      ),
      (
        proposal(fromClient: ['3des-cbc', 'aes256-gcm@openssh.com']),
        'No matching client cipher algorithm',
        ['aes256-ctr', 'aes128-ctr'],
        ['3des-cbc', 'aes256-gcm@openssh.com'],
      ),
      (
        proposal(toClient: ['blowfish-cbc', 'arcfour']),
        'No matching server cipher algorithm',
        ['aes256-ctr', 'aes128-ctr'],
        ['blowfish-cbc', 'arcfour'],
      ),
      (
        proposal(macFromClient: ['hmac-ripemd160', 'umac-64@openssh.com']),
        'No matching client MAC algorithm',
        ['hmac-sha2-256', 'hmac-sha2-512'],
        ['hmac-ripemd160', 'umac-64@openssh.com'],
      ),
      (
        proposal(macToClient: ['umac-128@openssh.com', 'hmac-md5-96']),
        'No matching server MAC algorithm',
        ['hmac-sha2-256', 'hmac-sha2-512'],
        ['umac-128@openssh.com', 'hmac-md5-96'],
      ),
    ]) {
      final ended = await endedWith(theirs);
      expect(ended, isA<SSHHandshakeError>(), reason: message);
      final error = ended! as SSHHandshakeError;
      expect(error.message, message);
      expect(error.nothingInCommon, isTrue, reason: message);
      expect(error.offered, offered, reason: message);
      expect(error.otherSideOffered, otherSide, reason: message);
      expect(error.strictOrderBroken, isFalse, reason: message);
      // What it prints is what it printed: the other side's names are not in it.
      expect('$error', 'SSHHandshakeError($message)');
    }
  });

  test('the marks a proposal carries among its key exchanges are no key exchanges: neither a server\'s nor a '
      'client\'s is among what the other side offered', () async {
    // A client that is offered nothing it has, by a server.
    final asClient = await endedWith(proposal(kex: ['made-up-exchange']));
    expect((asClient! as SSHHandshakeError).otherSideOffered, ['made-up-exchange']);
    // A server that is offered nothing it has, by a client: the client's own marks.
    final asServer = await endedWith(
      proposal(kex: ['made-up-exchange', 'another-one'], marks: ['ext-info-c', 'kex-strict-c-v00@openssh.com']),
      isServer: true,
    );
    expect(asServer, isA<SSHHandshakeError>());
    final error = asServer! as SSHHandshakeError;
    expect(error.message, 'No matching key exchange algorithm');
    expect(error.otherSideOffered, ['made-up-exchange', 'another-one']);
    expect(error.offered, ['curve25519-sha256', 'ecdh-sha2-nistp256']);
    // A name that only begins like a mark is a name.
    final near = await endedWith(proposal(kex: ['ext-info-s-2', 'kex-strict-s-v01@openssh.com']));
    expect((near! as SSHHandshakeError).otherSideOffered, ['ext-info-s-2', 'kex-strict-s-v01@openssh.com']);
  });

  test('another side that offers nothing of a kind: an empty list, and still nothing in common', () async {
    final ended = await endedWith(proposal(hostKeys: const []));
    final error = ended! as SSHHandshakeError;
    expect(error.message, 'No matching host key algorithm');
    expect(error.nothingInCommon, isTrue);
    expect(error.otherSideOffered, isEmpty);
    expect(error.offered, ['ssh-ed25519', 'rsa-sha2-512']);
  });

  test('neither list can be changed by whoever is handed the error', () async {
    final error = (await endedWith(proposal(fromClient: ['3des-cbc'])))! as SSHHandshakeError;
    expect(() => error.offered!.add('none'), throwsUnsupportedError);
    expect(() => error.otherSideOffered!.add('aes256-ctr'), throwsUnsupportedError);
    expect(error.offered, ['aes256-ctr', 'aes128-ctr']);
    expect(error.otherSideOffered, ['3des-cbc']);
  });

  test('a cipher that checks its packets by itself has no use for a MAC: MACs with nothing in common end '
      'nothing then, as before', () async {
    const aead = SSHAlgorithms(
      kex: [SSHKexType.x25519Iana],
      hostkey: [SSHHostkeyType.ed25519],
      cipher: [SSHCipherType.chacha20poly1305],
      mac: [SSHMacType.hmacSha256],
    );
    final ended = await endedWith(
      proposal(
        fromClient: ['chacha20-poly1305@openssh.com'],
        toClient: ['chacha20-poly1305@openssh.com'],
        macFromClient: ['hmac-ripemd160'],
        macToClient: ['hmac-ripemd160'],
      ),
      algorithms: aead,
    );
    // (What ends such a connection later is the played side's own proposal, which is a second one: nothing of
    // an algorithm.)
    expect(ended is SSHHandshakeError && ended.nothingInCommon, isFalse);
  });

  test('every other end of a handshake has neither list, and is no end of this kind', () {
    for (final error in [
      SSHHandshakeError('No matching key exchange algorithm'),
      SSHHandshakeError('The version exchange failed: nobody was there'),
      SSHHandshakeError('Strict KEX violation', strictOrderBroken: true),
    ]) {
      expect(error.nothingInCommon, isFalse, reason: error.message);
      expect(error.offered, isNull, reason: error.message);
      expect(error.otherSideOffered, isNull, reason: error.message);
    }
    // The lists make it one, whatever it says.
    final made = SSHHandshakeError('x', offered: const ['a'], otherSideOffered: const []);
    expect(made.nothingInCommon, isTrue);
    expect('$made', 'SSHHandshakeError(x)');
    // What the other side offered is what says so: an error that was made with that alone is one, and one
    // with what this side offered alone is none.
    expect(SSHHandshakeError('x', otherSideOffered: const ['a']).nothingInCommon, isTrue);
    expect(SSHHandshakeError('x', offered: const ['a']).nothingInCommon, isFalse);
  });
}
