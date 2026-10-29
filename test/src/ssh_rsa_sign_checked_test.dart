// SPDX-License-Identifier: MIT
import 'dart:io';
import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';
import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';

import 'played_server.dart';

/// An RSA signature is given out only once it has been checked with the
/// key's public half.
///
/// An RSA key signs in two halves, one for each of its two primes, and puts
/// them together. If one half comes out wrong and the other right, the
/// signature is wrong, and it gives the key away: whoever sees it and knows
/// what was signed takes the greatest common divisor of two numbers they
/// can compute and has one of the primes (the fault attack of Boneh,
/// DeMillo and Lipton). A server a client signs in to sees every
/// signature, and so does a host that an agent is forwarded to. A half
/// comes out wrong when a machine computes wrongly, and where the
/// arithmetic it is computed with has a fault, which that of the Dart SDK
/// has (ssh_kex_dh_arithmetic_test.dart). The client gave out whatever came
/// of the computation, and where nothing came of it (a key file whose
/// numbers do not fit), it passed the key over without a word.
///
/// Here the wrong half is made by a key whose numbers do not fit: one of
/// its "primes" is a product of two, so everything computed for it is
/// wrong, and everything for the other prime is right.
void main() {
  final real = SSHKeyPair.fromPem(File('test/fixtures/ssh-rsa/ssh_host_rsa_key').readAsStringSync()).single
      as OpenSSHRsaKeyPair;
  final e = BigInt.from(65537);

  // A key as something that makes keys wrongly would make it: the modulus is
  // a product of three primes, and two of them are taken for one.
  final q = real.q;
  final notAPrime = real.p * BigInt.from(1000003);
  final n = notAPrime * q;
  final d = e.modInverse((notAPrime - BigInt.one) * (q - BigInt.one));
  final iqmp = q.modInverse(notAPrime);

  final inOpenSshForm = OpenSSHRsaKeyPair(n, e, d, iqmp, notAPrime, q, 'a key whose numbers do not fit');
  RsaPrivateKey inPemForm(OpenSSHRsaKeyPair key) => RsaPrivateKey(
        BigInt.zero,
        key.n,
        key.e,
        key.d,
        key.p,
        key.q,
        key.d % (key.p - BigInt.one),
        key.d % (key.q - BigInt.one),
        key.iqmp,
      );

  // A key file in which a number was changed.
  final primesDoNotMakeIt = OpenSSHRsaKeyPair(real.n, real.e, real.d, real.iqmp, real.p, real.q + BigInt.two, '');
  final anotherExponent = OpenSSHRsaKeyPair(real.n, BigInt.from(65539), real.d, real.iqmp, real.p, real.q, '');
  final anotherSecret = OpenSSHRsaKeyPair(real.n, real.e, real.d + BigInt.two, real.iqmp, real.p, real.q, '');

  final data = Uint8List.fromList('what a sign-in signs'.codeUnits);

  /// [base] to the power of [exponent], modulo [modulus].
  BigInt byHand(BigInt base, BigInt exponent, BigInt modulus) {
    var result = BigInt.one % modulus;
    var square = base % modulus;
    for (var left = exponent; left > BigInt.zero; left = left >> 1) {
      if (left.isOdd) result = (result * square) % modulus;
      square = (square * square) % modulus;
    }
    return result;
  }

  BigInt asNumber(Uint8List bytes) => bytes.fold(BigInt.zero, (sum, byte) => (sum << 8) | BigInt.from(byte));

  /// What a signature of [data] under [modulus] has to come back to
  /// (RSASSA-PKCS1-v1_5 with SHA-256).
  BigInt expected(BigInt modulus) {
    final hash = SHA256Digest().process(data);
    const digestInfo = [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];
    final length = (modulus.bitLength + 7) ~/ 8;
    final padding = length - 3 - digestInfo.length - hash.length;
    return asNumber(Uint8List.fromList([0, 1, ...List.filled(padding, 0xff), 0, ...digestInfo, ...hash]));
  }

  Matcher notGivenOut(String saying) =>
      throwsA(isA<SSHKeySignError>().having((e) => e.message, 'what it says', contains(saying)));

  /// What an agent that holds [key] answers when it is asked to sign [data]
  /// with it, with [flags] for the kind of signature.
  Future<Uint8List> askedToSign(SSHKeyPair key, int flags) => SSHKeyPairAgent([key]).handleRequest((SSHMessageWriter()
        ..writeUint8(SSHAgentProtocol.signRequest)
        ..writeString(key.toPublicKey().encode())
        ..writeString(data)
        ..writeUint32(flags))
      .takeBytes());

  group('a key that is real signs, and its signature is its own', () {
    test('in the OpenSSH form and in the PEM form, at once and when it is asked to in its own time', () async {
      final key = real.toPublicKey() as SSHRsaPublicKey;
      final signature = real.sign(data);
      expect(signature.type, 'rsa-sha2-256');
      expect(key.verify(data, signature), isTrue);
      expect(byHand(asNumber(signature.signature), real.e, real.n), expected(real.n));
      final pem = inPemForm(real);
      expect(pem.sign(data).signature, signature.signature, reason: 'the same key makes the same signature');
      expect(((await pem.signAsync(data)) as SSHRsaSignature).signature, signature.signature);
    });

    test('an agent that holds it signs with the hash it is asked for, and each signature is the key\'s own', () async {
      final key = real.toPublicKey() as SSHRsaPublicKey;
      for (final holder in <SSHKeyPair>[real, inPemForm(real)]) {
        for (final (flags, kind) in [
          (0, 'ssh-rsa'),
          (SSHAgentProtocol.rsaSha2_256, 'rsa-sha2-256'),
          (SSHAgentProtocol.rsaSha2_512, 'rsa-sha2-512'),
        ]) {
          final answer = SSHMessageReader(await askedToSign(holder, flags));
          expect(answer.readUint8(), SSHAgentProtocol.signResponse, reason: kind);
          final signature = SSHRsaSignature.decode(answer.readString());
          expect(signature.type, kind);
          expect(key.verify(data, signature), isTrue, reason: kind);
        }
      }
    });
  });

  group('a key whose numbers do not fit gives out no signature', () {
    test('one half of whose signatures is wrong: in the OpenSSH form and in the PEM form', () async {
      const words = 'The signature this RSA key made is not its own, and was not given out';
      expect(() => inOpenSshForm.sign(data), notGivenOut(words));
      expect(() => inPemForm(inOpenSshForm).sign(data), notGivenOut(words));
      await expectLater(inPemForm(inOpenSshForm).signAsync(data), notGivenOut(words));
      await expectLater(inOpenSshForm.signAsync(data), notGivenOut(words));
    });

    test('whose primes do not make its modulus: said as that (it was an error of the library that signs)', () {
      const words = 'The numbers of this RSA key do not fit each other';
      expect(() => primesDoNotMakeIt.sign(data), notGivenOut(words));
      expect(() => inPemForm(primesDoNotMakeIt).sign(data), notGivenOut(words));
    });

    test('whose public exponent or secret exponent is another than the one that goes with the rest', () {
      for (final key in [anotherExponent, anotherSecret]) {
        expect(() => key.sign(data), throwsA(isA<SSHKeySignError>()));
        expect(() => inPemForm(key).sign(data), throwsA(isA<SSHKeySignError>()));
      }
    });

    test('an agent that holds such a key answers that it could not sign, under each of the three kinds of '
        'signature', () async {
      for (final key in <SSHKeyPair>[inOpenSshForm, inPemForm(inOpenSshForm), primesDoNotMakeIt, anotherSecret]) {
        for (final flags in [0, SSHAgentProtocol.rsaSha2_256, SSHAgentProtocol.rsaSha2_512]) {
          expect(await askedToSign(key, flags), [SSHAgentProtocol.failure], reason: 'flags $flags');
        }
      }
    });
  });

  test('a key too short to hold a signature with the hash that is asked for says so, and an agent answers that it '
      'could not sign', () async {
    /// The first prime from [from] on (a number that passes for one with every base tried).
    BigInt primeFrom(BigInt from) {
      var candidate = from | BigInt.one;
      while (![2, 3, 5, 7, 11].every((b) => byHand(BigInt.from(b), candidate - BigInt.one, candidate) == BigInt.one)) {
        candidate += BigInt.two;
      }
      return candidate;
    }

    // A key of 511 bits: long enough for SHA-256 with what goes before it, and not for SHA-512.
    final p = primeFrom((BigInt.one << 255) + BigInt.from(12345));
    var q = primeFrom(p + (BigInt.one << 254));
    while (((p - BigInt.one) * (q - BigInt.one)).gcd(e) != BigInt.one) {
      q = primeFrom(q + BigInt.two);
    }
    final short = OpenSSHRsaKeyPair(p * q, e, e.modInverse((p - BigInt.one) * (q - BigInt.one)), q.modInverse(p), p, q, '');
    expect(short.n.bitLength, 511);
    expect((short.toPublicKey() as SSHRsaPublicKey).verify(data, short.sign(data)), isTrue);
    expect(
      () => signRsaChecked(
          n: short.n, e: short.e, d: short.d, p: short.p, q: short.q, data: data, type: SSHRsaSignatureType.sha512),
      notGivenOut('This RSA key is too short for a signature of the kind rsa-sha2-512 (511 bits)'),
    );
    expect(await askedToSign(short, SSHAgentProtocol.rsaSha2_512), [SSHAgentProtocol.failure]);
    final answer = SSHMessageReader(await askedToSign(short, SSHAgentProtocol.rsaSha2_256));
    expect(answer.readUint8(), SSHAgentProtocol.signResponse);
  });

  test('a kind of signature that is none is said to be none', () {
    expect(
      () => signRsaChecked(n: real.n, e: real.e, d: real.d, p: real.p, q: real.q, data: data, type: 'rsa-sha2-384'),
      throwsFormatException,
    );
  });

  group('a client that signs in with such a key', () {
    /// A client with [keys] on a played server that takes keys and nothing
    /// else: how its sign-in ended, and the signatures the server was sent.
    /// Asked about a key, the server says that it would take it, unless it
    /// is [notTaken]; it lets in whoever signs with the key of the fixture.
    Future<({Object? failure, List<Uint8List> signaturesSent})> signIn(
      List<SSHKeyPair> keys, {
      SSHKeyPair? notTaken,
    }) async {
      final server = PlayedServer();
      final client = SSHClient(
        server.socket,
        username: 'deploy',
        identities: keys,
        algorithms: server.speaks,
        keepAliveInterval: null,
      );
      addTearDown(client.close);
      Object? failure;
      var ended = false;
      final tried = client.authenticated.then<void>((_) {
        ended = true;
      }, onError: (Object error) {
        failure = error;
        ended = true;
      });
      await server.greet();
      final asked = SSH_Message_Userauth_Request.decode(await server.next(SSH_Message_Userauth_Request.messageId));
      expect(asked.methodName, 'none');
      server.send([SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode()]);
      final signatures = <Uint8List>[];
      final clock = Stopwatch()..start();
      while (!ended && clock.elapsed < PlayedServer.patience) {
        for (final payload in server.takeSent()) {
          if (payload[0] != SSH_Message_Userauth_Request.messageId) continue;
          final request = SSH_Message_Userauth_Request.decode(payload);
          if (request.signature == null) {
            if (notTaken != null && '${request.publicKey}' == '${notTaken.toPublicKey().encode()}') {
              server.send([SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode()]);
            } else {
              server.takesKey(request);
            }
            continue;
          }
          signatures.add(request.signature!);
          // The server takes the key of the fixture and no other.
          final itsOwn = '${request.publicKey}' == '${real.toPublicKey().encode()}';
          server.send([
            itsOwn
                ? SSH_Message_Userauth_Success().encode()
                : SSH_Message_Userauth_Failure(methodsLeft: const ['publickey']).encode(),
          ]);
        }
        await Future<void>.delayed(const Duration(milliseconds: 5));
      }
      await tried;
      return (failure: failure, signaturesSent: signatures);
    }

    Matcher cutOffByTheKey() => isA<SSHAuthAbortError>()
        .having((e) => e.message, 'what it says', 'The key could not sign')
        .having((e) => e.reason, 'why', isA<SSHKeySignError>());

    test('the key that is real: signed in, with one signature', () async {
      final outcome = await signIn([real]);
      expect(outcome.failure, isNull);
      expect(outcome.signaturesSent, hasLength(1));
    });

    for (final (what, key) in [
      ('one half of whose signatures is wrong', inOpenSshForm),
      ('whose primes do not make its modulus', primesDoNotMakeIt),
    ]) {
      test('$what: the sign-in ends, saying that the key could not sign, and the server is sent no signature',
          () async {
        final outcome = await signIn([key]);
        expect(outcome.failure, cutOffByTheKey());
        expect(outcome.signaturesSent, isEmpty);
      });
    }

    test('such a key before one that is real: the sign-in ends at the first, and the second is not signed with',
        () async {
      final outcome = await signIn([inOpenSshForm, real]);
      expect(outcome.failure, cutOffByTheKey());
      expect(outcome.signaturesSent, isEmpty);
    });

    test('a key that the server does not take, before one it takes: it is passed over, and the one that is taken signs',
        () async {
      final notTaken = SSHKeyPair.fromPem(File('test/fixtures/ssh-ed25519/ssh_host_ed25519_key').readAsStringSync()).single;
      final outcome = await signIn([notTaken, real], notTaken: notTaken);
      expect(outcome.failure, isNull);
      expect(outcome.signaturesSent, hasLength(1));
    });
  });

  test('what such a signature gives away, as the arithmetic underneath makes it: one of the key\'s primes', () {
    // Made here as the key pairs made it, with nothing checked.
    final halves = [
      byHand(expected(n) % notAPrime, d % (notAPrime - BigInt.one), notAPrime),
      byHand(expected(n) % q, d % (q - BigInt.one), q),
    ];
    final wrong = halves[1] + q * (((halves[0] - halves[1]) * iqmp) % notAPrime);
    final comesBackTo = byHand(wrong, e, n);
    expect(comesBackTo, isNot(expected(n)), reason: 'the signature is wrong');
    final given = (comesBackTo - expected(n)).gcd(n);
    expect(given % q, BigInt.zero, reason: 'and what it gives away is a multiple of a prime of the key');
    expect(given < n, isTrue);
    expect(given > BigInt.one, isTrue);
  });
}
