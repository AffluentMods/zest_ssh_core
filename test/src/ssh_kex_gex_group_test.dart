// SPDX-License-Identifier: MIT
import 'dart:async';

import 'package:test/test.dart';
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';

import 'played_group_exchange.dart';

/// The group of a group exchange is one that can be used, or the connection
/// is not made.
///
/// In a group exchange (RFC 4419) the client says how long a group it wants
/// and the server names one: a modulus and a generator. Everything the
/// session carries is then as safe as that group. The client asked for a
/// group of at least 1024 bits and took one of 1024, where a group of that
/// length can be broken by whoever has the means, and with it everything
/// that was recorded of the session; nothing has taken one under 2048 bits
/// for years. And it took any generator: nought and one, with which the
/// secret both sides arrive at is nought or one whatever either does, and
/// one less than the modulus, with which it is one of two numbers.
///
/// With a server played by the test, which offers a group exchange and
/// nothing else and names the group a test gives it. A real OpenSSH server
/// answers the client's request as it is now in
/// test/kex/pq_kex_interop_test.dart.
void main() {
  const groupExchangeOnly = SSHAlgorithms(
    kex: [SSHKexType.dhGexSha256],
    hostkey: [SSHHostkeyType.ed25519],
    cipher: [SSHCipherType.aes256ctr],
    mac: [SSHMacType.hmacSha256],
  );

  // The groups of RFC 2409 (1024 bits) and RFC 3526 (2048 bits): moduli
  // that are primes, with the generator 2.
  final group1 = SSHKexDH.group1();
  final group14 = SSHKexDH.group14();

  /// An odd number of exactly [bits] bits. No prime: a client cannot tell,
  /// and takes a modulus by its length.
  BigInt odd(int bits) => (BigInt.one << (bits - 1)) | (BigInt.one << (bits ~/ 2)) | BigInt.one;

  /// A client that is named the group of [p] and [g] by a played server:
  /// what it had asked for, its public value where it went on with the
  /// exchange (null where it ended the connection), and how its connection
  /// ended.
  Future<({({int shortest, int preferred, int longest}) asked, BigInt? publicValue, Object? endedWith})> named(
    BigInt p,
    BigInt g, {
    SSHAlgorithms algorithms = groupExchangeOnly,
    String kex = 'diffie-hellman-group-exchange-sha256',
    List<String>? lines,
  }) async {
    final server = PlayedGroupExchange(kex: kex);
    final transport = SSHTransport(server.socket,
        algorithms: algorithms, onVerifyHostKey: (type, key) => true, printDebug: (line) => lines?.add('$line'));
    addTearDown(transport.close);
    Object? endedWith;
    unawaited(transport.done.then((_) {}, onError: (Object e) {
      endedWith = e;
    }));
    final asked = await server.request();
    final publicValue = await server.name(p, g);
    await Future<void>.delayed(const Duration(milliseconds: 20));
    return (asked: asked, publicValue: publicValue, endedWith: endedWith);
  }

  void expectTaken(({({int shortest, int preferred, int longest}) asked, BigInt? publicValue, Object? endedWith}) o,
      BigInt p) {
    expect(o.endedWith, isNull);
    expect(o.publicValue, isNotNull, reason: 'the client went on with the exchange');
    expect(o.publicValue! > BigInt.one && o.publicValue! < p - BigInt.one, isTrue,
        reason: 'its public value is one of the group');
  }

  /// Refused as a group of [bits] bits: too short where that is why, and
  /// with [saying] in what the error says. Nothing more is sent.
  void expectRefused(
    ({({int shortest, int preferred, int longest}) asked, BigInt? publicValue, Object? endedWith}) o, {
    required int bits,
    bool tooShort = false,
    required String saying,
    int shortestTaken = 2048,
  }) {
    expect(o.publicValue, isNull, reason: 'the client went on with the exchange, with a public value of its own');
    expect(
      o.endedWith,
      isA<SSHKexGroupError>()
          .having((e) => e.bits, 'the length of the group', bits)
          .having((e) => e.shortestTaken, 'the shortest that is taken', shortestTaken)
          .having((e) => e.tooShort, 'too short', tooShort)
          .having((e) => e.message, 'what it says', contains(saying)),
    );
  }

  group('what the client asks for', () {
    test('a group of 2048 bits at the least, of 8192 at the most, and of 3072 for choice', () async {
      final o = await named(group14.p, group14.g);
      expect(o.asked.shortest, 2048);
      expect(o.asked.longest, 8192);
      // Where the server has a choice it names the shortest group that is at
      // least this long: 3072 bits, the level of everything else this client
      // offers, and not the shortest it takes at all.
      expect(o.asked.preferred, 3072);
      expect((SSHKexDH.gexMin, SSHKexDH.gexPref, SSHKexDH.gexMax), (2048, 3072, 8192));
    });

    test('the same with the algorithms a client has when it is told nothing, and under the older name of the '
        'exchange', () async {
      final byDefault = await named(group14.p, group14.g, algorithms: const SSHAlgorithms());
      expect(byDefault.asked.shortest, 2048);
      expectTaken(byDefault, group14.p);
      final older = await named(
        group14.p,
        group14.g,
        algorithms: const SSHAlgorithms(kex: [SSHKexType.dhGexSha1]),
        kex: 'diffie-hellman-group-exchange-sha1',
      );
      expect(older.asked.shortest, 2048);
      expectTaken(older, group14.p);
    });
  });

  test('the lines a client writes say how long the group is that it was named, and nothing of the group', () async {
    final lines = <String>[];
    final o = await named(odd(4096), BigInt.two, lines: lines);
    expectTaken(o, odd(4096));
    expect(lines.where((line) => line.contains('named a group')),
        ['SSHTransport: the server named a group of 4096 bits for the key exchange']);
    expect(lines.join(' '), isNot(contains('${odd(4096)}')), reason: 'the modulus itself is in no line');
    // A group that is refused is not said to have been named for the exchange: what refused it says its length.
    final refused = <String>[];
    await named(group1.p, group1.g, lines: refused);
    expect(refused.where((line) => line.contains('named a group of 1024 bits for the key exchange')), isEmpty);
  });

  group('a group by the length of its modulus', () {
    test('2048 bits, the group of RFC 3526: taken', () async {
      expect(group14.p.bitLength, 2048);
      expectTaken(await named(group14.p, group14.g), group14.p);
    });

    test('3072 bits, the length that was asked for by choice: taken', () async {
      final o = await named(odd(3072), BigInt.two);
      expectTaken(o, odd(3072));
    });

    test('8192 bits, the longest that was asked for: taken', () async {
      final p = odd(8192);
      expectTaken(await named(p, BigInt.two), p);
    });

    test('1024 bits, the group of RFC 2409: refused as too short, with its length said', () async {
      expect(group1.p.bitLength, 1024);
      final o = await named(group1.p, group1.g);
      expectRefused(o, bits: 1024, tooShort: true, saying: 'of 1024 bits');
      expect(
        (o.endedWith as SSHKexGroupError).message,
        'The server named a group for the key exchange of 1024 bits, and none under 2048 bits is taken',
      );
      expect('${o.endedWith}', startsWith('SSHKexGroupError('));
    });

    for (final bits in [2047, 1536, 768]) {
      test('$bits bits: refused as too short, with its length said', () async {
        expectRefused(await named(odd(bits), BigInt.two), bits: bits, tooShort: true, saying: 'of $bits bits');
      });
    }

    test('8193 bits, one more than was asked for: refused, and not as too short', () async {
      final o = await named(odd(8193), BigInt.two);
      expectRefused(o, bits: 8193, saying: 'of 8193 bits, and none over 8192 bits was asked for');
    });

    test('a modulus that is an even number, which is no prime: refused', () async {
      expectRefused(await named(group14.p + BigInt.one, BigInt.two),
          bits: 2048, saying: 'whose modulus is an even number');
    });
  });

  group('a group by its generator', () {
    for (final (g, what) in [
      (BigInt.two, '2'),
      (BigInt.from(5), '5'),
      (group14.p - BigInt.two, 'the modulus less two, the largest there is'),
    ]) {
      test('$what: taken', () async {
        final o = await named(group14.p, g);
        expect(o.endedWith, isNull);
        expect(o.publicValue, isNotNull);
      });
    }

    for (final (g, what) in [
      (BigInt.zero, 'nought, with which every secret is nought'),
      (BigInt.one, 'one, with which every secret is one'),
      (group14.p - BigInt.one, 'the modulus less one, with which a secret is one of two numbers'),
      (group14.p, 'the modulus itself, which is nought'),
      (group14.p + BigInt.one, 'the modulus and one, which is one'),
    ]) {
      test('$what: refused', () async {
        expectRefused(await named(group14.p, g), bits: 2048, saying: 'with a generator that is none');
      });
    }
  });

  // Where whoever connects has said that an old server may have a group of 1024 bits and no longer one (the
  // app's Compatibility mode, for a server that cannot be updated): such a group is asked for and taken, and
  // everything else is held to what it was held to. Nothing under 1024 bits is ever taken.
  group('for an old server, where groups of 1024 bits are taken', () {
    const oldServer = SSHAlgorithms(
      kex: [SSHKexType.dhGexSha256],
      hostkey: [SSHHostkeyType.ed25519],
      cipher: [SSHCipherType.aes256ctr],
      mac: [SSHMacType.hmacSha256],
      minDhGroupBits: 1024,
    );

    test('nothing is said: 2048 bits is the least that is asked for and taken', () {
      expect(const SSHAlgorithms().minDhGroupBits, 2048);
      expect(groupExchangeOnly.minDhGroupBits, 2048);
      expect(SSHKexDH.gexMinOldServers, 1024);
    });

    test('asks for a group of 1024 bits at the least; still 3072 for choice and 8192 at the most', () async {
      final o = await named(group1.p, group1.g, algorithms: oldServer);
      expect((o.asked.shortest, o.asked.preferred, o.asked.longest), (1024, 3072, 8192));
    });

    test('1024 bits, the group of RFC 2409: taken, where without it it is refused', () async {
      expectTaken(await named(group1.p, group1.g, algorithms: oldServer), group1.p);
      expectRefused(await named(group1.p, group1.g), bits: 1024, tooShort: true, saying: 'of 1024 bits');
    });

    test('2048 and 8192 bits: taken as before', () async {
      expectTaken(await named(group14.p, group14.g, algorithms: oldServer), group14.p);
      expectTaken(await named(odd(8192), BigInt.two, algorithms: oldServer), odd(8192));
    });

    for (final bits in [1023, 768, 512]) {
      test('$bits bits: refused as too short, with 1024 as the shortest taken', () async {
        final o = await named(odd(bits), BigInt.two, algorithms: oldServer);
        expectRefused(o, bits: bits, tooShort: true, saying: 'of $bits bits', shortestTaken: 1024);
        expect((o.endedWith as SSHKexGroupError).message,
            'The server named a group for the key exchange of $bits bits, and none under 1024 bits is taken');
      });
    }

    test('the other checks hold: over 8192 bits, an even modulus, a generator that is none', () async {
      expectRefused(await named(odd(8193), BigInt.two, algorithms: oldServer),
          bits: 8193, saying: 'none over 8192 bits was asked for', shortestTaken: 1024);
      expectRefused(await named(group1.p + BigInt.one, BigInt.two, algorithms: oldServer),
          bits: 1024, saying: 'whose modulus is an even number', shortestTaken: 1024);
      for (final g in [BigInt.zero, BigInt.one, group1.p - BigInt.one]) {
        expectRefused(await named(group1.p, g, algorithms: oldServer),
            bits: 1024, saying: 'with a generator that is none', shortestTaken: 1024);
      }
    });

    test('a shortest under 1024 bits is asked for and taken as 1024, and one over 3072 as 3072', () async {
      const shorter = SSHAlgorithms(
        kex: [SSHKexType.dhGexSha256],
        hostkey: [SSHHostkeyType.ed25519],
        cipher: [SSHCipherType.aes256ctr],
        mac: [SSHMacType.hmacSha256],
        minDhGroupBits: 512,
      );
      final o = await named(odd(768), BigInt.two, algorithms: shorter);
      expect(o.asked.shortest, 1024);
      expectRefused(o, bits: 768, tooShort: true, saying: 'of 768 bits', shortestTaken: 1024);
      expect((SSHKexDH.shortestAskedFor(0), SSHKexDH.shortestAskedFor(1024), SSHKexDH.shortestAskedFor(2048)),
          (1024, 1024, 2048));
      expect(SSHKexDH.shortestAskedFor(4096), 3072);
    });

    test('the check by itself, at the limits', () {
      void taken(BigInt p, BigInt g) => SSHKexDH.requireGroupOfAnExchange(p, g, shortest: 1024);
      taken(group1.p, BigInt.two);
      taken(odd(1024), BigInt.two);
      expect(() => taken(odd(1023), BigInt.two),
          throwsA(isA<SSHKexGroupError>().having((e) => (e.tooShort, e.shortestTaken), 'too short, of', (true, 1024))));
      expect(() => SSHKexDH.requireGroupOfAnExchange(odd(768), BigInt.two, shortest: 0),
          throwsA(isA<SSHKexGroupError>().having((e) => e.shortestTaken, 'the shortest taken', 1024)));
      expect(() => SSHKexDH.requireGroupOfAnExchange(group1.p, BigInt.two),
          throwsA(isA<SSHKexGroupError>().having((e) => e.shortestTaken, 'the shortest taken', 2048)));
    });
  });

  test('the check by itself: what it takes and what it refuses, at the very limits', () {
    void taken(BigInt p, BigInt g) => SSHKexDH.requireGroupOfAnExchange(p, g);
    Matcher refused({required bool tooShort}) =>
        throwsA(isA<SSHKexGroupError>().having((e) => e.tooShort, 'too short', tooShort));

    taken(group14.p, BigInt.two);
    taken(odd(2048), BigInt.two);
    taken(odd(8192), BigInt.two);
    taken(group14.p, group14.p - BigInt.two);
    expect(() => taken(odd(2047), BigInt.two), refused(tooShort: true));
    expect(() => taken(BigInt.zero, BigInt.two), refused(tooShort: true));
    expect(() => taken(odd(8193), BigInt.two), refused(tooShort: false));
    expect(() => taken(odd(2048) + BigInt.one, BigInt.two), refused(tooShort: false));
    expect(() => taken(group14.p, BigInt.one), refused(tooShort: false));
    expect(() => taken(group14.p, group14.p - BigInt.one), refused(tooShort: false));
    // A group that is both too short and no group is too short: that is what its server can mend.
    expect(() => taken(group1.p, BigInt.one), refused(tooShort: true));
  });
}
