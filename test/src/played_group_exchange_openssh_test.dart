// SPDX-License-Identifier: MIT
import 'package:test/test.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';

import 'played_openssh_client.dart';

/// The played group exchange speaks what OpenSSH speaks, and what OpenSSH
/// takes for a group is known from OpenSSH itself.
///
/// The tests of what this package's client does with the group a server
/// names (ssh_kex_gex_group_test.dart) play the server to it
/// (played_group_exchange.dart). Here the same played server is held to a
/// client that was not written with it, the OpenSSH client of the machine:
/// it asks the played server for a group and is named one. What it asks
/// for, and which groups it goes on with, is what this package's client is
/// measured by where it says that it does as OpenSSH does.
///
/// The client looks at no key and no file of whoever runs the tests, and
/// its own account of what it did is checked for that. Where a machine has
/// no OpenSSH client these tests are skipped.
void main() {
  final clients = OpenSshClient.found();
  if (clients.isEmpty) {
    test('the played group exchange speaks what OpenSSH speaks', () {}, skip: 'this machine has no OpenSSH client');
    return;
  }

  // The groups of RFC 2409 (1024 bits) and RFC 3526 (2048 bits).
  final group1 = SSHKexDH.group1();
  final group14 = SSHKexDH.group14();

  /// What the client did when it was named the group of [p] and [g]: its
  /// public value where it went on, null where it ended the connection.
  Future<BigInt?> named(OpenSshClient client, BigInt p, BigInt g) async {
    final run = await client.groupExchange();
    addTearDown(run.end);
    await run.group.request();
    final publicValue = await run.group.name(p, g);
    if (publicValue == null) expect(await run.exitCode, 255, reason: run.said.join('\n'));
    expect(run.lookedAtOthersKeys, 0, reason: 'the client looked at a key that is not of the run');
    return publicValue;
  }

  for (final client in clients) {
    group('the OpenSSH client $client', () {
      test('asks for a group of 2048 bits at the least and of 8192 at the most', () async {
        final run = await client.groupExchange();
        addTearDown(run.end);
        final asked = await run.group.request();
        expect(asked.shortest, 2048);
        expect(asked.longest, 8192);
        expect(asked.preferred, inInclusiveRange(2048, 8192));
        // (With the 256-bit cipher it is offered here, OpenSSH would like the longest group there is. This
        // package's client would like one of 3072 bits whatever the cipher: never a longer one than OpenSSH.)
        expect(asked.preferred, greaterThanOrEqualTo(SSHKexDH.gexPref));
        expect(run.lookedAtOthersKeys, 0, reason: 'the client looked at a key that is not of the run');
      });

      test('named the group of RFC 3526 (2048 bits), goes on with a public value of that group', () async {
        final e = await named(client, group14.p, group14.g);
        expect(e, isNotNull);
        expect(e! > BigInt.one && e < group14.p - BigInt.one, isTrue);
      });

      test('named the group of RFC 2409 (1024 bits), ends the connection', () async {
        expect(await named(client, group1.p, group1.g), isNull);
      });

      test('named a group with a generator of one, ends the connection', () async {
        expect(await named(client, group14.p, BigInt.one), isNull);
      });

      test('named a group with the modulus less one for a generator, ends the connection', () async {
        expect(await named(client, group14.p, group14.p - BigInt.one), isNull);
      });

      test('named a group whose modulus is an even number, ends the connection', () async {
        expect(await named(client, group14.p + BigInt.one, group14.g), isNull);
      });
    });
  }
}
