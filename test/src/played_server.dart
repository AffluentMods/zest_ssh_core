// SPDX-License-Identifier: MIT
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as ed25519;
import 'package:pointycastle/export.dart'
    show AEADParameters, AESEngine, BlockCipher, GCMBlockCipher, InvalidCipherTextException, KeyParameter, SHA256Digest;
import 'package:zest_ssh_core/dartssh2.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_cipher_chacha20_poly1305.dart';
import 'package:zest_ssh_core/src/exceptions/ssh_exceptions.dart' show SSHMacMismatchException;
import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
import 'package:zest_ssh_core/src/message/msg_channel.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/message/msg_kex_ecdh.dart';
import 'package:zest_ssh_core/src/message/msg_service.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_kex_utils.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:zest_ssh_core/src/ssh_packet.dart';

/// A server played by a test to a real client, for what no real server can
/// be made to do when a test wants it: an answer and what follows it in one
/// read, a refusal a real server never gives, a channel that will not take
/// more, new keys under other algorithms than the ones before.
///
/// It speaks the protocol as a server does: the versions, a key exchange
/// (curve25519, an Ed25519 host key made for the test, the strict exchange
/// unless it is told not to name it), then what its [PlayedSuite] says
/// (aes256-ctr with hmac-sha2-256 where nothing else is asked for), the
/// service, and the first sign-in it is asked for, which it accepts whatever
/// it is. From there the test says what the server sends, message by message
/// ([send]), and reads what the client sends ([next], [takeSent]). What is
/// handed over in one [send] reaches the client in one read. It can ask for
/// new keys at any time after the first ([rekey]), under another suite if
/// the test says so.
///
/// The client is whoever is made on [socket]: an [SSHClient] of a test's
/// own ([signedIn] makes a plain one), or an application's own connection
/// code, handed the socket where it would open one. Or it is a program on
/// the other end of a [PlayedLine] of the test's: played_openssh_client.dart
/// puts the OpenSSH client of the machine there, which is what holds this
/// server to the real thing (played_server_openssh_test.dart). Nothing here
/// is of a test framework: what goes wrong is thrown as a [StateError],
/// which fails a test in any of them, and whoever makes a client closes it.
///
/// What the client sends is read under the keys in force and under nothing
/// else: a packet that those keys do not open ends the test, and where it
/// reads as a packet in the clear the error says so.
///
/// (The key exchange itself, with a server that plays it wrong, is in
/// ssh_transport_kex_reply_test.dart, which has its own.)
class PlayedServer {
  /// A server with nobody connected to it yet. Its packets and the client's
  /// come under [suite] once keys are in force, or its own under [toClient]
  /// where the two directions are to differ. It names the strict key
  /// exchange unless [strict] is false, as a server older than OpenSSH 9.6
  /// does not.
  ///
  /// It shows an Ed25519 host key made for the test, or [hostKey]: a key of
  /// another kind, or what a test makes up for one.
  PlayedServer({
    PlayedLine? line,
    PlayedSuite suite = PlayedSuite.ctr,
    PlayedSuite? toClient,
    this.strict = true,
    PlayedHostKey? hostKey,
  })  : _line = line ?? _Wire(),
        _fromClientSuite = suite,
        _toClientSuite = toClient ?? suite,
        _hostKey = hostKey ?? PlayedHostKey.ed25519();

  /// Whether the server names the strict key exchange.
  final bool strict;

  /// The server's end of a connection, for a client to be made on.
  SSHSocket get socket {
    final line = _line;
    if (line is! _Wire) throw StateError('this played server is on a line of the test\'s own');
    return line;
  }

  /// The client [signedIn] made.
  SSHClient get client => _client!;
  SSHClient? _client;

  final PlayedLine _line;
  PlayedSuite _fromClientSuite;
  PlayedSuite _toClientSuite;

  /// The server's host key: one for all its exchanges, as a server has,
  /// unless a test has it show another when it asks for new keys.
  PlayedHostKey _hostKey;

  /// What protects the client's packets and the server's own, and what the
  /// client's will come under from its next NEWKEYS on.
  _Protection _fromClient = _Clear();
  _Protection _toClient = _Clear();
  _Protection? _fromClientNext;

  /// The numbers of the next packet of each side. They count every packet
  /// from the first, and start again at each NEWKEYS where the strict
  /// exchange is in force.
  var _readNumber = 0;
  var _sentNumber = 0;
  var _strictInForce = false;

  /// The first exchange's hash, which a connection keeps for all its keys.
  Uint8List? _sessionId;

  /// What names this connection for as long as it lasts, once its first
  /// exchange is over: what a key signs along with a sign-in, so that its
  /// signature is of use on no other connection.
  Uint8List get sessionId => _sessionId!;

  /// The client's version line, once it has come.
  String? _clientVersion;

  /// What the client wrote and was not read as packets yet.
  final _raw = BytesBuilder(copy: true);

  /// What the client sent and nobody has asked for yet.
  final _unread = <Uint8List>[];

  var _nextChannel = 40;

  static const version = 'SSH-2.0-OpenSSH_9.6';

  /// How long the client is given to do something a test waits for.
  static const patience = Duration(seconds: 10);

  /// The algorithms a played server speaks where it is told nothing else.
  /// A client that offers others as well agrees on these.
  static const algorithms = SSHAlgorithms(
    kex: [SSHKexType.x25519],
    hostkey: [SSHHostkeyType.ed25519],
    cipher: [SSHCipherType.aes256ctr],
    mac: [SSHMacType.hmacSha256],
  );

  /// Algorithms that agree with this server on what it speaks now, and
  /// offer nothing else.
  SSHAlgorithms get speaks => SSHAlgorithms(
        kex: const [SSHKexType.x25519],
        hostkey: [
          const [
            SSHHostkeyType.ed25519,
            SSHHostkeyType.rsaSha512,
            SSHHostkeyType.rsaSha256,
            SSHHostkeyType.rsaSha1,
            SSHHostkeyType.ecdsa521,
            SSHHostkeyType.ecdsa384,
            SSHHostkeyType.ecdsa256,
          ].firstWhere((type) => type.name == _hostKey.algorithm),
        ],
        cipher: {_fromClientSuite.cipher, _toClientSuite.cipher}.toList(),
        mac: {_fromClientSuite.mac ?? SSHMacType.hmacSha256, _toClientSuite.mac ?? SSHMacType.hmacSha256}.toList(),
      );

  /// A client signed in to a played server: a plain one, with no
  /// keep-alives, or the one [client] makes on the connection, with the
  /// algorithms it is given (those the server [speaks]) or others of its
  /// own that agree with the server. Whoever asks closes it.
  static Future<PlayedServer> signedIn({
    SSHClient Function(SSHSocket socket, SSHAlgorithms algorithms)? client,
    PlayedSuite suite = PlayedSuite.ctr,
    PlayedSuite? toClient,
    bool strict = true,
  }) async {
    final server = PlayedServer(suite: suite, toClient: toClient, strict: strict);
    final made = client != null
        ? client(server.socket, server.speaks)
        : SSHClient(server.socket, username: 'deploy', algorithms: server.speaks, keepAliveInterval: null);
    server._client = made;
    await server.letIn();
    await made.authenticated.timeout(patience);
    return server;
  }

  /// Plays the server to whoever is on the line, up to the point where they
  /// are signed in: the versions, the key exchange, the service, and a yes
  /// to the first sign-in they ask for. With [afterNewKeys] the server says
  /// those messages right after its NEWKEYS, as [exchangeKeys] has it.
  Future<void> letIn({List<Uint8List> afterNewKeys = const []}) async {
    await greet(afterNewKeys: afterNewKeys);
    await next(SSH_Message_Userauth_Request.messageId);
    send([SSH_Message_Userauth_Success().encode()]);
  }

  /// Says yes to [question], a request to sign in with a key that carries
  /// no signature: the server would take that key, which it names as the
  /// question did (SSH_MSG_USERAUTH_PK_OK, RFC 4252, 7). The client signs
  /// with the key then, and sends the request again with the signature.
  void takesKey(SSH_Message_Userauth_Request question) => send([
        SSH_Message_Userauth_PkOk(
          publicKeyAlgorithm: question.publicKeyAlgorithm!,
          publicKey: question.publicKey!,
        ).encode(),
      ]);

  /// Plays the server to whoever is on the line, up to the point where they
  /// ask to be signed in: the versions, the key exchange and the service.
  /// What they ask for then is the test's to answer. With [afterNewKeys]
  /// the server says those messages right after its NEWKEYS, as
  /// [exchangeKeys] has it.
  Future<void> greet({List<Uint8List> afterNewKeys = const []}) async {
    await exchangeKeys(afterNewKeys: afterNewKeys);
    await next(SSH_Message_Service_Request.messageId);
    send([SSH_Message_Service_Accept('ssh-userauth').encode()]);
  }

  /// Plays the server to whoever is on the line, up to the end of the first
  /// key exchange: the versions, the proposals, the answer and the new keys
  /// of both sides. The service the client asks for next is the test's to
  /// answer.
  ///
  /// With [first] the server sends those messages before its proposal, with
  /// [beforeAnswer] between the proposals and its answer, and with
  /// [beforeNewKeys] between its answer and its NEWKEYS, once the client
  /// has had the answer and looked at the key. A server that keeps to the
  /// order of an exchange sends none of them; whoever sits on the line can
  /// put them there, since nothing is under keys yet.
  ///
  /// With [afterNewKeys] the server sends those messages right after its
  /// NEWKEYS, under its new keys and in the same read: where a server says
  /// what it has to say of itself (SSH_MSG_EXT_INFO), which reaches a
  /// client while it may still be looking at the server's key.
  Future<void> exchangeKeys({
    List<Uint8List> first = const [],
    List<Uint8List> beforeAnswer = const [],
    List<Uint8List> beforeNewKeys = const [],
    List<Uint8List> afterNewKeys = const [],
  }) async {
    final proposal = _proposal();
    _line.feed([
      ...latin1.encode('$version\r\n'),
      for (final payload in [...first, proposal]) ..._sealed(payload),
    ]);
    await _proposals(proposal);
    if (beforeAnswer.isNotEmpty) send(beforeAnswer);
    await _answerAndNewKeys(beforeNewKeys: beforeNewKeys, afterNewKeys: afterNewKeys);
  }

  /// Asks the client for new keys and plays the exchange to its end, as a
  /// server does when it has sent enough under the old ones. With [suite]
  /// (and [toClient], for the server's own packets where they are to
  /// differ) the server proposes other algorithms than it did before: until
  /// each side's NEWKEYS its packets come as they did, and after it under
  /// what was agreed on now. With [hostKey] it shows that key from here on,
  /// which no server does to a connection that is open: whoever has got
  /// into one does.
  Future<void> rekey({PlayedSuite? suite, PlayedSuite? toClient, PlayedHostKey? hostKey}) async {
    await beginRekey(suite: suite, toClient: toClient, hostKey: hostKey);
    await finishRekey();
  }

  /// The first half of [rekey], for a test that does something while the
  /// exchange is under way: the server's proposal goes out, and the client's
  /// proposal and its start of the exchange are read. Both sides have
  /// compared the proposals by then, and the answer has not come: whatever
  /// either side sends until [finishRekey] goes as it did before.
  Future<void> beginRekey({PlayedSuite? suite, PlayedSuite? toClient, PlayedHostKey? hostKey}) async {
    if (_sessionId == null) throw StateError('new keys can be asked for once the first exchange is over');
    if (suite != null) _fromClientSuite = _toClientSuite = suite;
    if (toClient != null) _toClientSuite = toClient;
    if (hostKey != null) _hostKey = hostKey;
    final proposal = _proposal();
    send([proposal]);
    await _proposals(proposal);
  }

  /// The second half of [rekey]: the answer and the server's NEWKEYS, and
  /// the client's NEWKEYS.
  Future<void> finishRekey() => _answerAndNewKeys();

  /// The server's proposal: one key exchange under both its names, one kind
  /// of host key, and the suites of the two directions. A suite that checks
  /// its packets by itself has no use for the MAC that is named with it.
  Uint8List _proposal() => SSH_Message_KexInit(
        kexAlgorithms: [
          'curve25519-sha256',
          'curve25519-sha256@libssh.org',
          if (strict) 'kex-strict-s-v00@openssh.com',
        ],
        serverHostKeyAlgorithms: [_hostKey.algorithm],
        encryptionClientToServer: [_fromClientSuite.cipher.name],
        encryptionServerToClient: [_toClientSuite.cipher.name],
        macClientToServer: [(_fromClientSuite.mac ?? SSHMacType.hmacSha256).name],
        macServerToClient: [(_toClientSuite.mac ?? SSHMacType.hmacSha256).name],
        compressionClientToServer: const ['none'],
        compressionServerToClient: const ['none'],
        firstKexPacketFollows: false,
      ).encode();

  /// The proposals the client has made, in order: its first, and one for
  /// each time new keys were asked for.
  final clientProposals = <SSH_Message_KexInit>[];

  /// An exchange whose proposals are in and whose answer has not gone out:
  /// the two proposals and the client's start of the exchange.
  ({Uint8List proposal, Uint8List clientProposal, Uint8List clientPublic})? _underWay;

  /// What follows the server's [proposal] in an exchange: the client's
  /// proposal, and its start of the exchange.
  Future<void> _proposals(Uint8List proposal) async {
    final clientProposal = await next(SSH_Message_KexInit.messageId);
    clientProposals.add(SSH_Message_KexInit.decode(clientProposal));
    if (_sessionId == null) {
      _strictInForce = strict &&
          SSH_Message_KexInit.decode(clientProposal).kexAlgorithms.contains('kex-strict-c-v00@openssh.com');
    }
    final clientPublic =
        SSH_Message_KexECDH_Init.decode(await next(SSH_Message_KexECDH_Init.messageId)).ecdhPublicKey;
    _underWay = (proposal: proposal, clientProposal: clientProposal, clientPublic: clientPublic);
  }

  /// The rest of the exchange that is under way: the answer signed by the
  /// host key, and the new keys of both sides. With [beforeNewKeys] the
  /// answer goes out by itself, and those messages come with the server's
  /// NEWKEYS a moment later. With [afterNewKeys] those messages follow the
  /// server's NEWKEYS in the same read, under its new keys.
  Future<void> _answerAndNewKeys({
    List<Uint8List> beforeNewKeys = const [],
    List<Uint8List> afterNewKeys = const [],
  }) async {
    final exchange = _underWay;
    if (exchange == null) throw StateError('no exchange is under way');
    _underWay = null;
    final (:proposal, :clientProposal, :clientPublic) = exchange;
    final mine = SSHKexX25519();
    final secret = SSHKexUtils.encodeSharedSecretMpint(mine.computeSecret(clientPublic));
    final blob = _hostKey.blob;
    final hash = SSHKexUtils.computeExchangeHash(
      digest: SHA256Digest(),
      clientVersion: _clientVersion!,
      serverVersion: version,
      clientKexInit: clientProposal,
      serverKexInit: proposal,
      hostKey: blob,
      clientPublicKey: clientPublic,
      serverPublicKey: mine.publicKey,
      sharedSecret: secret,
    );
    final sessionId = _sessionId ??= hash;
    final answer = (SSHMessageWriter()
          ..writeUint8(SSH_Message_KexECDH_Reply.messageId)
          ..writeString(blob)
          ..writeString(mine.publicKey)
          ..writeString(_hostKey.sign(hash)))
        .takeBytes();

    // What the client sends after its NEWKEYS comes under the new keys. That
    // is said before the answer goes out, since its NEWKEYS follows at once.
    _fromClientNext = _Protection.of(_fromClientSuite,
        secret: secret, hash: hash, sessionId: sessionId, toClient: false);
    // The answer and the server's NEWKEYS still go out as before; what the
    // server sends after them is under the new keys.
    if (beforeNewKeys.isNotEmpty) {
      send([answer]);
      await settle();
    }
    final packets = [
      for (final payload in [if (beforeNewKeys.isEmpty) answer, ...beforeNewKeys, SSH_Message_NewKeys().encode()])
        _sealed(payload),
    ];
    _toClient =
        _Protection.of(_toClientSuite, secret: secret, hash: hash, sessionId: sessionId, toClient: true);
    if (_strictInForce) _sentNumber = 0;
    packets.addAll([for (final payload in afterNewKeys) _sealed(payload)]);
    _line.feed([for (final packet in packets) ...packet]);
    await next(SSH_Message_NewKeys.messageId);
  }

  /// Hands [payloads] to the client, in order and in one read.
  void send(List<Uint8List> payloads) => _line.feed([for (final payload in payloads) ..._sealed(payload)]);

  /// Hands the client [bytes] as they are, with nothing made a packet of:
  /// for what no server would send.
  void sendRaw(List<int> bytes) => _line.feed(bytes);

  /// Hands [payloads] to the client as [send] does, once [change] has had
  /// the packets they go out as, each as it would have left the server:
  /// what a line that is failing, or whoever sits on it, makes of them.
  /// Under keys a packet ends with its check value, which is
  /// [PlayedSuite.checkLength] bytes long.
  void sendChanged(List<Uint8List> payloads, void Function(List<Uint8List> packets) change) {
    final packets = [for (final payload in payloads) _sealed(payload)];
    change(packets);
    _line.feed([for (final packet in packets) ...packet]);
  }

  Uint8List _sealed(Uint8List payload) {
    final packet = _toClient.seal(payload, _sentNumber);
    _sentNumber = (_sentNumber + 1) & 0xFFFFFFFF;
    return packet;
  }

  /// What the client has sent and nobody has asked for, in order.
  List<Uint8List> takeSent() {
    _read();
    final sent = List.of(_unread);
    _unread.clear();
    return sent;
  }

  /// The next message with the number [id] that the client sends. What it
  /// sends of other kinds is kept for whoever asks for those.
  Future<Uint8List> next(int id) async {
    final waited = Stopwatch()..start();
    while (true) {
      // Asked before reading: what a client wrote before it left is all
      // there by the time it is known to have left.
      final gone = _line.clientGone;
      _read();
      final at = _unread.indexWhere((p) => p[0] == id);
      if (at >= 0) return _unread.removeAt(at);
      if (gone || waited.elapsed > patience) {
        throw StateError('the client ${gone ? 'ended the connection and had not sent' : 'did not send'} message $id '
            '(it sent ${_unread.map((p) => p[0])})${_inTheClear(_raw.toBytes())}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 2));
    }
  }

  /// Whether the client has sent a message with the number [id] that nobody
  /// has asked for, after it was given a moment to.
  Future<bool> sent(int id) async {
    await settle();
    _read();
    return _unread.any((p) => p[0] == id);
  }

  /// The server's side of the connection ends, with nothing more said: a
  /// network that broke, a host that went down.
  void hangUp() => _line.end();

  /// Lets the client do what it does with what it was handed.
  Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 30));

  /// Waits for the client to ask for a channel, and gives it one.
  Future<PlayedChannel> confirmChannel({int window = 2 * 1024 * 1024, int maxPacket = 32768}) async {
    final open = SSH_Message_Channel_Open.decode(await next(SSH_Message_Channel_Open.messageId));
    final mine = _nextChannel++;
    send([
      SSH_Message_Channel_Confirmation(
        recipientChannel: open.senderChannel,
        senderChannel: mine,
        initialWindowSize: window,
        maximumPacketSize: maxPacket,
        data: Uint8List(0),
      ).encode(),
    ]);
    return PlayedChannel._(this, open, mine);
  }

  /// Reads what the client wrote since this was last done: its version
  /// line first, then packets, each under what protects the client's
  /// packets at that point. Its NEWKEYS is the last under the old keys.
  void _read() {
    final more = _line.takeOutput();
    if (more.isNotEmpty) _raw.add(more);
    if (_raw.isEmpty) return;
    final bytes = _raw.takeBytes();
    var at = 0;
    if (_clientVersion == null) {
      final end = bytes.indexOf(0x0A);
      if (end < 0) {
        _raw.add(bytes);
        return;
      }
      _clientVersion = latin1.decode(bytes.sublist(0, end > 0 && bytes[end - 1] == 0x0D ? end - 1 : end));
      at = end + 1;
    }
    while (at < bytes.length) {
      final rest = Uint8List.sublistView(bytes, at);
      ({Uint8List payload, int taken})? opened;
      try {
        opened = _fromClient.open(rest, _readNumber);
      } on StateError catch (e) {
        throw StateError('${e.message}${_inTheClear(rest)}');
      }
      if (opened == null) {
        // Part of a packet, where the line hands over what was written as
        // it comes. Where it hands over whole packets, the keys in force do
        // not open what is there.
        if (_line.wholePackets) {
          throw StateError('what the client sent is not a packet under the keys in force${_inTheClear(rest)}');
        }
        break;
      }
      at += opened.taken;
      _readNumber = (_readNumber + 1) & 0xFFFFFFFF;
      _unread.add(opened.payload);
      if (opened.payload.length == 1 && opened.payload[0] == SSH_Message_NewKeys.messageId) {
        final keys = _fromClientNext;
        if (keys == null) throw StateError('the client sent NEWKEYS with no exchange for it to end');
        _fromClient = keys;
        _fromClientNext = null;
        if (_strictInForce) _readNumber = 0;
      }
    }
    if (at < bytes.length) _raw.add(Uint8List.sublistView(bytes, at));
  }

  /// What to add to an error about [bytes] that the keys in force do not
  /// open: that they read as a packet in the clear, where they do.
  String _inTheClear(Uint8List bytes) {
    if (_fromClient is _Clear || bytes.isEmpty) return '';
    try {
      final clear = _Clear().open(bytes, 0);
      if (clear == null) return '';
      return ': it reads as message ${clear.payload[0]} in the clear, with keys in force';
    } on StateError {
      return '';
    }
  }
}

/// The host key a played server shows: the algorithm it names for it in its
/// proposal, the key as it sends it, and what it signs an exchange with.
class PlayedHostKey {
  /// A host key that is whatever a test says: also a key no server has, and
  /// a signature that is none.
  PlayedHostKey(this.algorithm, this.blob, this.sign);

  /// An Ed25519 key made here.
  factory PlayedHostKey.ed25519() {
    final signing = ed25519.SigningKey.generate();
    return PlayedHostKey.of(
      OpenSSHEd25519KeyPair(
        Uint8List.fromList(signing.verifyKey.asTypedList),
        Uint8List.fromList(signing.asTypedList),
        'played server',
      ),
      algorithm: 'ssh-ed25519',
    );
  }

  /// The key of [pair], which signs as that key pair signs, named in the
  /// proposal as [algorithm].
  factory PlayedHostKey.of(SSHKeyPair pair, {required String algorithm}) =>
      PlayedHostKey(algorithm, pair.toPublicKey().encode(), (hash) => pair.sign(hash).encode());

  /// The name of the host key algorithm in the server's proposal.
  final String algorithm;

  /// The key as the server sends it.
  final Uint8List blob;

  /// The signature the server sends for the hash of an exchange.
  final Uint8List Function(Uint8List hash) sign;
}

/// What protects the packets of one direction once keys are in force: a
/// cipher, and the MAC that checks its packets where the cipher does not
/// check them by itself.
class PlayedSuite {
  const PlayedSuite(this.cipher, {this.mac});

  final SSHCipherType cipher;

  /// The MAC, for a cipher that needs one.
  final SSHMacType? mac;

  /// aes256-ctr with hmac-sha2-256: the packet encrypted whole, the check
  /// value made of it as it was before.
  static const ctr = PlayedSuite(SSHCipherType.aes256ctr, mac: SSHMacType.hmacSha256);

  /// aes256-ctr with hmac-sha2-256-etm@openssh.com: the length in the clear,
  /// the check value made of what was encrypted.
  static const ctrEtm = PlayedSuite(SSHCipherType.aes256ctr, mac: SSHMacType.hmacSha256Etm);

  /// aes256-cbc with hmac-sha2-256, which servers of the past speak.
  static const cbc = PlayedSuite(SSHCipherType.aes256cbc, mac: SSHMacType.hmacSha256);

  /// aes256-gcm@openssh.com.
  static const gcm = PlayedSuite(SSHCipherType.aes256gcm);

  /// chacha20-poly1305@openssh.com.
  static const chacha = PlayedSuite(SSHCipherType.chacha20poly1305);

  /// How long the check value at the end of each packet is, in bytes: the
  /// MAC, or the tag of a cipher that checks its packets by itself.
  int get checkLength => mac?.createMac(Uint8List(mac!.keySize)).macSize ?? 16;

  @override
  String toString() => mac == null ? cipher.name : '${cipher.name} with ${mac!.name}';
}

/// The connection as a played server holds it: a way to hand the other side
/// bytes, and what the other side wrote.
abstract class PlayedLine {
  /// Hands [bytes] to the other side, as one read where the line can.
  void feed(List<int> bytes);

  /// What the other side wrote since this was last asked.
  Uint8List takeOutput();

  /// Nothing more comes from the server: its side of the connection is over.
  void end();

  /// Whether what the other side writes is here packet by packet, each
  /// whole or not at all. Then bytes that are no whole packet under the
  /// keys in force are a fault and not a packet on its way.
  bool get wholePackets;

  /// Whether the other side has ended the connection: nothing more comes
  /// from it, and whoever waits for more need not.
  bool get clientGone;
}

/// A channel the client opened on a [PlayedServer], and the messages a
/// server sends on one.
class PlayedChannel {
  PlayedChannel._(this._server, this.asked, this.serverId);

  final PlayedServer _server;

  /// What the client asked for.
  final SSH_Message_Channel_Open asked;

  /// The server's number for the channel: what the client addresses.
  final int serverId;

  /// The client's number for the channel: what the server addresses.
  int get clientId => asked.senderChannel;

  /// The next request the client makes on a channel.
  Future<SSH_Message_Channel_Request> nextRequest() async =>
      SSH_Message_Channel_Request.decode(await _server.next(SSH_Message_Channel_Request.messageId));

  /// Yes to a request.
  Uint8List get success => SSH_Message_Channel_Success(recipientChannel: clientId).encode();

  /// No to a request.
  Uint8List get failure => SSH_Message_Channel_Failure(recipientChannel: clientId).encode();

  /// What a program printed.
  Uint8List data(String text) =>
      SSH_Message_Channel_Data(recipientChannel: clientId, data: Uint8List.fromList(utf8.encode(text))).encode();

  /// What a program printed as errors.
  Uint8List errorData(String text) => SSH_Message_Channel_Extended_Data(
        recipientChannel: clientId,
        dataTypeCode: SSH_Message_Channel_Extended_Data.dataTypeStderr,
        data: Uint8List.fromList(utf8.encode(text)),
      ).encode();

  /// How a program ended.
  Uint8List exitStatus(int status) =>
      SSH_Message_Channel_Request.exitStatus(recipientChannel: clientId, exitStatus: status).encode();

  /// The signal that ended a program.
  Uint8List exitSignal(String name) => SSH_Message_Channel_Request.exitSignal(
        recipientChannel: clientId,
        exitSignalName: name,
        errorMessage: '',
        languageTag: '',
      ).encode();

  /// No more from the program.
  Uint8List get eof => SSH_Message_Channel_EOF(recipientChannel: clientId).encode();

  /// The channel is over.
  Uint8List get close => SSH_Message_Channel_Close(recipientChannel: clientId).encode();
}

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// How much goes after a payload of [payloadLength] bytes so that it, the
/// byte that says how much, and the padding come to whole blocks of [block]
/// bytes: at least four bytes. The four bytes of the length are not counted,
/// as a suite does not count them that leaves them out of what it encrypts.
int _paddingAfter(int payloadLength, int block) {
  final padding = block - ((payloadLength + 1) % block);
  return padding < 4 ? padding + block : padding;
}

/// The bytes that follow the length of a packet whose length is not
/// encrypted with it: how much padding, [payload], the padding.
Uint8List _body(Uint8List payload, int block) {
  final padding = _paddingAfter(payload.length, block);
  return Uint8List(1 + payload.length + padding)
    ..[0] = padding
    ..setRange(1, 1 + payload.length, payload);
}

Uint8List _uint32(int value) => Uint8List(4)..buffer.asByteData().setUint32(0, value);

/// The length a packet begins with, where it is one a packet can have:
/// whole blocks of [block] bytes with [counted] bytes of the length among
/// them. Anything else is not a packet.
int _lengthOf(Uint8List bytes, {required int block, required int counted}) {
  final length = ByteData.sublistView(bytes).getUint32(0);
  if (length < 8 || length > SSHPacket.maxLength || (length + counted) % block != 0) {
    throw StateError('what the client sent is not a packet under the keys in force');
  }
  return length;
}

/// The payload in the [length] bytes that follow a packet's length: after
/// the byte that says how much padding, before the padding.
Uint8List _payloadIn(Uint8List body, int length) {
  final padding = body[0];
  if (padding < 4 || padding > length - 1) {
    throw StateError('what the client sent is not a packet under the keys in force');
  }
  return Uint8List.fromList(Uint8List.sublistView(body, 1, length - padding));
}

/// What protects the packets of one direction of a connection: nothing
/// before the first NEWKEYS, then the keys of a [PlayedSuite]. Each is used
/// for one direction and so for one of the two things only.
abstract class _Protection {
  /// The keys of [suite] that follow from an exchange, for the server's own
  /// packets ([toClient]) or the client's.
  static _Protection of(
    PlayedSuite suite, {
    required Uint8List secret,
    required Uint8List hash,
    required Uint8List sessionId,
    required bool toClient,
  }) {
    Uint8List key(SSHDeriveKeyType type, int size) => SSHKexUtils.deriveKey(
          digest: SHA256Digest(),
          sharedSecret: secret,
          exchangeHash: hash,
          keyType: type,
          sessionId: sessionId,
          keySize: size,
        );
    final cipher = suite.cipher;
    final cipherKey = key(toClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey, cipher.keySize);
    if (cipher.isChaCha) return _ChaCha(cipherKey);
    final iv = key(toClient ? SSHDeriveKeyType.serverIV : SSHDeriveKeyType.clientIV, cipher.ivSize);
    if (cipher.isAead) return _Gcm(cipherKey, iv);
    final mac = suite.mac;
    if (mac == null) throw StateError('${cipher.name} needs a MAC');
    final macKey = key(toClient ? SSHDeriveKeyType.serverMacKey : SSHDeriveKeyType.clientMacKey, mac.keySize);
    final block = cipher.createCipher(cipherKey, iv, forEncryption: toClient);
    return mac.isEtm ? _EncryptedThenChecked(block, mac, macKey) : _CheckedThenEncrypted(block, mac, macKey);
  }

  /// [payload] as the packet with the number [number].
  Uint8List seal(Uint8List payload, int number);

  /// The packet [bytes] begin with, as the one with the number [number]:
  /// its payload and how many bytes it took, or null where [bytes] do not
  /// hold all of it yet. Throws a [StateError] where they begin with no
  /// packet that these keys open.
  ({Uint8List payload, int taken})? open(Uint8List bytes, int number);
}

/// Before any keys: packets in the clear, with no check value.
class _Clear implements _Protection {
  @override
  Uint8List seal(Uint8List payload, int number) => SSHPacket.pack(payload, align: 8);

  @override
  ({Uint8List payload, int taken})? open(Uint8List bytes, int number) {
    if (bytes.length < 4) return null;
    final length = _lengthOf(bytes, block: 8, counted: 4);
    if (bytes.length < 4 + length) return null;
    return (payload: _payloadIn(Uint8List.sublistView(bytes, 4), length), taken: 4 + length);
  }
}

/// A block cipher with a MAC of the first kind (RFC 4253, 6): the check
/// value is made of the packet as it is before it is encrypted, and the
/// packet is encrypted whole, its length with it.
class _CheckedThenEncrypted implements _Protection {
  _CheckedThenEncrypted(this._cipher, this._mac, this._macKey);

  final BlockCipher _cipher;
  final SSHMacType _mac;
  final Uint8List _macKey;

  /// The first block of the packet being read, once it is decrypted: the
  /// cipher goes on from where it is, so a block is decrypted once.
  Uint8List? _first;

  @override
  Uint8List seal(Uint8List payload, int number) {
    final clear = SSHPacket.pack(payload, align: 16);
    final sealed = Uint8List(clear.length);
    for (var i = 0; i < clear.length; i += 16) {
      _cipher.processBlock(clear, i, sealed, i);
    }
    return Uint8List.fromList([...sealed, ..._checkValue(_mac, _macKey, number, [clear])]);
  }

  @override
  ({Uint8List payload, int taken})? open(Uint8List bytes, int number) {
    if (bytes.length < 16) return null;
    var first = _first;
    if (first == null) {
      first = _first = Uint8List(16);
      _cipher.processBlock(bytes, 0, first, 0);
    }
    final length = _lengthOf(first, block: 16, counted: 4);
    final size = _mac.createMac(_macKey).macSize;
    if (bytes.length < 4 + length + size) return null;
    final clear = Uint8List(4 + length)..setRange(0, 16, first);
    for (var i = 16; i < clear.length; i += 16) {
      _cipher.processBlock(bytes, i, clear, i);
    }
    _first = null;
    final payload = _payloadIn(Uint8List.sublistView(clear, 4), length);
    if (!_same(_checkValue(_mac, _macKey, number, [clear]),
        Uint8List.sublistView(bytes, 4 + length, 4 + length + size))) {
      throw StateError('a packet of the client\'s has a check value the keys in force do not give it');
    }
    return (payload: payload, taken: 4 + length + size);
  }
}

/// A block cipher with a MAC of the kind OpenSSH names "etm": the length
/// stays in the clear, what follows it is encrypted, and the check value is
/// made of the length and of what was encrypted.
class _EncryptedThenChecked implements _Protection {
  _EncryptedThenChecked(this._cipher, this._mac, this._macKey);

  final BlockCipher _cipher;
  final SSHMacType _mac;
  final Uint8List _macKey;

  @override
  Uint8List seal(Uint8List payload, int number) {
    final body = _body(payload, 16);
    final length = _uint32(body.length);
    final sealed = Uint8List(body.length);
    for (var i = 0; i < body.length; i += 16) {
      _cipher.processBlock(body, i, sealed, i);
    }
    return Uint8List.fromList([...length, ...sealed, ..._checkValue(_mac, _macKey, number, [length, sealed])]);
  }

  @override
  ({Uint8List payload, int taken})? open(Uint8List bytes, int number) {
    if (bytes.length < 4) return null;
    final length = _lengthOf(bytes, block: 16, counted: 0);
    final size = _mac.createMac(_macKey).macSize;
    if (bytes.length < 4 + length + size) return null;
    if (!_same(_checkValue(_mac, _macKey, number, [Uint8List.sublistView(bytes, 0, 4 + length)]),
        Uint8List.sublistView(bytes, 4 + length, 4 + length + size))) {
      throw StateError('a packet of the client\'s has a check value the keys in force do not give it');
    }
    final body = Uint8List(length);
    for (var i = 0; i < length; i += 16) {
      _cipher.processBlock(bytes, 4 + i, body, i);
    }
    return (payload: _payloadIn(body, length), taken: 4 + length + size);
  }
}

/// aes-gcm@openssh.com (RFC 5647): the length in the clear and checked with
/// the rest, what follows it encrypted, sixteen bytes of check value. Each
/// packet has a nonce of its own: the one the keys give, counted on by one
/// for every packet since these keys were taken into use. That is not the
/// number of the packet, which only starts again with the keys where the
/// strict exchange is in force: the OpenSSH client holds this server to it
/// (played_server_openssh_test.dart).
class _Gcm implements _Protection {
  _Gcm(this._key, this._iv);

  final Uint8List _key;
  final Uint8List _iv;

  /// How many packets these keys have protected.
  var _packets = 0;

  /// The nonce of the packet that comes after [packets] others.
  Uint8List _nonce(int packets) {
    final nonce = Uint8List.fromList(_iv);
    final count = ByteData.sublistView(nonce, 4);
    count.setUint64(0, count.getUint64(0) + packets);
    return nonce;
  }

  @override
  Uint8List seal(Uint8List payload, int number) {
    final body = _body(payload, 16);
    final length = _uint32(body.length);
    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(_key), 128, _nonce(_packets), length));
    _packets++;
    return Uint8List.fromList([...length, ...cipher.process(body)]);
  }

  @override
  ({Uint8List payload, int taken})? open(Uint8List bytes, int number) {
    if (bytes.length < 4) return null;
    final length = _lengthOf(bytes, block: 16, counted: 0);
    if (bytes.length < 4 + length + 16) return null;
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(_key), 128, _nonce(_packets), Uint8List.sublistView(bytes, 0, 4)));
    final Uint8List body;
    try {
      body = cipher.process(Uint8List.sublistView(bytes, 4, 4 + length + 16));
    } on InvalidCipherTextException {
      throw StateError('a packet of the client\'s has a check value the keys in force do not give it');
    }
    _packets++;
    return (payload: _payloadIn(body, length), taken: 4 + length + 16);
  }
}

/// chacha20-poly1305@openssh.com: the length encrypted by itself, what
/// follows it encrypted, sixteen bytes of check value, and the number of the
/// packet as the nonce. The cipher is this package's own, which its tests
/// against a real OpenSSH server hold, and the OpenSSH client holds here.
class _ChaCha implements _Protection {
  _ChaCha(Uint8List key) : _cipher = SSHCipherChaCha20Poly1305(key: key);

  final SSHCipherChaCha20Poly1305 _cipher;

  @override
  Uint8List seal(Uint8List payload, int number) {
    final body = _body(payload, 8);
    return _cipher.encrypt(body, body.length, number);
  }

  @override
  ({Uint8List payload, int taken})? open(Uint8List bytes, int number) {
    if (bytes.length < 4) return null;
    final sealedLength = Uint8List.fromList(Uint8List.sublistView(bytes, 0, 4));
    final length = _lengthOf(_uint32(_cipher.decryptLength(sealedLength, number)), block: 8, counted: 0);
    if (bytes.length < 4 + length + 16) return null;
    final Uint8List body;
    try {
      body = _cipher.decrypt(
        sealedLength,
        Uint8List.fromList(Uint8List.sublistView(bytes, 4, 4 + length)),
        Uint8List.fromList(Uint8List.sublistView(bytes, 4 + length, 4 + length + 16)),
        number,
      );
    } on SSHMacMismatchException {
      throw StateError('a packet of the client\'s has a check value the keys in force do not give it');
    }
    return (payload: _payloadIn(body, length), taken: 4 + length + 16);
  }
}

/// The check value a MAC of [type] gives the packet with the number
/// [number] that is made of [parts].
Uint8List _checkValue(SSHMacType type, Uint8List macKey, int number, List<Uint8List> parts) {
  final mac = type.createMac(macKey);
  mac.update(_uint32(number), 0, 4);
  for (final part in parts) {
    mac.update(part, 0, part.length);
  }
  final value = Uint8List(mac.macSize);
  mac.doFinal(value, 0);
  return value;
}

/// The connection as the played server holds it where the client is made in
/// the test itself: what the client wrote, and a way to hand it bytes.
class _Wire implements SSHSocket, PlayedLine {
  final _incoming = StreamController<Uint8List>();
  final _done = Completer<void>();
  final _written = BytesBuilder(copy: true);

  /// Bytes from the server, as one read. Once the client has ended the
  /// connection they go nowhere, as they would.
  @override
  void feed(List<int> bytes) {
    if (!_incoming.isClosed) _incoming.add(Uint8List.fromList(bytes));
  }

  @override
  void end() {
    if (!_incoming.isClosed) unawaited(_incoming.close());
  }

  @override
  Uint8List takeOutput() => _written.takeBytes();

  /// A client writes each packet in one piece.
  @override
  bool get wholePackets => true;

  @override
  bool get clientGone => _done.isCompleted;

  @override
  Stream<Uint8List> get stream => _incoming.stream;

  @override
  StreamSink<List<int>> get sink => _Sink(_written);

  @override
  Future<void> get done => _done.future;

  @override
  Future<void> flush() async {}

  @override
  Future<void> close() async {
    if (!_done.isCompleted) _done.complete();
    await _incoming.close();
  }

  @override
  void destroy() {
    if (!_done.isCompleted) _done.complete();
    unawaited(_incoming.close());
  }
}

class _Sink implements StreamSink<List<int>> {
  _Sink(this._into);

  final BytesBuilder _into;

  @override
  void add(List<int> data) => _into.add(data);

  @override
  void addError(Object error, [StackTrace? stackTrace]) {}

  @override
  Future<void> addStream(Stream<List<int>> stream) async {
    await for (final chunk in stream) {
      _into.add(chunk);
    }
  }

  @override
  Future<void> close() async {}

  @override
  Future<void> get done => Future.value();
}
