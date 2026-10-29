import 'dart:async';
import 'dart:convert';
import 'dart:math' show max;
import 'dart:typed_data';

import 'package:zest_ssh_core/src/algorithm/ssh_cipher_chacha20_poly1305.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_send_crypto.dart';
import 'package:zest_ssh_core/src/exceptions/ssh_exceptions.dart' show SSHMacMismatchException;
import 'package:zest_ssh_core/src/hostkey/hostkey_ecdsa.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';
import 'package:zest_ssh_core/src/kex/kex_nist.dart';
import 'package:zest_ssh_core/src/kex/kex_mlkem768x25519.dart';
import 'package:zest_ssh_core/src/kex/kex_sntrup761x25519.dart';
import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
import 'package:zest_ssh_core/src/message/msg_disconnect.dart';
import 'package:zest_ssh_core/src/message/msg_ext_info.dart';
import 'package:zest_ssh_core/src/message/msg_userauth.dart';
import 'package:zest_ssh_core/src/ssh_algorithm.dart';
import 'package:zest_ssh_core/src/version.dart';
import 'package:zest_ssh_core/src/ssh_kex.dart';
import 'package:zest_ssh_core/src/utils/bigint.dart';
import 'package:zest_ssh_core/src/utils/cipher_ext.dart';
import 'package:zest_ssh_core/src/utils/chunk_buffer.dart';
import 'package:zest_ssh_core/src/ssh_kex_utils.dart';
import 'package:zest_ssh_core/src/ssh_packet.dart';
import 'package:zest_ssh_core/src/utils/int.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ed25519.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ed448.dart';
import 'package:zest_ssh_core/src/utils/list.dart';
import 'package:zest_ssh_core/src/message/msg_kex.dart';
import 'package:zest_ssh_core/src/message/msg_kex_dh.dart';
import 'package:zest_ssh_core/src/message/msg_kex_ecdh.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:pointycastle/export.dart';

import 'package:zest_ssh_core/src/utils/secure_memory.dart';

import '../dartssh2.dart';

typedef SSHPrintHandler = void Function(String?);

/// Function called to verify a received host key.
/// [type] is the type of the host key, for example 'ssh-rsa'.
/// [keyBlob] is the RAW host public-key blob (the wire encoding) - NOT a
/// digest - so the app can compute the standard OpenSSH SHA256 fingerprint
/// that matches `ssh-keygen -lf`, store the real key, and let users verify
/// out-of-band.
typedef SSHHostkeyVerifyHandler = FutureOr<bool> Function(
  String type,
  Uint8List keyBlob,
);

typedef SSHTransportReadyHandler = void Function();

typedef SSHPacketHandler = void Function(Uint8List payload);

/// Called when SSH version strings have been exchanged.
typedef SSHVersionExchangeHandler = void Function(
  String localVersion,
  String remoteVersion,
);

/// Called when key exchange algorithms have been negotiated, with what was
/// agreed on for what the client sends: the cipher, and the MAC beside it.
/// [mac] is empty where the cipher checks its packets by itself
/// (chacha20-poly1305, AES-GCM) and so has none.
typedef SSHKexNegotiatedHandler = void Function({
  required String kex,
  required String cipher,
  required String mac,
  required String hostKey,
});

/// Called when key exchange has completed.
typedef SSHKexCompletedHandler = void Function(Duration duration);

/// Called when the host key has been received with its type and fingerprint.
typedef SSHHostKeyReceivedHandler = void Function(
  String keyType,
  String fingerprint,
);

class SSHTransport {
  /// Version of the SSH software sent in the identification banner. Defaults to
  /// [kDefaultClientIdent] (`"zest_ssh_core_<version>"`).
  final String version;

  /// The socket to read and write data to.
  final SSHSocket socket;

  /// Whether the transport acts as a server.
  final bool isServer;

  /// Whether the transport acts as a client. This is equal to `!isServer`.
  bool get isClient => !isServer;

  /// Function invoked with debug logging.
  final SSHPrintHandler? printDebug;

  /// Function invoked with trace logging.
  final SSHPrintHandler? printTrace;

  final SSHAlgorithms algorithms;

  /// Function called when the hostkey has been received. Returns true if the
  /// hostkey is valid, false to reject key and disconnect.
  final SSHHostkeyVerifyHandler? onVerifyHostKey;

  /// Function called when the transport is ready to send data.
  final SSHTransportReadyHandler? onReady;

  /// Function called when a packet is received.
  final SSHPacketHandler? onPacket;

  /// Called when SSH version strings have been exchanged.
  final SSHVersionExchangeHandler? onVersionExchange;

  /// Called when key exchange algorithms have been negotiated.
  final SSHKexNegotiatedHandler? onKexNegotiated;

  /// Called when key exchange has completed.
  final SSHKexCompletedHandler? onKexCompleted;

  /// Called when the host key has been received.
  final SSHHostKeyReceivedHandler? onHostKeyReceived;

  /// Called when the server has said something of itself
  /// (SSH_MSG_EXT_INFO): [serverExtensions] and [serverSignatureAlgorithms]
  /// hold what it said.
  final void Function()? onExtInfo;

  final bool disableHostkeyVerification;

  /// A [Future] that completes when the transport is closed, or when an error
  /// occurs. After this [Future] completes, [isClosed] will be true and no
  /// more data can be sent or received.
  Future<void> get done => _doneCompleter.future;

  /// `true` if the connection is closed normally or due to an error.
  bool get isClosed => _doneCompleter.isCompleted;

  /// Identification string sent by the other side. For example, "SSH-2.0-OpenSSH_7.4p1".
  /// May be `null` if the handshake has not yet completed.
  String? get remoteVersion => _remoteVersion;

  SSHTransport(
    this.socket, {
    this.isServer = false,
    this.version = kDefaultClientIdent,
    this.printDebug,
    this.printTrace,
    this.algorithms = const SSHAlgorithms(),
    this.onVerifyHostKey,
    this.onReady,
    this.onPacket,
    this.onVersionExchange,
    this.onKexNegotiated,
    this.onKexCompleted,
    this.onHostKeyReceived,
    this.onExtInfo,
    this.disableHostkeyVerification = false,
    this.rekeyAfterBytes = defaultRekeyAfterBytes,
    this.rekeyAfterPackets = defaultRekeyAfterPackets,
    this.kexInitPatience = defaultKexInitPatience,
  })  : assert(rekeyAfterBytes > 0),
        assert(rekeyAfterPackets > 0) {
    _initSocket();
    _startHandshake();
  }

  /// How long a client waits, once the server's version has come, for the
  /// server's proposal for the key exchange (SSH_MSG_KEXINIT) before it
  /// ends the connection with [SSHHandshakeError.kexUnanswered]. A server
  /// sends its proposal straight after its version, and nothing of it is
  /// worked out first; a server that has sent neither within this has
  /// stopped answering. Where it is said so, that is said in seconds, not
  /// as a sign-in that ran out of time a while later.
  final Duration kexInitPatience;

  /// [kexInitPatience] where nothing is said.
  static const defaultKexInitPatience = Duration(seconds: 10);

  /// Ends the connection once [kexInitPatience] is over: from the server's
  /// version until its first proposal (client only).
  Timer? _kexInitWait;

  void _stopKexInitWait() {
    _kexInitWait?.cancel();
    _kexInitWait = null;
  }

  void _kexInitNotCome() {
    _kexInitWait = null;
    if (isClosed) return;
    printDebug?.call('SSHTransport: no KEXINIT from the server in ${kexInitPatience.inSeconds}s');
    closeWithError(SSHHandshakeError(
      'The server sent its version ($_remoteVersion) and then no key exchange '
      'proposal in ${kexInitPatience.inSeconds} seconds',
      kexUnanswered: true,
    ));
  }

  /// How many bytes of what packets carry go out, or come in, under one set
  /// of keys before this side asks for new ones. A gigabyte where nothing
  /// is said: what RFC 4253 (9) recommends, and what an OpenSSH client and
  /// server keep to under chacha20-poly1305.
  final int rekeyAfterBytes;

  /// How many packets go out, or come in, under one set of keys before this
  /// side asks for new ones. 2^31 where nothing is said, as OpenSSH has it.
  ///
  /// A packet is numbered in 32 bits, and under chacha20-poly1305 that
  /// number is the one thing no two packets under the same keys may share:
  /// a side must not send more than 2^32 packets under one set of keys (RFC
  /// 4344, 3.1). Where twice this many, less one, have gone one way and the
  /// new keys that were asked for have not come, the connection is ended.
  final int rekeyAfterPackets;

  /// [rekeyAfterBytes] where nothing is said.
  static const defaultRekeyAfterBytes = 1 << 30;

  /// [rekeyAfterPackets] where nothing is said.
  static const defaultRekeyAfterPackets = 1 << 31;

  final _doneCompleter = Completer<void>();

  /// Contains unprocessed data from the socket.
  final _buffer = ChunkBuffer();

  /// Contains decrypted packet data. May be partial.
  final _decryptBuffer = ChunkBuffer();

  /// Subscription to the socket's [Stream]. It should be closed when the
  /// transport is closed.
  StreamSubscription? _socketSubscription;

  /// Identification string sent by us without trailing \r\n. For example,
  /// "SSH-2.0-zest_ssh_core_0.1.0".
  String get _localVersion => 'SSH-2.0-$version';

  /// Identification string sent by the other side. For example, "SSH-2.0-OpenSSH_7.4p1".
  /// May be `null` if the handshake has not yet completed.
  /// This is kept to compute [_exchangeHash]
  String? _remoteVersion;

  /// Payload of the [SSH_Message_KexInit] sent by us. Kept to compute the
  /// exchange hash.
  late Uint8List _localKexInit;

  /// Payload of the [SSH_Message_KexInit] sent by the other side. Kept to
  /// compute the exchange hash.
  late Uint8List _remoteKexInit;

  SSHKexType? _kexType;

  SSHHostkeyType? _hostkeyType;

  /// The cipher and the MAC of each direction that the two sides agreed on
  /// in the key exchange in progress, or in the last one: what the keys of
  /// that exchange are made for. They are not what protects packets until
  /// those keys are installed, see [_localCipherType].
  SSHCipherType? _clientCipherType;

  SSHCipherType? _serverCipherType;

  SSHMacType? _clientMacType;

  SSHMacType? _serverMacType;

  /// What protects the packets of each direction NOW: the cipher, and the
  /// MAC where the cipher does not check its packets by itself, whose keys
  /// are in force. Null until that direction's first NEWKEYS.
  ///
  /// What an exchange agrees on is taken into use with its keys: by each
  /// side for what it sends from its own NEWKEYS on, and for what it reads
  /// from the other side's NEWKEYS on (RFC 4253, 7.3). Until then
  /// everything goes as it did, the rest of that exchange too. So these are
  /// set where the keys are installed ([_applyLocalKeys],
  /// [_applyRemoteKeys]) and nowhere else, and whatever packs or reads a
  /// packet asks these, and never what was only agreed on.
  /// (The packet paths asked what was agreed on until this was held. At the
  /// first exchange nothing is in force, so nothing came of it there. At a
  /// later one that agreed on another cipher or MAC, the client's start of
  /// the exchange and its NEWKEYS went out under the new framing with the
  /// old keys, or in the clear, and what the server sent before its NEWKEYS
  /// was read as if it were under the new ones. See the changelog, "What an
  /// exchange agrees on is taken into use with its keys".)
  SSHCipherType? _localCipherType;

  SSHMacType? _localMacType;

  SSHCipherType? _remoteCipherType;

  SSHMacType? _remoteMacType;

  SSHKex? _kex;

  /// [_exchangeHash] of the first key exchange is used as session identifier.
  /// Used to derive the cipher IV, cipher key and MAC key.
  Uint8List? _sessionId;

  /// A hash value of various parameters (defined in rfc4253). Kept to derive the
  /// cipher IV, cipher key and MAC key.
  Uint8List? _exchangeHash;

  /// Whether the hostkey of the server has been verified. This is always false
  /// when the transport is acting as a server.
  var _hostkeyVerified = false;

  /// The exact host-key blob the user verified (or the signature check
  /// accepted) on the INITIAL key exchange. On every subsequent re-key the
  /// server's host key must be byte-identical to this - otherwise a MITM that
  /// seizes the link mid-session could swap in a different key during re-key,
  /// which we would otherwise accept because host-key verification only runs
  /// once. Null until the first key exchange completes.
  Uint8List? _verifiedHostKey;

  /// Shared secret derived from the key exchange process, in its WIRE
  /// encoding (`mpint` for classic exchanges, `string` for the hybrid
  /// post-quantum ones). Kept to derive the cipher IV, cipher key and MAC key.
  Uint8List? _sharedSecret;

  /// A [BlockCipher] to encrypt data sent to the other side.
  BlockCipher? _encryptCipher;

  /// A [BlockCipher] to decrypt data sent from the other side.
  BlockCipher? _decryptCipher;

  Uint8List? _localCipherKey;

  Uint8List? _remoteCipherKey;

  Uint8List? _localIV;

  Uint8List? _remoteIV;

  /// A [Mac] used to authenticate data sent to the other side.
  Mac? _localMac;

  /// A [Mac] used to authenticate data sent from the other side.
  Mac? _remoteMac;

  /// ChaCha20-Poly1305 cipher for decrypting inbound packets. (What goes out
  /// under that cipher is encrypted from [_localCipherKey], packet by packet.)
  SSHCipherChaCha20Poly1305? _remoteChaCha;

  /// How many packets have gone out, and how many have come in, under the
  /// AES-GCM keys in force. A packet's nonce is the one its keys give,
  /// counted on by this (RFC 5647, 7.1): by the packets since the keys were
  /// taken into use, and not by the number of the packet, which starts
  /// again with the keys only where the strict key exchange is in force.
  /// (It was the number of the packet until this was held: with a server
  /// that has no strict exchange neither side could read the other. See the
  /// changelog, "AES-GCM packets are counted from the keys".)
  var _localGcmPackets = 0;
  var _remoteGcmPackets = 0;

  /// How many packets, and how many bytes of what they carry, have gone out
  /// and have come in under the keys in force: what new keys are asked for
  /// by ([rekeyAfterBytes], [rekeyAfterPackets]).
  var _sentPacketsUnderKeys = 0;
  var _sentBytesUnderKeys = 0;
  var _receivedPacketsUnderKeys = 0;
  var _receivedBytesUnderKeys = 0;

  final _localPacketSN = SSHPacketSN.fromZero();

  final _remotePacketSN = SSHPacketSN.fromZero();

  /// Whether this is the initial (first) key exchange. Used for the Terrapin
  /// attack (CVE-2023-48795) strict KEX mitigation: sequence numbers are reset
  /// to 0 after the first NEWKEYS when both sides advertise strict KEX.
  bool _isInitialKex = true;

  /// Whether the server advertised `kex-strict-s-v00@openssh.com` in its
  /// KEXINIT, indicating support for the Terrapin strict KEX extension.
  bool _serverSupportsStrictKex = false;

  /// The kinds of signature the server has said it takes from a key that
  /// signs in ("server-sig-algs", RFC 8308, 3.1), in its order, or null
  /// where it has not said. It says so with SSH_MSG_EXT_INFO, which a
  /// client asks for in its first proposal ([_handleMessageExtInfo]).
  List<String>? get serverSignatureAlgorithms => _serverSignatureAlgorithms;
  List<String>? _serverSignatureAlgorithms;

  /// The names of what the server has said of itself with
  /// SSH_MSG_EXT_INFO, in its order. Empty where it has said nothing.
  List<String> get serverExtensions => _serverExtensions;
  List<String> _serverExtensions = const [];

  /// Timestamp when the current key exchange round started.
  DateTime? _kexStartTime;

  /// Whether a key exchange is currently in progress (initial or re-key).
  bool _kexInProgress = false;

  /// Whether we have already sent our SSH_MSG_KEXINIT for the ongoing key
  /// exchange round. This is reset when the exchange finishes.
  bool _sentKexInit = false;

  /// Where the key exchange in progress stands, as what the server may send
  /// next. An exchange is one proposal, one answer (a group first, for a
  /// group exchange) and one NEWKEYS, in that order, and each is taken once:
  /// anything else for the exchange ends the connection.
  ///
  /// It is held to that because the host key that comes with the answer is
  /// looked up or put to the person, which takes time. Were a second answer
  /// taken in that time, it would replace the secret the session is about to
  /// use: whoever sits between this client and the server could put the real
  /// server's answer, signed by the key the person trusts, between two of its
  /// own, and have its own secret in force under the approval of the trusted
  /// key. (The transport took every answer until this was held: see the
  /// changelog, "The answer to a key exchange is taken once".)
  _KexStep _kexStep = _KexStep.idle;

  /// Whether our own NEWKEYS for the exchange is still to be sent: from the
  /// answer until its host key is approved (on a re-key, where the key is
  /// the approved one, at once). The server may not open another exchange
  /// before it is sent.
  bool _localNewKeysOwed = false;

  /// Tracks the last sequence number used for an inbound ChaCha20-Poly1305
  /// packet. Used to enforce strict monotonicity (Finding 1.2).
  int? _lastRemoteChaChaSeq;

  /// Cryptographically secure RNG used for padding bytes.
  /// Packet-padding generator.
  ///
  /// SSH padding SHOULD be random (RFC 4253 §6), but it sits inside the
  /// AEAD/MAC envelope, so what matters is a cryptographically strong STREAM,
  /// not a kernel round-trip per byte. `Random.secure()` reaches the OS CSPRNG
  /// on EVERY `nextInt` call; the previous per-byte padding loop therefore cost
  /// one syscall per padding byte, on the main isolate, for every packet sent.
  // ---- socket write path + bulk-send drain ---------------------------------

  /// True while [drainSocket] is waiting on the socket. Writes that arrive in
  /// that window are parked in [_deferredWrites] instead of hitting the sink:
  /// dart:io's IOSink throws "StreamSink is bound to a stream" for an add()
  /// during flush(), and this one transport is shared by every channel.
  bool _draining = false;
  Future<void>? _drainFuture;
  final List<List<int>> _deferredWrites = [];

  /// The ONLY path to the socket sink. Preserves write order across a drain.
  void _writeToSocket(List<int> bytes) {
    if (_draining) {
      _deferredWrites.add(bytes);
      return;
    }
    socket.sink.add(bytes);
  }

  /// Wait until everything handed to the socket so far has been accepted by
  /// the OS. Bulk senders (the channel upload loop) await this periodically so
  /// a slow uplink does not pile megabytes of ciphertext into the Dart-side
  /// socket queue. Every channel shares this one TCP stream, so an interactive
  /// request issued during an upload (a directory listing, a keystroke) would
  /// otherwise sit behind the whole SSH window of already-queued data: seconds
  /// on a residential uplink. The kernel's own auto-tuned (~bandwidth-delay
  /// product) send buffer keeps the pipe full in the meantime, so throughput
  /// is unaffected. Packets written while the drain is in flight keep their
  /// order: they are queued and handed to the sink the moment it completes.
  Future<void> drainSocket() {
    final inFlight = _drainFuture;
    if (inFlight != null) return inFlight;
    Future<void> flushed;
    try {
      flushed = socket.flush();
    } catch (_) {
      return Future<void>.value();
    }
    _draining = true;
    final future = flushed.catchError((Object _) {}).whenComplete(() {
      _draining = false;
      _drainFuture = null;
      if (_deferredWrites.isEmpty) return;
      final pending = List<List<int>>.of(_deferredWrites);
      _deferredWrites.clear();
      for (final bytes in pending) {
        try {
          socket.sink.add(bytes);
        } catch (_) {
          // The socket died mid-drain; the transport's done/close path owns
          // the teardown, and the writer will see the closed transport.
          break;
        }
      }
    });
    _drainFuture = future;
    return future;
  }

  /// Packets queued during key exchange that will be sent after NEW_KEYS
  final List<Uint8List> _rekeyPendingPackets = [];

  void sendPacket(Uint8List data) {
    if (isClosed) {
      throw SSHStateError('Transport is closed');
    }

    // Buffer application packets that arrive mid key-exchange; they are
    // flushed (encrypted) once NEW_KEYS completes. A buffered packet is NOT
    // put on the wire now, so it can never travel in cleartext - hence this
    // runs BEFORE the cleartext guard below, which only concerns packets we
    // are about to actually transmit.
    if (_kexInProgress && !_shouldBypassRekeyBuffer(data)) {
      _rekeyPendingPackets.add(Uint8List.fromList(data));
      return;
    }

    // SECURITY: never TRANSMIT a secret-bearing message on an unencrypted
    // transport.
    //
    // Only the transport/KEX exchange legitimately travels in the clear:
    // ids 1-4 (DISCONNECT/IGNORE/UNIMPLEMENTED/DEBUG), 20-21 (KEXINIT/
    // NEWKEYS) and the 30-49 KEX-method-specific range (e.g. KEX_ECDH_INIT).
    // Everything from SERVICE_REQUEST (5) upward carries or leads directly to
    // secrets - the user-auth password, a public-key signature, then session
    // data - and must only go out once keys are installed. If a bug or a
    // hostile peer drives the state machine into sending those before
    // encryption is established, refuse rather than silently fall back to
    // plaintext (the old behaviour: `if (_encryptCipher == null) sink.add`).
    //
    // Encryption is "established" once the keys of this direction are
    // installed, whatever the cipher: [_localCipherType] says what protects
    // what goes out now, and is null until then.
    final localCipherType = _localCipherType;
    if (localCipherType == null && data.isNotEmpty) {
      final messageId = SSHMessage.readMessageId(data);
      final isKexOrTransport = messageId <= _maxPreHandshakeMessageId ||
          (messageId >= 20 && messageId <= 49);
      if (!isKexOrTransport) {
        throw SSHStateError(
          'Refusing to send message id $messageId before encryption is '
          'established - this would transmit credentials in cleartext.',
        );
      }
    }

    // ChaCha20-Poly1305 has its own packet framing with encrypted length
    if (localCipherType != null && localCipherType.isChaCha) {
      _sendChaChaPacket(data, localCipherType);
      _localPacketSN.increase();
      _sentUnderKeys(data.length);
      return;
    }

    if (localCipherType != null && localCipherType.isAead) {
      _sendAeadPacket(data, localCipherType);
      _localPacketSN.increase();
      _sentUnderKeys(data.length);
      return;
    }

    final macType = _localMacType;
    final isEtm = macType != null && macType.isEtm;

    // For ETM, we need to handle the packet differently
    if (isEtm) {
      // For ETM (Encrypt-Then-MAC):
      // 1. Keep the packet length in plaintext
      // 2. Encrypt only the payload (padding length, payload, padding)

      // Calculate the block size for alignment
      final blockSize = _encryptCipher!.blockSize;

      // Create a custom packet structure for ETM mode
      // We need to ensure that the payload we're encrypting is a multiple of the block size

      // Calculate the padding length to ensure the total length is a multiple of the block size
      // We need to account for the 1 byte padding length field
      final paddingLength = blockSize - ((data.length + 1) % blockSize);
      // Ensure padding is at least 4 bytes as per SSH spec
      final adjustedPaddingLength =
          paddingLength < 4 ? paddingLength + blockSize : paddingLength;

      // Calculate the total packet length (excluding the length field itself)
      final packetLength = 1 + data.length + adjustedPaddingLength;

      // Create the packet length field (4 bytes)
      final packetLengthBytes = Uint8List(4);
      packetLengthBytes.buffer.asByteData().setUint32(0, packetLength);

      // Create the payload to be encrypted (padding length + payload + padding)
      final payloadToEncrypt = Uint8List(packetLength);
      payloadToEncrypt[0] = adjustedPaddingLength; // Set padding length
      payloadToEncrypt.setRange(1, 1 + data.length, data); // Copy data

      // Random padding from the shared OS CSPRNG (batched, see randomBytes).
      payloadToEncrypt.setRange(
          1 + data.length, packetLength, randomBytes(adjustedPaddingLength));

      // Verify that the payload length is a multiple of the block size
      if (payloadToEncrypt.length % blockSize != 0) {
        throw StateError(
            'Payload length ${payloadToEncrypt.length} is not a multiple of block size $blockSize');
      }

      // Encrypt the payload
      final encryptedPayload = _encryptCipher!.processAll(payloadToEncrypt);

      // Calculate MAC on the packet length and encrypted payload
      final mac = _localMac!;
      mac.updateAll(_localPacketSN.value.toUint32());
      mac.updateAll(packetLengthBytes);
      mac.updateAll(encryptedPayload);
      final macBytes = mac.finish();

      // Build the final packet: length + encrypted payload + MAC
      final buffer = BytesBuilder(copy: false);
      buffer.add(packetLengthBytes);
      buffer.add(encryptedPayload);
      buffer.add(macBytes);

      _writeToSocket(buffer.takeBytes());
    } else {
      // For standard encryption or no encryption:
      // Use the original packet packing logic
      final packetAlign = localCipherType == null
          ? SSHPacket.minAlign
          : max(SSHPacket.minAlign, _encryptCipher!.blockSize);

      final packet = SSHPacket.pack(data, align: packetAlign);

      // In the clear while no keys of this direction are in force, and
      // never after: with a cipher in force a packet goes out under it.
      if (localCipherType == null) {
        _writeToSocket(packet);
      } else {
        final mac = _localMac!;
        final encryptedPacket = _encryptCipher!.processAll(packet);

        final buffer = BytesBuilder(copy: false);
        buffer.add(encryptedPacket);

        // Calculate MAC on the unencrypted packet
        mac.updateAll(_localPacketSN.value.toUint32());
        mac.updateAll(packet);
        buffer.add(mac.finish());

        _writeToSocket(buffer.takeBytes());
      }
    }

    _localPacketSN.increase();
    if (localCipherType != null) _sentUnderKeys(data.length);
  }

  /// A packet has gone out under keys, with [bytes] of what it carries.
  void _sentUnderKeys(int bytes) {
    _sentPacketsUnderKeys++;
    _sentBytesUnderKeys += bytes;
    _newKeysWhenDue();
  }

  /// A packet has come in under keys, with [bytes] of what it carried.
  void _receivedUnderKeys(int bytes) {
    _receivedPacketsUnderKeys++;
    _receivedBytesUnderKeys += bytes;
    _newKeysWhenDue();
  }

  /// Asks for new keys once enough has gone one way under those in force
  /// ([rekeyAfterBytes], [rekeyAfterPackets]), and ends the connection
  /// where they were asked for and have not come by the time a count of
  /// packets would run round.
  ///
  /// This side asked for none by itself until this was held: it took new
  /// keys when the other side asked, which an OpenSSH server does after
  /// about a gigabyte and not every server does at all. With a server that
  /// never asks, the 2^32nd packet under chacha20-poly1305 came under a
  /// nonce that had been used with the same keys. (See the changelog, "New
  /// keys are asked for".)
  void _newKeysWhenDue() {
    if (isClosed || _isInitialKex) return;
    final packets = max(_sentPacketsUnderKeys, _receivedPacketsUnderKeys);
    if (packets >= 2 * rekeyAfterPackets - 1) {
      closeWithError(SSHHandshakeError(
        'New keys were asked for and have not come: $packets packets have '
        'gone one way under the keys in force, and no more may',
      ));
      return;
    }
    // An exchange that is under way ends with new keys, and with them the
    // counts begin again.
    if (_kexInProgress || _localNewKeysOwed) return;
    if (packets >= rekeyAfterPackets ||
        _sentBytesUnderKeys >= rekeyAfterBytes ||
        _receivedBytesUnderKeys >= rekeyAfterBytes) {
      printDebug?.call('SSHTransport: asking for new keys ($packets packets one way, '
          '$_sentBytesUnderKeys bytes out and $_receivedBytesUnderKeys in under those in force)');
      rekey();
    }
  }

  void _sendAeadPacket(Uint8List data, SSHCipherType cipherType) {
    final paddingLength =
        _alignedPaddingLength(data.length, cipherType.blockSize);
    final packetLength = 1 + data.length + paddingLength;

    final aad = Uint8List(4)..buffer.asByteData().setUint32(0, packetLength);

    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data)
      ..setRange(1 + data.length, packetLength, randomBytes(paddingLength));

    // Same pure function the crypto worker runs (aad + GCM ciphertext + tag).
    _writeToSocket(encryptGcmPacket(
      _localCipherKey!,
      _localIV!,
      _localGcmPackets++,
      aad,
      plaintext,
    ));
  }

  void _sendChaChaPacket(Uint8List data, SSHCipherType cipherType) {
    final paddingLength = _alignedPaddingLength(data.length, cipherType.blockSize);
    final packetLength = 1 + data.length + paddingLength;

    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data)
      ..setRange(1 + data.length, packetLength, randomBytes(paddingLength));

    // Same pure function the crypto worker runs.
    _writeToSocket(encryptChaChaPacket(
      _localCipherKey!,
      _localPacketSN.value,
      plaintext,
      packetLength,
    ));
  }

  int _alignedPaddingLength(int payloadLength, int align) {
    final paddingLength = align - ((payloadLength + 1) % align);
    return paddingLength < 4 ? paddingLength + align : paddingLength;
  }

  Uint8List _processAead({
    required Uint8List key,
    required Uint8List iv,
    required int packetsBefore,
    required Uint8List aad,
    required Uint8List input,
    required bool forEncryption,
  }) {
    final cipher = GCMBlockCipher(AESEngine());
    final nonce = _nonceForSequence(iv, packetsBefore);
    cipher.init(
      forEncryption,
      AEADParameters(KeyParameter(key), 128, nonce, aad),
    );
    return cipher.process(input);
  }

  // Delegates to the shared pure helper so send (worker) and receive share one
  // nonce derivation and cannot drift.
  Uint8List _nonceForSequence(Uint8List iv, int packetsBefore) =>
      sshAeadNonceForSequence(iv, packetsBefore);

  /// Ends the connection from this side. Where its keys are in force it
  /// says so first (SSH_MSG_DISCONNECT, RFC 4253, 11.1), so that the other
  /// side reads a connection that was ended and not one that broke: a
  /// server writes "Received disconnect from ..." of the one and
  /// "Connection closed by ..." of the other. (It said nothing, whatever it
  /// was closed for.) The socket is given a moment to send it, and is closed
  /// then. A connection that ends over an error ([closeWithError]) says
  /// nothing: what was wrong with it is not told to the other side.
  void close() {
    printDebug?.call('SSHTransport.close');
    if (isClosed) return;
    _stopKexInitWait();
    final said = _sayGoodbye();
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.complete();
    if (!said) {
      socket.destroy();
      return;
    }
    // A socket that is destroyed drops what it has not sent yet.
    unawaited(
      Future.sync(socket.flush)
          .timeout(_goodbyePatience)
          .then((_) {}, onError: (Object _) {})
          .whenComplete(socket.destroy),
    );
  }

  /// How long a goodbye is given to leave before the socket is closed on it.
  static const _goodbyePatience = Duration(seconds: 2);

  /// Tells the other side that this side ends the connection, and whether
  /// it could be told: under keys only (nothing is said in the clear, where
  /// anybody on the line could have said it), and not while the socket is
  /// being drained, which takes no write until that is over.
  bool _sayGoodbye() {
    if (_localCipherType == null || _draining) return false;
    try {
      // 11: SSH_DISCONNECT_BY_APPLICATION.
      sendPacket(SSH_Message_Disconnect(reasonCode: 11, description: 'disconnected by application').encode());
      return true;
    } catch (_) {
      // A socket that has gone takes no goodbye.
      return false;
    }
  }

  void closeWithError(SSHError error, [StackTrace? stackTrace]) {
    printDebug?.call('SSHTransport.closeWithError $error');
    if (isClosed) return;
    _stopKexInitWait();
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.completeError(error, stackTrace ?? StackTrace.current);
    socket.destroy();
  }

  void _initSocket() {
    _socketSubscription = socket.stream.listen(
      _onSocketData,
      onError: _onSocketError,
      onDone: _onSocketDone,
    );

    socket.done.catchError(_onSocketError);
  }

  /// How many bytes have come from the other side so far, whatever they
  /// were: for whoever looks at whether the connection has gone quiet.
  int get bytesReceived => _bytesReceived;
  int _bytesReceived = 0;

  void _onSocketData(Uint8List data) {
    _bytesReceived += data.length;
    _buffer.add(data);
    try {
      _processData();
    } on SSHError catch (e, stackTrace) {
      printDebug?.call('SSHTransport: SSH error during packet processing: $e');
      closeWithError(e, stackTrace);
    } catch (e, stackTrace) {
      // What is thrown here was thrown in the exchange of versions: packets
      // are handled by [_processPackets], which ends the connection itself
      // and throws nothing. It must end the connection all the same.
      // Rethrowing escapes to the zone as an uncaught async error: the
      // subscription is never cancelled and the connect future never
      // completes, hanging the client forever (a pre-auth DoS). Wrap it as
      // an SSHError so `closeWithError` rejects the pending handshake
      // instead. (It was said to be a malformed packet, where no packet had
      // come yet.)
      printDebug?.call('SSHTransport: Unexpected error in the version exchange: $e\n$stackTrace');
      closeWithError(SSHHandshakeError('The version exchange failed: $e'), stackTrace);
    }
  }

  void _onSocketError(Object error, StackTrace stackTrace) {
    printDebug?.call('SSHTransport._onSocketError($error)');
    closeWithError(SSHSocketError(error), stackTrace);
  }

  void _onSocketDone() {
    printDebug?.call('SSHTransport._onSocketDone');
    close();
  }

  void _processData() {
    if (_remoteVersion == null) {
      _processVersionExchange();
    } else {
      // Fire-and-forget: [_processPackets] is async (it yields periodically)
      // and routes any processing error to [closeWithError] internally, so its
      // future never rejects - unawaited is safe and cannot leak an unhandled
      // async error.
      unawaited(_processPackets());
    }
  }

  /// The longest line taken during the version exchange.
  static const _maxVersionLineBytes = 10240;

  /// The most a peer may send in lines before its version string.
  static const _maxBeforeVersionBytes = 32768;

  /// Bytes of lines before the version string passed over so far.
  var _beforeVersionBytes = 0;

  void _processVersionExchange() {
    printDebug?.call('SSHTransport._processVersionExchange');

    // The version string is a line of text on a stream: it may arrive in
    // more than one read, and a peer may send other lines before it (RFC
    // 4253, 4.2), none of which begins with "SSH-". Lines are taken as they
    // end; what has not ended yet waits for the rest.
    String versionString;
    while (true) {
      final data = _buffer.data;
      // A line ends in \r\n, or in \n alone (observed on Synology DS120j 2021).
      final end = data.indexOf(0x0A);
      if (end == -1) {
        if (data.length > _maxVersionLineBytes) {
          throw SSHHandshakeError('Version exchange too long');
        }
        return;
      }
      if (end > _maxVersionLineBytes) {
        throw SSHHandshakeError('Version exchange too long');
      }
      final cut = end > 0 && data[end - 1] == 0x0D ? end - 1 : end;
      final line = latin1.decode(Uint8List.sublistView(data, 0, cut));
      _buffer.consume(end + 1);
      if (line.startsWith('SSH-')) {
        versionString = line;
        break;
      }
      _beforeVersionBytes += end + 1;
      if (_beforeVersionBytes > _maxBeforeVersionBytes) {
        throw SSHHandshakeError('Version exchange too long');
      }
      printDebug?.call('SSHTransport: a line before the version string was passed over');
    }

    // RFC compatibility: SSH-1.99 banners indicate SSH-2 support with SSH-1 fallback.
    if (!(versionString.startsWith('SSH-2.0-') ||
        versionString.startsWith('SSH-1.99-'))) {
      _writeToSocket(latin1.encode('Protocol mismatch\r\n'));
      throw SSHHandshakeError('Invalid version: $versionString');
    }

    printTrace?.call('<- $socket: $versionString');
    printDebug?.call('SSHTransport._remoteVersion = "$versionString"');
    _remoteVersion = versionString;

    onVersionExchange?.call(_localVersion, versionString);

    if (isServer) {
      _sendKexInit();
    } else {
      _kexInitWait = Timer(kexInitPatience, _kexInitNotCome);
    }

    // There maybe more data in the buffer, so process it. Fire-and-forget for
    // the same reason as in [_processData]: the async loop self-handles errors.
    unawaited(_processPackets());
  }

  /// Whether the remote sequence number was just reset (strict KEX) and
  /// the automatic post-message increment should be skipped once.
  bool _skipNextRemoteSNIncrease = false;

  /// Reentrancy guard for [_processPackets]. While the loop is suspended on its
  /// periodic `await` (see below), more socket data can arrive and its handler
  /// calls [_processPackets] again; the guard makes that re-entry a no-op.
  bool _processingPackets = false;

  /// How many packets to dispatch between cooperative yields. Every this-many
  /// packets the loop hands control back to the event loop so the platform
  /// message pump / frame scheduler get a slice during a large inbound burst.
  ///
  /// Kept SMALL (~128 KB of decrypt at 16 KB/packet) so each burst finishes
  /// well inside a 16 ms frame even on a slow pure-Dart ChaCha20 path - the file
  /// list stays scrollable during a big download. A zero-delay yield adds no
  /// crypto work, so yielding more often costs no throughput; 32 (≈512 KB, ~1-2
  /// dropped frames per burst) was the visible jank.
  static const int _packetsPerYield = 8;

  /// Process one or more SSH packets queued in [_buffer].
  ///
  /// This is asynchronous purely so it can *cooperatively yield* to the event
  /// loop during a large inbound burst (e.g. an SFTP download where the
  /// ChaCha20-Poly1305 decrypt loop would otherwise monopolise the isolate for
  /// a minute-plus, freezing the UI / window-restore on Windows). Packet
  /// ordering, framing and decryption are unchanged - the only additions are
  /// the reentrancy guard, the periodic zero-delay yield, and moving the
  /// error handling that used to live in [_onSocketData] inside here (async
  /// errors no longer surface synchronously to that caller).
  Future<void> _processPackets() async {
    // See [_processingPackets]: a re-entrant call arriving while we are yielded
    // must not start a second interleaved loop. It is safe to simply return -
    // the still-running loop re-reads [_buffer] every iteration (the `while`
    // condition below evaluates `_buffer.isNotEmpty` afresh), so any data the
    // re-entrant caller appended is drained by the loop already in progress.
    if (_processingPackets) return;
    _processingPackets = true;

    // The number of the message that is being handled, once a packet has
    // been taken off the line and has a message in it: for what is said of
    // something thrown meanwhile that is none of the package's own errors.
    int? handling;
    try {
      var processedSinceYield = 0;
      final sinceYield = Stopwatch()..start();
      while (_buffer.isNotEmpty && !isClosed) {
        handling = null;
        final payload = _consumePacket();
        if (payload == null) {
          break;
        }

        handling = SSHMessage.readMessageId(payload);
        _handleMessage(payload);

        // What came in under keys is counted, and new keys are asked for
        // when it is time. (A NEWKEYS has just put the counts at nought.)
        if (_remoteUnderKeys) _receivedUnderKeys(payload.length);

        // After a strict-KEX sequence number reset (in _handleMessageNewKeys),
        // skip one increment so the next encrypted packet uses nonce 0.
        if (_skipNextRemoteSNIncrease) {
          _skipNextRemoteSNIncrease = false;
        } else {
          _remotePacketSN.increase();
        }

        // Cooperatively yield after every [_packetsPerYield] packets OR once
        // ~8ms has elapsed since the last yield, whichever comes first, so a
        // sustained burst can't starve the platform event loop. The count
        // alone is not enough when packets are large or the cipher is slow;
        // the time cap guarantees control returns to the pump within a frame
        // regardless of packet size (mirrors the send-side _uploadLoop). The
        // loop condition re-reads [_buffer] after the await, so data that
        // arrived during the yield is drained by this same loop (the reentrant
        // call that appended it was a no-op).
        if (++processedSinceYield >= _packetsPerYield ||
            sinceYield.elapsedMilliseconds >= 8) {
          processedSinceYield = 0;
          sinceYield.reset();
          await Future<void>.delayed(Duration.zero);
        }
      }
    } on SSHError catch (e, stackTrace) {
      printDebug?.call('SSHTransport: SSH error during packet processing: $e');
      closeWithError(e, stackTrace);
    } catch (e, stackTrace) {
      // Mirror [_onSocketData]: any non-SSHError raised while a packet is
      // taken off the line or its message is handled must tear the
      // connection down cleanly rather than escape as an uncaught async
      // error that hangs the connect future forever.
      //
      // It is said by what is known of it. A packet that could not be taken
      // off the line, or has no message in it, is a malformed packet. Once
      // the message is known by its number, what is thrown may come of the
      // message (a field that is cut short or cannot be read: a RangeError,
      // a FormatException) or of what handles it (the client's own handler,
      // something an application asked to be told of): which, this cannot
      // tell, so it says the number and what was thrown. (All of it was a
      // "Malformed packet", and whoever read that of a handler that had
      // failed went looking for what the server had sent wrong.)
      printDebug?.call(
          'SSHTransport: Unexpected error during packet processing: $e\n$stackTrace');
      closeWithError(
        SSHPacketError(
          handling == null ? 'Malformed packet: $e' : 'Message $handling could not be read or handled: $e',
        ),
        stackTrace,
      );
    } finally {
      _processingPackets = false;
    }
  }

  /// Reads a single SSH packet from the buffer. Returns payload of the packet
  /// WITHOUT `packet length`, `padding length`, `padding` and `MAC`. Returns
  /// `null` if there is not enough data in the buffer to read the packet.
  Uint8List? _consumePacket() {
    final remoteCipherType = _remoteCipherType;
    return remoteCipherType == null
        ? _consumeClearTextPacket()
        : _consumeEncryptedPacket(remoteCipherType);
  }

  /// Whether what the other side sends comes under keys by now: from its
  /// first NEWKEYS on.
  bool get _remoteUnderKeys => _remoteCipherType != null;

  /// Whether what the other side sends is its own by now: it comes under
  /// keys and, where this side is the client, under those of a host key that
  /// was approved. Until then it comes in the clear, or from whoever holds a
  /// host key nobody has approved yet: from anybody on the way.
  bool get _remoteIsItself => _remoteUnderKeys && (isServer || _hostkeyVerified);

  Uint8List? _consumeClearTextPacket() {

    if (_buffer.length < 4) {
      return null;
    }

    final packetLength = SSHPacket.readPacketLength(_buffer.data);
    _verifyPacketLength(packetLength);

    if (_buffer.length < packetLength + 4) {
      return null;
    }

    final packet = _buffer.consume(packetLength + 4);
    final paddingLength = SSHPacket.readPaddingLength(packet);
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);

    return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
  }

  /// Reads a packet under [remoteCipherType], the cipher whose keys are in
  /// force for what the other side sends.
  Uint8List? _consumeEncryptedPacket(SSHCipherType remoteCipherType) {
    // ChaCha20-Poly1305 has its own framing with encrypted length
    if (remoteCipherType.isChaCha) {
      return _consumeChaChaPacket();
    }

    if (remoteCipherType.isAead) {
      return _consumeAeadPacket(remoteCipherType);
    }

    final blockSize = _decryptCipher!.blockSize;
    if (_buffer.length < blockSize) {
      return null;
    }

    final macType = _remoteMacType!;
    final isEtm = macType.isEtm;
    final macLength = _remoteMac!.macSize;

    if (isEtm) {
      // For ETM (Encrypt-Then-MAC) algorithms, the packet length is in plaintext
      // followed by the encrypted payload and then the MAC

      // We need at least 4 bytes to read the packet length
      if (_buffer.length < 4) {
        return null;
      }

      // Read the packet length from the plaintext data
      final packetLength = SSHPacket.readPacketLength(_buffer.data);
      _verifyPacketLength(packetLength);

      // Make sure we have enough data for the entire packet and MAC
      if (_buffer.length < 4 + packetLength + macLength) {
        return null;
      }

      // Get the packet length bytes
      final packetLengthBytes = _buffer.view(0, 4);

      // Get the encrypted payload and MAC
      final encryptedPayload = _buffer.view(4, packetLength);
      final mac = _buffer.view(4 + packetLength, macLength);

      // Verify the MAC on the packet length and encrypted payload
      final packetForMac = Uint8List(4 + packetLength);
      packetForMac.setRange(0, 4, packetLengthBytes);
      packetForMac.setRange(4, 4 + packetLength, encryptedPayload);
      _verifyPacketMac(packetForMac, mac, isEncrypted: true);

      // Consume the packet and MAC from the buffer
      _buffer.consume(4 + packetLength + macLength);

      // Ensure the encrypted payload length is a multiple of the block size
      if (encryptedPayload.length % blockSize != 0) {
        throw SSHPacketError(
          'Encrypted payload length ${encryptedPayload.length} is not a multiple of block size $blockSize',
        );
      }

      // Decrypt the payload
      final decryptedPayload = _decryptCipher!.processAll(encryptedPayload);

      // Process the decrypted payload
      final paddingLength = decryptedPayload[0];

      // Verify that the padding length is valid
      if (paddingLength < 4) {
        throw SSHPacketError(
          'Padding length too small: $paddingLength (minimum is 4)',
        );
      }

      if (paddingLength >= packetLength) {
        throw SSHPacketError(
          'Padding length too large: $paddingLength (packet length is $packetLength)',
        );
      }

      final payloadLength = packetLength - paddingLength - 1;
      if (payloadLength < 0) {
        throw SSHPacketError(
          'Invalid payload length: $payloadLength (packet length: $packetLength, padding length: $paddingLength)',
        );
      }

      // Skip the padding length byte and extract the payload
      return Uint8List.sublistView(decryptedPayload, 1, 1 + payloadLength);
    } else {
      // For standard MAC algorithms, decrypt the packet first, then verify the MAC

      if (_decryptBuffer.isEmpty) {
        final firstBlock = _buffer.consume(blockSize);
        _decryptBuffer.add(_decryptCipher!.process(firstBlock));
      }

      final packetLength = SSHPacket.readPacketLength(_decryptBuffer.data);
      _verifyPacketLength(packetLength);
      // A packet of this kind is encrypted whole, its length with it, block
      // by block: one that is no whole number of blocks is none. (Blocks
      // were read until the packet was there, into the MAC behind it.)
      if ((4 + packetLength) % blockSize != 0) throw _damagedPacket(itsLength: true);

      if (_buffer.length + _decryptBuffer.length <
          4 + packetLength + macLength) {
        return null;
      }

      while (_decryptBuffer.length < 4 + packetLength) {
        final block = _buffer.consume(blockSize);
        _decryptBuffer.add(_decryptCipher!.process(block));
      }

      final packet = _decryptBuffer.consume(packetLength + 4);
      // The MAC first: nothing of the packet is looked into before it has
      // passed its check. (Its padding was, and a packet that was changed
      // on the way was then said by what its padding looked like, with the
      // numbers in it.)
      final mac = _buffer.consume(macLength);
      _verifyPacketMac(packet, mac, isEncrypted: false);

      final paddingLength = SSHPacket.readPaddingLength(packet);
      final payloadLength = packetLength - paddingLength - 1;
      _verifyPacketPadding(payloadLength, paddingLength);

      return Uint8List.sublistView(packet, 5, packet.length - paddingLength);
    }
  }

  Uint8List? _consumeChaChaPacket() {
    final chacha = _remoteChaCha!;

    // Enforce monotonically increasing sequence numbers (Finding 1.2).
    final currentSeq = _remotePacketSN.value;
    if (_lastRemoteChaChaSeq != null && currentSeq <= _lastRemoteChaChaSeq!) {
      throw SSHPacketError(
        'ChaCha20 nonce reuse detected: sequence $currentSeq '
        '<= last $_lastRemoteChaChaSeq',
      );
    }

    // Need at least 4 bytes for the encrypted length
    if (_buffer.length < 4) {
      return null;
    }

    // Peek at the encrypted length to determine packet size
    final encryptedLength = _buffer.view(0, 4);
    final packetLength = chacha.decryptLength(
      Uint8List.fromList(encryptedLength),
      _remotePacketSN.value,
    );
    _verifyPacketLength(packetLength);

    // Need: 4 (enc length) + packetLength (enc payload) + 16 (tag)
    const tagLength = SSHCipherChaCha20Poly1305.tagSize;
    if (_buffer.length < 4 + packetLength + tagLength) {
      return null;
    }

    // Consume all the data
    final encLenBytes = _buffer.consume(4);
    final encPayload = _buffer.consume(packetLength);
    final tag = _buffer.consume(tagLength);

    // Decrypt and verify MAC
    final Uint8List plaintext;
    try {
      plaintext = chacha.decrypt(
        encLenBytes,
        encPayload,
        tag,
        _remotePacketSN.value,
      );
    } on SSHMacMismatchException {
      throw _damagedPacket();
    }

    final paddingLength = plaintext[0];
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);

    // Record the successfully consumed sequence number for monotonicity.
    _lastRemoteChaChaSeq = currentSeq;

    return Uint8List.sublistView(plaintext, 1, 1 + payloadLength);
  }

  Uint8List? _consumeAeadPacket(SSHCipherType cipherType) {
    if (_buffer.length < 4) {
      return null;
    }

    final packetLength = SSHPacket.readPacketLength(_buffer.data);
    _verifyPacketLength(packetLength);

    final tagLength = cipherType.aeadTagSize;
    if (_buffer.length < 4 + packetLength + tagLength) {
      return null;
    }

    final aad = _buffer.consume(4);
    final ciphertext = _buffer.consume(packetLength);
    final tag = _buffer.consume(tagLength);

    final encryptedInput = Uint8List(packetLength + tagLength)
      ..setRange(0, packetLength, ciphertext)
      ..setRange(packetLength, packetLength + tagLength, tag);

    late Uint8List plaintext;
    try {
      plaintext = _processAead(
        key: _remoteCipherKey!,
        iv: _remoteIV!,
        packetsBefore: _remoteGcmPackets,
        aad: aad,
        input: encryptedInput,
        forEncryption: false,
      );
    } on InvalidCipherTextException {
      throw _damagedPacket();
    }
    _remoteGcmPackets++;

    final paddingLength = plaintext[0];
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);
    return Uint8List.sublistView(plaintext, 1, 1 + payloadLength);
  }

  void _verifyPacketLength(int packetLength) {
    if (packetLength > SSHPacket.maxLength) {
      // Under keys the length of a packet is read before the packet can be
      // checked, and a packet comes as its sender made it or not at all.
      if (_remoteUnderKeys) throw _damagedPacket(itsLength: true);
      throw SSHPacketError('Packet too long: $packetLength');
    }
  }

  /// What a packet under keys ends the connection with when it does not
  /// pass its check, or has a length no packet has ([itsLength]): the same
  /// whatever protects the packets, with [SSHPacketError.damaged] set for
  /// an application to say it by.
  ///
  /// The words say what is known and no more: the packet is not what the
  /// other side made with the keys both sides arrived at. That is so when
  /// it was changed on the way, and when the two sides do not protect their
  /// packets the same way (keys that differ, a count of packets that
  /// differs). There is nothing of the packet in them. (They held the check
  /// value it came with and the one it should have had, which is made with
  /// the session's key.)
  static SSHPacketError _damagedPacket({bool itsLength = false}) => SSHPacketError(
        'A packet from the other side '
        '${itsLength ? 'has a length that no packet has' : 'did not pass its check'}: '
        'it was changed or damaged on the way, or the two sides do not protect '
        'their packets the same way',
        damaged: true,
      );

  /// Verifies that the padding of the packet is correct. Throws [SSHPacketError]
  /// if the padding is incorrect.
  void _verifyPacketPadding(int payloadLength, int paddingLength) {
    // Bound padding BEFORE the alignment math. `paddingLength` is a single
    // attacker-controlled byte (0-255) and `payloadLength` is derived as
    // `packetLength - paddingLength - 1`. Without this guard a crafted packet
    // with an oversized padding byte drives `payloadLength` negative and makes
    // every caller's `sublistView(packet, 5, packet.length - paddingLength)`
    // request a negative end index - a RangeError that escapes as an
    // unhandled zone error instead of a clean protocol teardown. RFC 4253
    // requires at least 4 padding bytes, and payload can never be negative.
    if (paddingLength < 4 || payloadLength < 0) {
      throw SSHPacketError(
        'Invalid padding: paddingLength=$paddingLength '
        'payloadLength=$payloadLength',
      );
    }

    // The cipher whose keys are in force for what the peer sends, the one
    // _consumePacket picks its framing by. A cipher that is merely
    // negotiated (KEXINIT done, NEWKEYS not yet received) is not that: the
    // KEX reply and NEWKEYS still travel as before, in the clear at the
    // first exchange, where they follow the plain 5-byte-header alignment.
    // (Deciding by the negotiated type rejected valid cleartext replies
    // whose payload length happened to make the two rules differ: an ECDH
    // P-256 reply signed with an Ed25519 host key, for one.)
    final remoteCipherType = _remoteCipherType;
    final remoteAeadActive = remoteCipherType != null && remoteCipherType.isAead;

    int expectedPacketAlign;
    if (remoteCipherType == null) {
      expectedPacketAlign = SSHPacket.minAlign;
    } else if (remoteAeadActive) {
      expectedPacketAlign = max(SSHPacket.minAlign, remoteCipherType.blockSize);
    } else {
      expectedPacketAlign = max(SSHPacket.minAlign, _decryptCipher!.blockSize);
    }

    int minPaddingLength;

    if (remoteAeadActive) {
      // Both ChaCha20-Poly1305 and AES-GCM exclude the 4-byte packet-length
      // field from block alignment: ChaCha encrypts it separately, and GCM
      // carries it as cleartext AAD (RFC 5647). Alignment is therefore over
      // (1 + payloadLength + paddingLength) only. This mirrors
      // [_alignedPaddingLength] on the send side; using the generic 5-byte
      // header formula here (the previous behaviour for AEAD) computed a
      // different minimum and REJECTED valid AES-GCM packets outright.
      minPaddingLength =
          expectedPacketAlign - ((payloadLength + 1) % expectedPacketAlign);
      if (minPaddingLength < 4) minPaddingLength += expectedPacketAlign;
    } else {
      minPaddingLength = SSHPacket.paddingLength(
        payloadLength,
        align: expectedPacketAlign,
      );
    }

    if (paddingLength < minPaddingLength) {
      throw SSHPacketError(
        'Invalid padding length: $paddingLength, expected: $minPaddingLength',
      );
    }
  }

  /// Length-independent, constant-time byte comparison used for the re-key
  /// host-key pin. Host keys are public, but comparing in constant time keeps
  /// the check free of data-dependent timing regardless.
  static bool _hostKeyBytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Verifies that the MAC of the packet is correct. Throws [SSHPacketError]
  /// if the MAC is incorrect.
  ///
  /// For ETM (Encrypt-Then-MAC) algorithms, the MAC is calculated on the packet length and encrypted payload.
  /// For standard MAC algorithms, the MAC is calculated on the unencrypted packet.
  void _verifyPacketMac(Uint8List payload, Uint8List actualMac,
      {bool isEncrypted = false}) {
    final macSize = _remoteMac!.macSize;
    if (actualMac.length != macSize) {
      throw ArgumentError.value(actualMac, 'mac', 'Invalid MAC size');
    }

    final macType = _remoteMacType!;
    final isEtm = macType.isEtm;

    _remoteMac!.updateAll(_remotePacketSN.value.toUint32());

    // For ETM algorithms, the MAC is calculated on the packet length and encrypted payload
    // For standard MAC algorithms, the MAC is calculated on the unencrypted packet
    if (isEtm && isEncrypted) {
      _remoteMac!.updateAll(payload);
    } else if (!isEtm && !isEncrypted) {
      _remoteMac!.updateAll(payload);
    } else {
      throw SSHPacketError(
        'MAC algorithm mismatch: isEtm=$isEtm, isEncrypted=$isEncrypted',
      );
    }

    final expectedMac = _remoteMac!.finish();

    if (!expectedMac.equals(actualMac)) throw _damagedPacket();
  }

  void _startHandshake() {
    _writeToSocket(latin1.encode('$_localVersion\r\n'));

    if (isClient) {
      _sendKexInit();
    }
  }

  /// Installs the keys of the exchange for what this side sends, and with
  /// them what the exchange agreed on for that direction: from here on it
  /// is what protects what goes out ([_localCipherType]). Called when our
  /// own NEWKEYS has gone out, and nowhere else.
  void _applyLocalKeys() {
    final cipherType = isClient ? _clientCipherType : _serverCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');
    // A cipher that checks its packets by itself has no MAC beside it.
    final macType = cipherType.isAead
        ? null
        : (isClient ? _clientMacType : _serverMacType);
    if (!cipherType.isAead && macType == null) {
      throw StateError('No MAC type selected');
    }

    // Zero old key material before overwriting references (rekey safety).
    if (_localCipherKey != null) zeroBytes(_localCipherKey!);
    if (_localIV != null && _localIV!.isNotEmpty) zeroBytes(_localIV!);

    _localCipherType = cipherType;
    _localMacType = macType;

    // New keys: what goes out under them is counted from here.
    _localGcmPackets = 0;
    _sentPacketsUnderKeys = 0;
    _sentBytesUnderKeys = 0;

    _localCipherKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
      cipherType.keySize,
    );

    if (cipherType.isChaCha) {
      // ChaCha20-Poly1305 does not use a derived IV; the nonce is the
      // sequence number. The 64-byte key is split internally.
      _localIV = Uint8List(0);
      _encryptCipher = null;
      _localMac = null;
      return;
    }

    _localIV = _deriveKey(
      isClient ? SSHDeriveKeyType.clientIV : SSHDeriveKeyType.serverIV,
      cipherType.ivSize,
    );

    if (cipherType.isAead) {
      _encryptCipher = null;
      _localMac = null;
      return;
    }

    _encryptCipher = cipherType.createCipher(
      _localCipherKey!,
      _localIV!,
      forEncryption: true,
    );

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientMacKey : SSHDeriveKeyType.serverMacKey,
      macType!.keySize,
    );

    _localMac = macType.createMac(macKey);
  }

  /// Installs the keys of the exchange for what the other side sends, and
  /// with them what the exchange agreed on for that direction: from here on
  /// it is what its packets are read by ([_remoteCipherType]). Called when
  /// the other side's NEWKEYS has come, and nowhere else.
  void _applyRemoteKeys() {
    final cipherType = isClient ? _serverCipherType : _clientCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');
    // A cipher that checks its packets by itself has no MAC beside it.
    final macType = cipherType.isAead
        ? null
        : (isClient ? _serverMacType : _clientMacType);
    if (!cipherType.isAead && macType == null) {
      throw StateError('No MAC type selected');
    }

    // Rekey opens a fresh key epoch: under strict KEX the receive sequence
    // number restarts at 0 under a brand-new key, so re-arm the ChaCha
    // nonce-reuse monotonicity guard. Without this the guard would see the
    // post-rekey seq drop from a high value back to 0 and falsely flag nonce
    // reuse (it is NOT reuse: the key rotated). Kept atomic with the key
    // rotation here.
    _lastRemoteChaChaSeq = null;

    // Zero old key material before overwriting references (rekey safety).
    if (_remoteCipherKey != null) zeroBytes(_remoteCipherKey!);
    if (_remoteIV != null && _remoteIV!.isNotEmpty) zeroBytes(_remoteIV!);

    _remoteCipherType = cipherType;
    _remoteMacType = macType;

    // New keys: what comes in under them is counted from here.
    _remoteGcmPackets = 0;
    _receivedPacketsUnderKeys = 0;
    _receivedBytesUnderKeys = 0;

    _remoteCipherKey = _deriveKey(
      isClient ? SSHDeriveKeyType.serverKey : SSHDeriveKeyType.clientKey,
      cipherType.keySize,
    );

    if (cipherType.isChaCha) {
      // ChaCha20-Poly1305 does not use a derived IV; the nonce is the
      // sequence number. The 64-byte key is split internally.
      _remoteIV = Uint8List(0);
      _remoteChaCha = SSHCipherChaCha20Poly1305(key: _remoteCipherKey!);
      _decryptCipher = null;
      _remoteMac = null;
      return;
    }

    // Not ChaCha20 -- clear any stale ChaCha instance from a prior cipher.
    _remoteChaCha = null;

    _remoteIV = _deriveKey(
      isClient ? SSHDeriveKeyType.serverIV : SSHDeriveKeyType.clientIV,
      cipherType.ivSize,
    );

    if (cipherType.isAead) {
      _decryptCipher = null;
      _remoteMac = null;
      return;
    }

    _decryptCipher = cipherType.createCipher(
      _remoteCipherKey!,
      _remoteIV!,
      forEncryption: false,
    );

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.serverMacKey : SSHDeriveKeyType.clientMacKey,
      macType!.keySize,
    );
    _remoteMac = macType.createMac(macKey);
  }

  Uint8List _deriveKey(SSHDeriveKeyType keyType, int keySize) {
    return SSHKexUtils.deriveKey(
      digest: _kexType!.createDigest(),
      sharedSecret: _sharedSecret!,
      exchangeHash: _exchangeHash!,
      keyType: keyType,
      sessionId: _sessionId!,
      keySize: keySize,
    );
  }

  /// Composes the data blob to be signed by the client with its public key.
  Uint8List composeChallenge({
    required String username,
    required String service,
    required String publicKeyAlgorithm,
    required Uint8List publicKey,
  }) {
    final writer = SSHMessageWriter();
    writer.writeString(_sessionId!);
    writer.writeUint8(SSH_Message_Userauth_Request.messageId);
    writer.writeUtf8(username);
    writer.writeUtf8(service);
    writer.writeUtf8('publickey');
    writer.writeBool(true);
    writer.writeUtf8(publicKeyAlgorithm);
    writer.writeString(publicKey);
    return writer.takeBytes();
  }

  /// Whether the key the server shows ([keyBytes]) signed this exchange:
  /// whether [signatureBytes] is its signature of [exchangeHash].
  ///
  /// The key has to be of the kind that was agreed on, and its signature of
  /// the kind of the key. A key that is not, and bytes that are no key or
  /// no signature, are refused with an [SSHHostkeyError] that says so: a
  /// host key that cannot be taken is a host key that was refused, whatever
  /// it failed on, and not a packet that could not be read.
  /// (A key was read by what was agreed on, with nothing held to it: an
  /// ECDSA key of another curve was taken, since the three read alike, and
  /// anything that did not read ended the connection as a "Malformed
  /// packet". See the changelog, "A host key is of the kind that was agreed
  /// on".)
  bool _verifyHostkey({
    required Uint8List keyBytes,
    required Uint8List signatureBytes,
    required Uint8List exchangeHash,
  }) {
    final agreed = _hostkeyType;
    if (agreed == null) throw StateError('No hostkey type negotiated');
    try {
      _requireHostKeyOfTheKindAgreedOn(agreed, keyBytes);
      return _signedByHostKey(agreed, keyBytes, signatureBytes, exchangeHash);
    } on SSHHostkeyError catch (e) {
      // What reads a key does not know which exchange of the connection
      // this is: that is said here.
      if (!_hostkeyVerified) rethrow;
      throw SSHHostkeyError(e.message, fault: e.fault, duringRekey: true);
    } on SSHError {
      rethrow;
    } catch (e) {
      throw SSHHostkeyError(
        'The host key or its signature could not be read: '
        '${_asSaid('$e', 160)}',
        fault: SSHHostkeyFault.noKey,
        duringRekey: _hostkeyVerified,
      );
    }
  }

  /// The kind a host key has to be of where [agreed] was agreed on: the
  /// name of the algorithm itself, which for an RSA key is `ssh-rsa` also
  /// under the two newer names an RSA signature has.
  static String _keyKindAgreedOn(SSHHostkeyType agreed) =>
      agreed == SSHHostkeyType.rsaSha256 || agreed == SSHHostkeyType.rsaSha512
          ? SSHRsaPublicKey.type
          : agreed.name;

  /// Refuses a key that says it is of another kind than was agreed on (RFC
  /// 4253, 7.1: the server shows a key of the algorithm that was chosen).
  static void _requireHostKeyOfTheKindAgreedOn(
    SSHHostkeyType agreed,
    Uint8List keyBytes,
  ) {
    final shown = SSHMessageReader(keyBytes).readUtf8();
    final wanted = _keyKindAgreedOn(agreed);
    if (shown != wanted) {
      throw SSHHostkeyError(
        'The server showed a host key of the kind "${_asSaid(shown, 64)}", '
        'and "$wanted" was agreed on',
        fault: SSHHostkeyFault.noKey,
      );
    }
  }

  /// [text] of the other side's own, or made of it, as it goes into an
  /// error: the characters a name of the protocol can have and a few that
  /// words have, anything else as a question mark, and no longer than
  /// [most].
  static String _asSaid(String text, int most) {
    final cut = text.length > most ? '${text.substring(0, most)}...' : text;
    return cut.replaceAll(RegExp(r'[^A-Za-z0-9@._+\-:,()/ ]'), '?');
  }

  bool _signedByHostKey(
    SSHHostkeyType agreed,
    Uint8List keyBytes,
    Uint8List signatureBytes,
    Uint8List exchangeHash,
  ) {
    switch (agreed) {
      case SSHHostkeyType.ed448:
        final publicKey = SSHEd448PublicKey.decode(keyBytes);
        final signature = SSHEd448Signature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.ed25519:
        final publicKey = SSHEd25519PublicKey.decode(keyBytes);
        final signature = SSHEd25519Signature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.rsaSha1:
      case SSHHostkeyType.rsaSha256:
      case SSHHostkeyType.rsaSha512:
        final publicKey = SSHRsaPublicKey.decode(keyBytes);
        _requireRsaHostKeyOfASize(publicKey, shortestTaken: algorithms.minRsaHostKeyBits);
        final signature = SSHRsaSignature.decode(signatureBytes);
        // RFC 8332: the signature algorithm MUST match the host-key
        // algorithm negotiated in KEXINIT. Without this check a server can
        // present a SHA-1 `ssh-rsa` signature even when we negotiated
        // rsa-sha2-512/256, silently downgrading host authentication to
        // SHA-1. A compliant server always matches, so reject a mismatch.
        const expectedSig = {
          SSHHostkeyType.rsaSha1: SSHRsaSignatureType.sha1,
          SSHHostkeyType.rsaSha256: SSHRsaSignatureType.sha256,
          SSHHostkeyType.rsaSha512: SSHRsaSignatureType.sha512,
        };
        if (signature.type != expectedSig[agreed]) {
          throw SSHHostkeyError(
            'The signature of the host key is of the kind '
            '"${_asSaid(signature.type, 64)}", and "${agreed.name}" was '
            'agreed on',
            fault: SSHHostkeyFault.noKey,
          );
        }
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.ecdsa256:
      case SSHHostkeyType.ecdsa384:
      case SSHHostkeyType.ecdsa521:
        final publicKey = SSHEcdsaPublicKey.decode(keyBytes);
        final signature = SSHEcdsaSignature.decode(signatureBytes);
        // The signature says its own kind too, and its key's is the kind
        // it has to be of: the hash it is checked with goes by the key.
        if (signature.type != publicKey.type) {
          throw SSHHostkeyError(
            'The signature of the host key is of the kind '
            '"${_asSaid(signature.type, 64)}", and its key is of the kind '
            '"${publicKey.type}"',
            fault: SSHHostkeyFault.noKey,
          );
        }
        return publicKey.verify(exchangeHash, signature);
      default:
        throw UnimplementedError('Unsupported hostkey type: $agreed');
    }
  }

  /// The longest RSA host key that is taken, by its modulus, in bits. No
  /// server has a longer one, and OpenSSH takes none.
  static const _maxRsaHostKeyBits = 16384;

  /// The longest public exponent of an RSA host key that is taken, in bits.
  /// It is 65537 in any key that anybody makes; OpenSSH's library takes none
  /// of more than 64 bits beside a long modulus.
  static const _maxRsaHostKeyExponentBits = 64;

  /// Refuses an RSA host key that no server has, before anything is
  /// computed with it.
  ///
  /// The check of a host key's signature raises a number to the key's
  /// public exponent, modulo the key, and how long that takes is for
  /// whoever sends the key to choose: with the length of the modulus and
  /// with the length of the exponent. It is done before anybody is asked
  /// whether they trust the key, and before the sign-in: whoever stands
  /// between a client and its server can send a key in the server's place.
  /// A key of 16384 bits with an exponent as long keeps a desktop's
  /// processor busy for more than a second, a doubling of both makes that
  /// eight times as long, and a key in one packet can be eight times as
  /// long: more than ten minutes in which the program does nothing else.
  /// (A key of any size was checked until this was held. See the
  /// changelog, "An RSA host key of a size no key has is refused".)
  ///
  /// A key shorter than [shortestTaken] bits is refused here as well, and
  /// said as what it is: too short, with both lengths, and not as no key.
  /// Such a key is a key, and what it would take to accept it is for
  /// whoever connects to say (`SSHAlgorithms.minRsaHostKeyBits`). (A key of
  /// any length down to what holds a signature was taken until this was
  /// held. See the changelog, "An RSA host key shorter than 1024 bits is
  /// refused".)
  static void _requireRsaHostKeyOfASize(SSHRsaPublicKey key, {required int shortestTaken}) {
    // (Neither number is below nought: a number is read off the wire as it
    // stands, with no sign.)
    final n = key.n;
    final e = key.e;
    if (n.isEven) {
      throw SSHHostkeyError(
        'The RSA host key has a modulus that is none: it is an even number, '
        'or nought',
        fault: SSHHostkeyFault.noKey,
      );
    }
    if (n.bitLength < shortestTaken) {
      throw SSHHostkeyError(
        'The RSA host key has a modulus of ${n.bitLength} bits, and none of '
        'less than $shortestTaken is taken',
        fault: SSHHostkeyFault.tooShort,
        bits: n.bitLength,
        shortestTaken: shortestTaken,
      );
    }
    if (n.bitLength > _maxRsaHostKeyBits) {
      throw SSHHostkeyError(
        'The RSA host key has a modulus of ${n.bitLength} bits, and no key '
        'has one of more than $_maxRsaHostKeyBits',
        fault: SSHHostkeyFault.noKey,
      );
    }
    if (e.bitLength > _maxRsaHostKeyExponentBits) {
      throw SSHHostkeyError(
        'The RSA host key has a public exponent of ${e.bitLength} bits, and '
        'no key has one of more than $_maxRsaHostKeyExponentBits',
        fault: SSHHostkeyFault.noKey,
      );
    }
    if (e < BigInt.from(3) || e.isEven) {
      throw SSHHostkeyError(
        'The RSA host key has a public exponent that is none ($e): it has '
        'to be odd, and at least 3',
        fault: SSHHostkeyFault.noKey,
      );
    }
  }

  void _sendKexInit() {
    printDebug?.call('SSHTransport._sendKexInit');

    // Don't start a new key exchange when one is already in progress
    if (_kexInProgress && _sentKexInit) {
      printDebug?.call('Key exchange already in progress, ignoring');
      return;
    }

    // Mark that a new key-exchange round has started from our side.
    _kexInProgress = true;
    _sentKexInit = true;

    // Advertise strict KEX extension (Terrapin / CVE-2023-48795 mitigation)
    // during the initial key exchange only. The extension indicator is a
    // pseudo-algorithm appended to the kexAlgorithms name list.
    final kexNames = algorithms.kex.toNameList();
    if (_isInitialKex && isClient) {
      // The server is asked to say what it has to say of itself once its
      // keys are in force (RFC 8308, 2.1): in the first proposal, and in no
      // later one. What it says then: [_handleMessageExtInfo].
      kexNames.add('ext-info-c');
      kexNames.add('kex-strict-c-v00@openssh.com');
    }

    final message = SSH_Message_KexInit(
      kexAlgorithms: kexNames,
      serverHostKeyAlgorithms: algorithms.hostkey.toNameList(),
      encryptionClientToServer: algorithms.cipher.toNameList(),
      encryptionServerToClient: algorithms.cipher.toNameList(),
      macClientToServer: algorithms.mac.toNameList(),
      macServerToClient: algorithms.mac.toNameList(),
      compressionClientToServer: ['none'],
      compressionServerToClient: ['none'],
      firstKexPacketFollows: false,
    );

    final payload = message.encode();
    _localKexInit = payload;

    sendPacket(payload);
    printTrace?.call('-> $socket: $message');
  }

  /// Send diffie-hellman key exchange message. The exact message format depends
  /// on the negotiated key exchange algorithm.
  void _sendKexDHInit() {
    printDebug?.call('SSHTransport._sendKexDHInit');

    final kex = _kex;
    late final SSHMessage message;

    if (kex is SSHKexDH) {
      message = SSH_Message_KexDH_Init(e: kex.e);
    } else if (kex is SSHKexECDH) {
      message = SSH_Message_KexECDH_Init(kex.publicKey);
    } else if (kex is SSHKexHybrid) {
      // Same message id as ECDH_INIT, carrying the KEM key || X25519 key.
      message = SSH_Message_KexECDH_Init(kex.publicKey);
    } else {
      throw StateError('No key exchange algorithm negotiated');
    }

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  /// The shortest group a group exchange asks for and takes: 2048 bits,
  /// or 1024 where whoever connects has said that an old server may have
  /// no longer group (`SSHAlgorithms.minDhGroupBits`). The same number goes
  /// into the request, the check of the group the server names, and the
  /// exchange hash, which is made of what was asked for.
  int get _gexShortest => SSHKexDH.shortestAskedFor(algorithms.minDhGroupBits);

  void _sendKexDHGexRequest() {
    printDebug?.call('SSHTransport._sendKexDHGexRequest');

    final message = SSH_Message_KexDH_GexRequest(
      minN: _gexShortest,
      preferredN: SSHKexDH.gexPref,
      maxN: SSHKexDH.gexMax,
    );

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  void _sendKexDHGexInit() {
    printDebug?.call('SSHTransport._sendKexDHGexInit');

    final kex = _kex;
    if (kex is! SSHKexDH) {
      throw StateError('kex is not SSHKexDH');
    }

    final message = SSH_Message_KexDH_GexInit(e: kex.e);
    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  /// Sends [SSH_Message_NewKeys] message. After this message, all data sent
  /// to the server should be encrypted with the keys negotiated in key exchange.
  void _sendNewKeys() {
    printDebug?.call('SSHTransport._sendNewKeys');
    final message = SSH_Message_NewKeys();
    printTrace?.call('-> $socket: $message');
    sendPacket(message.encode());

    // Terrapin (CVE-2023-48795) strict KEX mitigation: reset the SEND
    // sequence number AFTER sending our NEWKEYS. The receive side is
    // reset in _handleMessageNewKeys() when we receive the server's.
    if (_serverSupportsStrictKex) {
      printDebug?.call('SSHTransport: strict KEX - resetting SEND sequence number');
      _localPacketSN.reset();
    }
  }

  /// Highest message id that is legal before the handshake completes.
  ///
  /// RFC 4253 §11 reserves 1-4 (DISCONNECT / IGNORE / UNIMPLEMENTED /
  /// DEBUG) as valid at any time; 20-29 are key exchange and are dispatched
  /// explicitly below. Everything from SERVICE_ACCEPT (6) upward -
  /// including all user-auth (50-79) and connection-protocol (80+)
  /// messages - is only meaningful once keys are in place.
  static const _maxPreHandshakeMessageId = 4;

  void _handleMessage(Uint8List message) {
    final messageId = SSHMessage.readMessageId(message);

    // Terrapin (CVE-2023-48795) strict-KEX enforcement.
    //
    // Once strict KEX is negotiated, the INITIAL key exchange must carry
    // key-exchange traffic and nothing else. OpenSSH's strict-KEX rule
    // forbids SSH_MSG_IGNORE(2) / UNIMPLEMENTED(3) / DEBUG(4) - and any other
    // non-KEX message - between the first KEXINIT and the first NEWKEYS,
    // because permitting them is precisely the packet-injection primitive
    // Terrapin uses to desynchronise the handshake transcript. Allow only
    // DISCONNECT(1), KEXINIT(20), NEWKEYS(21) and the two numbers a server
    // answers an exchange under (31: its answer, or the group of a group
    // exchange; 33: the answer to a group exchange), which the steps of the
    // exchange hold to their order ([_kexStep]); fail closed on anything
    // else. (Every number from 30 to 49 was let through, and one that is no
    // message of the exchange was handed up once the host key had been
    // looked at.) This is stricter than the generic pre-handshake gate below
    // (which tolerates ids 1-4), and only applies while strict KEX is active
    // during the initial exchange.
    if (_serverSupportsStrictKex && _isInitialKex) {
      const disconnectId = 1; // SSH_Message_Disconnect.messageId
      final allowed = messageId == disconnectId ||
          messageId == SSH_Message_KexInit.messageId || // 20
          messageId == SSH_Message_NewKeys.messageId || // 21
          messageId == SSH_Message_KexDH_Reply.messageId || // 31
          messageId == SSH_Message_KexDH_GexReply.messageId; // 33
      if (!allowed) {
        closeWithError(_strictOrderBroken(
          'unexpected message id $messageId during the initial key exchange',
        ));
        return;
      }
    }

    switch (messageId) {
      case SSH_Message_Disconnect.messageId:
        return _handleMessageDisconnect(message);
      case SSH_Message_KexInit.messageId:
        return _handleMessageKexInit(message);
      case SSH_Message_KexDH_Reply.messageId:
      case SSH_Message_KexDH_GexReply.messageId:
        return _handleMessageKexReply(message, messageId);
      case SSH_Message_NewKeys.messageId:
        return _handleMessageNewKeys(message);
      case SSH_Message_ExtInfo.messageId when _remoteUnderKeys:
        return _handleMessageExtInfo(message);
      default:
        // SECURITY: do not hand post-KEX messages to the connection layer
        // until what the other side sends is its own ([_remoteIsItself]):
        // under keys, and on a client those of a host key that was
        // verified.
        //
        // Host-key verification is ASYNCHRONOUS - `onVerifyHostKey` shows
        // the user a "this host is unknown / has changed, accept?" prompt
        // and we await their answer. Without this gate the transport kept
        // dispatching whatever the peer sent during that window, so a
        // man-in-the-middle could push an UNSOLICITED SERVICE_ACCEPT while
        // the dialog was still on screen. The client took that as "the
        // server is ready for user-auth" and sent the user's password -
        // before the user had accepted the key, and before any cipher was
        // installed, i.e. in cleartext straight to the attacker.
        //
        // The approval alone is not enough: until the server's first
        // NEWKEYS what arrives comes in the clear, and anybody on the way
        // can have written it. Where no strict key exchange was agreed (the
        // gate above), a SERVICE_ACCEPT and a USERAUTH_SUCCESS in the clear
        // were handed up once the key was approved, and whoever sat between
        // could play the client a session it took for the server's.
        //
        // Anything legal this early is handled above or allowed through
        // here; everything else is a protocol violation and we fail closed.
        if (!_remoteIsItself && messageId > _maxPreHandshakeMessageId) {
          closeWithError(SSHStateError(
            _hostkeyVerified
                ? 'Server sent message id $messageId in the clear, before its '
                    'NEWKEYS - refusing to continue.'
                : 'Server sent message id $messageId before host-key verification '
                    'completed - refusing to continue.',
          ));
          return;
        }
        onPacket?.call(message);
    }
  }

  /// What ends a connection whose server broke the order of the strict
  /// key exchange ([SSHHandshakeError.strictOrderBroken]), with [what] it
  /// was.
  static SSHHandshakeError _strictOrderBroken(String what) => SSHHandshakeError(
        'Strict KEX violation: $what (possible Terrapin attack).',
        strictOrderBroken: true,
      );

  /// What ends a key exchange whose two sides have no algorithm of one
  /// [kind] in common, with what each side offered of it
  /// ([SSHHandshakeError.offered], [SSHHandshakeError.otherSideOffered]):
  /// [mine] as this side offered them, and [theirs] as the other side's
  /// proposal names them, without the marks that are no algorithms
  /// ([_proposalMarks]). (Nothing said what either side had offered: whoever
  /// read the error had to ask the other side with another program.)
  static SSHHandshakeError _nothingInCommon(String kind, List<SSHAlgorithm> mine, List<String> theirs) =>
      SSHHandshakeError(
        'No matching $kind algorithm',
        offered: List.unmodifiable(mine.toNameList()),
        otherSideOffered: List.unmodifiable(theirs.where((name) => !_proposalMarks.contains(name))),
      );

  /// What a proposal names among its key exchanges that is no key exchange:
  /// the mark of the strict exchange and the request to be told the
  /// extensions, each as a client and as a server names it.
  static const _proposalMarks = {
    'ext-info-c',
    'ext-info-s',
    'kex-strict-c-v00@openssh.com',
    'kex-strict-s-v00@openssh.com',
  };

  /// The other side ends the connection, and says why. That is how the
  /// connection ends for whoever holds it: with what was said, and with
  /// whether it is the other side's own ([_remoteIsItself]): this message
  /// may come at any time, before any keys as well.
  /// (The message was handed on and dropped unread; the connection then
  /// ended with the socket, and nothing said why.)
  void _handleMessageDisconnect(Uint8List payload) {
    final message = SSH_Message_Disconnect.decode(payload);
    printTrace?.call('<- $socket: $message');
    closeWithError(SSHDisconnectError(
      message.reasonCode,
      message.description,
      authentic: _remoteIsItself,
    ));
  }

  /// What the server says of itself (SSH_MSG_EXT_INFO, RFC 8308): kept for
  /// whoever signs in, and handed to nobody.
  ///
  /// It is taken under the server's keys, and from nobody before those. It
  /// comes right after the server's first NEWKEYS, which is while the host
  /// key may still be looked at: it is kept, and nothing is done with it
  /// until that key is approved, since nothing signs in before. Where a
  /// server says it again, what it says last holds (RFC 8308, 2.4).
  ///
  /// (The client did not ask, so no server said it, and an RSA key signed
  /// in one way whatever a server takes. Had a server said it, the
  /// connection would have ended where it came before the host key was
  /// approved, as a message with no business there, and it would have been
  /// handed up and dropped where it came after.)
  void _handleMessageExtInfo(Uint8List payload) {
    final message = SSH_Message_ExtInfo.decode(payload);
    printTrace?.call('<- $socket: $message');
    final takes = message.serverSignatureAlgorithms;
    _serverExtensions = List.unmodifiable(message.names);
    _serverSignatureAlgorithms = takes == null ? null : List.unmodifiable(takes);
    printDebug?.call(
      'SSHTransport: the server says of itself: ${_serverExtensions.join(', ')}'
      '${takes == null ? '' : '; signatures it takes: ${takes.join(', ')}'}',
    );
    onExtInfo?.call();
  }

  void _handleMessageKexInit(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexInit');
    _stopKexInitWait();

    // One proposal to an exchange, and the next exchange only once this one
    // is over on both sides (see [_kexStep]).
    if (isClient && (_kexStep != _KexStep.idle || _localNewKeysOwed)) {
      closeWithError(SSHHandshakeError(
        'The server sent a key exchange proposal while an exchange was still '
        'in progress.',
      ));
      return;
    }

    // If this message initiates a new key-exchange round from the remote
    // side, we MUST respond with our own KEXINIT (RFC 4253 §7.1).
    if (!_kexInProgress) {
      // Start a new exchange initiated by the peer.
      _kexInProgress = true;
    }

    if (!_sentKexInit) {
      // We have not sent our KEXINIT for this round yet, do it now.
      _sendKexInit();
    }

    final message = SSH_Message_KexInit.decode(payload);
    printTrace?.call('<- $socket: $message');
    _remoteKexInit = payload;

    // Terrapin (CVE-2023-48795): check if server supports strict KEX.
    if (_isInitialKex && isClient) {
      _serverSupportsStrictKex = message.kexAlgorithms
          .contains('kex-strict-s-v00@openssh.com');
      if (_serverSupportsStrictKex) {
        printDebug?.call('SSHTransport: server supports strict KEX (Terrapin mitigation)');
        // Under the strict exchange the proposal is the first packet a
        // server sends. Whether the exchange is strict is known only now,
        // so what came before the proposal was taken as it came (a message
        // that may come at any time: IGNORE, DEBUG, UNIMPLEMENTED), and is
        // counted here: the packets of the other side are numbered from
        // nought, and this one is not the first.
        if (_remotePacketSN.value != 0) {
          closeWithError(_strictOrderBroken(
            'the server\'s key exchange proposal was not the first packet it sent',
          ));
          return;
        }
      }
    }

    _kexType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.kex,
      remoteAlgorithms: message.kexAlgorithms,
      isServer: isServer,
    );
    _hostkeyType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.hostkey,
      remoteAlgorithms: message.serverHostKeyAlgorithms,
      isServer: isServer,
    );
    _clientCipherType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.cipher,
      remoteAlgorithms: message.encryptionClientToServer,
      isServer: isServer,
    );
    _serverCipherType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.cipher,
      remoteAlgorithms: message.encryptionServerToClient,
      isServer: isServer,
    );
    _clientMacType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.mac,
      remoteAlgorithms: message.macClientToServer,
      isServer: isServer,
    );
    _serverMacType = SSHKexUtils.selectAlgorithm(
      localAlgorithms: algorithms.mac,
      remoteAlgorithms: message.macServerToClient,
      isServer: isServer,
    );

    if (_kexType == null) {
      throw _nothingInCommon('key exchange', algorithms.kex, message.kexAlgorithms);
    }
    if (_hostkeyType == null) {
      throw _nothingInCommon('host key', algorithms.hostkey, message.serverHostKeyAlgorithms);
    }
    if (_clientCipherType == null) {
      throw _nothingInCommon('client cipher', algorithms.cipher, message.encryptionClientToServer);
    }
    if (_serverCipherType == null) {
      throw _nothingInCommon('server cipher', algorithms.cipher, message.encryptionServerToClient);
    }
    if (_clientMacType == null && !_clientCipherType!.isAead) {
      throw _nothingInCommon('client MAC', algorithms.mac, message.macClientToServer);
    }
    if (_serverMacType == null && !_serverCipherType!.isAead) {
      throw _nothingInCommon('server MAC', algorithms.mac, message.macServerToClient);
    }

    printDebug?.call('SSHTransport._kexType: $_kexType');
    printDebug?.call('SSHTransport._hostkeyType: $_hostkeyType');
    printDebug?.call('SSHTransport._clientCipherType: $_clientCipherType');
    printDebug?.call('SSHTransport._serverCipherType: $_serverCipherType');
    printDebug?.call('SSHTransport._clientMacType: $_clientMacType');
    printDebug?.call('SSHTransport._serverMacType: $_serverMacType');

    _kexStartTime = DateTime.now();
    onKexNegotiated?.call(
      kex: _kexType!.name,
      cipher: _clientCipherType!.name,
      // A cipher that checks its packets by itself has no MAC beside it,
      // whatever the two proposals named for one (and they always name one).
      mac: _clientCipherType!.isAead ? '' : _clientMacType!.name,
      hostKey: _hostkeyType!.name,
    );

    if (isClient) {
      _kexStep = _kexType!.isGroupExchange
          ? _KexStep.awaitingGroup
          : _KexStep.awaitingAnswer;
    }

    switch (_kexType) {
      case SSHKexType.mlkem768x25519:
        _kex = SSHKexMlKem768X25519();
        break;
      case SSHKexType.sntrup761x25519:
      case SSHKexType.sntrup761x25519OpenSSH:
        _kex = SSHKexSntrup761X25519();
        break;
      case SSHKexType.x25519:
      case SSHKexType.x25519Iana:
        _kex = SSHKexX25519();
        break;
      case SSHKexType.nistp256:
        _kex = SSHKexNist.p256();
        break;
      case SSHKexType.nistp384:
        _kex = SSHKexNist.p384();
        break;
      case SSHKexType.nistp521:
        _kex = SSHKexNist.p521();
        break;
      case SSHKexType.dh14Sha1:
      case SSHKexType.dh14Sha256:
        _kex = SSHKexDH.group14();
        break;
      case SSHKexType.dh1Sha1:
        _kex = SSHKexDH.group1();
        break;
      case SSHKexType.dhGexSha1:
      case SSHKexType.dhGexSha256:
        if (isClient) _sendKexDHGexRequest();
        return;
      default:
        throw UnimplementedError('$_kexType');
    }

    if (isClient) {
      _sendKexDHInit();
    }
  }

  /// When client receives [SSH_Message_KexECDH_Reply], it should verify the
  /// server's signature with the server's public key. Then send NEW_KEYS
  /// message back to the server.
  void _handleMessageKexReply(Uint8List payload, int messageId) {
    printDebug?.call('SSHTransport._handleMessageKexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_REPLY');

    final kexType = _kexType;

    if (kexType == null) {
      throw SSHStateError('kexType has not been negotiated');
    }

    // The answer is taken once, and only when it is the server's turn to
    // give it (see [_kexStep]). In a group exchange the group comes first,
    // under the number an answer has elsewhere.
    if (_kexStep == _KexStep.awaitingGroup &&
        messageId == SSH_Message_KexDH_GexGroup.messageId) {
      _kexStep = _KexStep.awaitingAnswer;
      return _handleMessageKexGexReply(payload);
    }
    final answerId = kexType.isGroupExchange
        ? SSH_Message_KexDH_GexReply.messageId
        : SSH_Message_KexDH_Reply.messageId;
    if (_kexStep != _KexStep.awaitingAnswer || messageId != answerId) {
      closeWithError(SSHHandshakeError(
        'The server sent an answer to the key exchange (message $messageId) '
        'that was not asked for: an exchange has one answer.',
      ));
      return;
    }
    _kexStep = _KexStep.awaitingNewKeys;
    _localNewKeysOwed = true;

    final kex = _kex;
    if (kex == null) {
      throw SSHStateError('No key exchange algorithm');
    }

    late Uint8List hostkey;
    late Uint8List hostSignature;
    late Uint8List serverKexKey;
    late Uint8List clientKexKey;
    late Uint8List sharedSecret;

    if (kex is SSHKexDH) {
      final message = kexType.isGroupExchange
          ? SSH_Message_KexDH_GexReply.decode(payload)
          : SSH_Message_KexDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = encodeBigInt(message.f);
      clientKexKey = encodeBigInt(kex.e);
      sharedSecret =
          SSHKexUtils.encodeSharedSecretMpint(kex.computeSecret(message.f));
    } else if (kex is SSHKexECDH) {
      final message = SSH_Message_KexECDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = message.ecdhPublicKey;
      clientKexKey = kex.publicKey;
      sharedSecret = SSHKexUtils.encodeSharedSecretMpint(
          kex.computeSecret(message.ecdhPublicKey));
    } else if (kex is SSHKexHybrid) {
      // Hybrid post-quantum: the reply blob is KEM ciphertext || X25519
      // key, the secret is a hash and travels as `string K`.
      final message = SSH_Message_KexECDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = message.ecdhPublicKey;
      clientKexKey = kex.publicKey;
      sharedSecret = SSHKexUtils.encodeSharedSecretString(
          kex.computeSharedSecret(message.ecdhPublicKey));
    } else {
      throw UnimplementedError('$kex');
    }

    final exchangeHash = SSHKexUtils.computeExchangeHash(
      digest: _kexType!.createDigest(),
      groupExchange: kexType.isGroupExchange ? kex as SSHKexDH : null,
      groupExchangeShortest: _gexShortest,
      clientVersion: _localVersion,
      serverVersion: _remoteVersion!,
      clientKexInit: _localKexInit,
      serverKexInit: _remoteKexInit,
      hostKey: hostkey,
      clientPublicKey: clientKexKey,
      serverPublicKey: serverKexKey,
      sharedSecret: sharedSecret,
    );

    if (!disableHostkeyVerification) {
      final verified = _verifyHostkey(
        keyBytes: hostkey,
        signatureBytes: hostSignature,
        exchangeHash: exchangeHash,
      );
      if (!verified) {
        throw SSHHostkeyError(
          'Signature verification failed',
          fault: SSHHostkeyFault.notSigned,
          duringRekey: _hostkeyVerified,
        );
      }
    }

    // Re-key host-key pinning: after the initial exchange the server's host
    // key is fixed for the lifetime of the connection. A byte-for-byte
    // mismatch on any later KEX means the peer we're talking to changed -
    // a MITM takeover - so tear down rather than silently accept it. The
    // signature check above proves the key owns the exchange, but NOT that
    // it is the SAME key the user already trusted; this closes that gap.
    final pinnedHostKey = _verifiedHostKey;
    if (pinnedHostKey != null && !_hostKeyBytesEqual(pinnedHostKey, hostkey)) {
      closeWithError(SSHHostkeyError(
        'Host key changed during re-key',
        fault: SSHHostkeyFault.changed,
        duringRekey: true,
      ));
      return;
    }

    _exchangeHash = exchangeHash;
    _sessionId ??= exchangeHash;
    _sharedSecret = sharedSecret;

    final fingerprint = MD5Digest().process(hostkey);

    // Format fingerprint as colon-separated hex for event reporting.
    final fingerprintHex = fingerprint
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join(':');
    onHostKeyReceived?.call(_hostkeyType!.name, fingerprintHex);

    if (_hostkeyVerified) {
      _finishExchange(exchangeHash, sharedSecret);
      return;
    }

    // Pass the RAW host key blob (not the MD5 digest) so the app computes
    // the standard OpenSSH SHA256 fingerprint and stores the real key.
    final userVerified = onVerifyHostKey != null
        ? onVerifyHostKey!(_hostkeyType!.name, hostkey)
        : true;

    Future.value(userVerified).then(
      (verified) {
        // The connection may have ended while the person was asked: there is
        // nothing left to finish, and nothing to send into.
        if (isClosed) return;
        if (!verified) {
          closeWithError(SSHHostkeyError('Hostkey verification failed'));
        } else if (_exchangeIs(exchangeHash, sharedSecret)) {
          _hostkeyVerified = true;
          // Pin the accepted key so every later re-key is checked against it.
          _verifiedHostKey = Uint8List.fromList(hostkey);
          // What is thrown from here on ends the connection. This runs by
          // itself, long after the server's answer was read where a person
          // was asked about the key, and nobody else is there to catch it:
          // our NEWKEYS failing to go out on a socket that has gone, or
          // whoever holds the connection failing at its first request. (It
          // was thrown into nowhere, with the connection left open and
          // whoever waited for the sign-in waiting until their own patience
          // ran out.)
          try {
            _finishExchange(exchangeHash, sharedSecret);
            onReady?.call();
          } catch (error, stackTrace) {
            closeWithError(
              error is SSHError
                  ? error
                  : SSHStateError('The connection could not be made ready once its host key was approved: $error'),
              stackTrace,
            );
          }
        } else {
          closeWithError(SSHStateError(
            'The key exchange changed while its host key was being verified.',
          ));
        }
      },
      onError: (Object error, StackTrace stackTrace) {
        if (isClosed) return;
        // Whatever the lookup failed with, the key was not verified. An
        // error of another kind than ours went to [closeWithError] as it
        // was until this was held, which is a type error there: thrown into
        // nowhere, with the connection left open and waiting for ever.
        closeWithError(
          error is SSHError
              ? error
              : SSHHostkeyError('The host key could not be verified: $error'),
          stackTrace,
        );
      },
    );
  }

  /// Whether the exchange waiting for our NEWKEYS is still the one that
  /// produced [exchangeHash] and [sharedSecret].
  bool _exchangeIs(Uint8List exchangeHash, Uint8List sharedSecret) =>
      _localNewKeysOwed &&
      identical(_exchangeHash, exchangeHash) &&
      identical(_sharedSecret, sharedSecret);

  /// Sends our NEWKEYS and puts our keys of the exchange in force: those
  /// that follow from [exchangeHash] and [sharedSecret], the answer whose
  /// host key was approved. With anything else in their place the connection
  /// ends (it cannot happen while an exchange takes one answer; this is the
  /// second lock on that door).
  void _finishExchange(Uint8List exchangeHash, Uint8List sharedSecret) {
    if (!_exchangeIs(exchangeHash, sharedSecret)) {
      closeWithError(SSHStateError(
        'The key exchange changed while its host key was being verified.',
      ));
      return;
    }
    _localNewKeysOwed = false;
    _sendNewKeys();
    _applyLocalKeys();
  }

  void _handleMessageKexGexReply(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexGexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_GEX_REPLY');

    final message = SSH_Message_KexDH_GexGroup.decode(payload);
    printTrace?.call('<- $socket: $message');

    // The group the server chose is one that can be used (RFC 4419), or
    // the connection ends here: of the length that was asked for, with a
    // generator that is one. A server could name a group that is easily
    // broken while its client believes it has a strong one. (What is
    // thrown is an SSHError, so the connection ends in order.)
    SSHKexDH.requireGroupOfAnExchange(message.p, message.g, shortest: _gexShortest);
    // How long it is: what the session's secrecy rests on, and nothing of
    // the group itself.
    printDebug?.call('SSHTransport: the server named a group of ${message.p.bitLength} bits for the key exchange');

    _kex = SSHKexDH(p: message.p, g: message.g, secretBits: 256);
    _sendKexDHGexInit();
  }

  void _handleMessageNewKeys(Uint8List message) {
    printDebug?.call('SSHTransport._handleMessageNewKeys');
    printTrace?.call('<- $socket: SSH_Message_NewKeys');

    // NEWKEYS ends an exchange whose answer was taken (see [_kexStep]):
    // without one there are no new keys to take, and a second NEWKEYS has
    // nothing to follow.
    if (isClient) {
      if (_kexStep != _KexStep.awaitingNewKeys) {
        closeWithError(SSHHandshakeError(
          'The server sent NEWKEYS without an answer to a key exchange.',
        ));
        return;
      }
      _kexStep = _KexStep.idle;
    }

    _applyRemoteKeys();

    // Terrapin (CVE-2023-48795) strict KEX mitigation: reset the RECEIVE
    // sequence number after receiving the server's NEWKEYS. Per the strict KEX
    // spec (OpenSSH PROTOCOL 1.9(b)) this reset happens on EVERY NEWKEYS "for
    // the duration of the connection (i.e. not just the first)", confirmed in
    // OpenSSH packet.c (the reset is gated only on NEWKEYS && kex_strict, never
    // on the initial KEX). So it must NOT be gated on _isInitialKex: a
    // mid-session rekey (OpenSSH RekeyLimit, ~1GB or 1h) re-zeroes both peers'
    // counters, and the old _isInitialKex gate desynced our read counter and
    // dropped the connection on the first rekey. The SEND side already resets
    // unconditionally in _sendNewKeys(). Nonce-safe: keys rotate each epoch, so
    // (key, seq) never repeats even though seq restarts at 0.
    //
    // We also set _skipNextRemoteSNIncrease because _processPackets()
    // increments _remotePacketSN AFTER this handler returns. Without
    // skipping that increment, the first encrypted packet would be
    // decrypted with nonce=1 instead of nonce=0.
    if (_serverSupportsStrictKex) {
      printDebug?.call('SSHTransport: strict KEX - resetting RECEIVE sequence number');
      _remotePacketSN.reset();
      _skipNextRemoteSNIncrease = true;
    }
    _isInitialKex = false;

    // Key exchange round finished.
    _kexInProgress = false;
    _sentKexInit = false;
    _kex = null;

    // Report kex completion with duration.
    final startTime = _kexStartTime;
    if (startTime != null) {
      final duration = DateTime.now().difference(startTime);
      onKexCompleted?.call(duration);
      _kexStartTime = null;
    }

    // Flush any pending packets
    final pending = List<Uint8List>.from(_rekeyPendingPackets);
    _rekeyPendingPackets.clear();
    for (final packet in pending) {
      sendPacket(packet);
    }
  }

  /// Initiates a client-side re-key operation. This can be called
  /// by client code to refresh session keys when needed.
  void rekey() {
    printDebug?.call('SSHTransport.rekey');
    // Not while an exchange is in progress, and not before our NEWKEYS for
    // the last one is out: with the server's NEWKEYS in and the host key
    // still being looked at, a proposal from here would go out in the clear,
    // ahead of the NEWKEYS it has to follow.
    if (_kexInProgress || _localNewKeysOwed) {
      printDebug
          ?.call('Key exchange already in progress, ignoring rekey request');
      return;
    }
    _sendKexInit();
  }

  /// Determines if a packet should bypass the rekey buffer.
  ///
  /// During key exchange, most packets should be buffered until the exchange
  /// is complete. However, key exchange packets themselves and transport layer
  /// control messages (like disconnect) need to be sent immediately.
  ///
  /// Per RFC 4253, the following message types bypass the buffer:
  ///
  ///  /// Critical transport messages (1-4):
  /// - 1: [SSH_Message_Disconnect]
  /// - 2: [SSH_Message_Ignore]
  /// - 3: [SSH_Message_Unimplemented]
  /// - 4: [SSH_Message_Debug]
  ///
  /// Key exchange messages (20-49):
  /// - 20: [SSH_Message_KexInit]
  /// - 21: [SSH_Message_NewKeys]
  /// - 30: [SSH_Message_KexDH_Init]/[SSH_Message_KexECDH_Init]
  /// - 31: [SSH_Message_KexDH_Reply]/[SSH_Message_KexECDH_Reply]/[SSH_Message_KexDH_GexGroup]
  /// - 32: [SSH_Message_KexDH_GexInit]
  /// - 33: [SSH_Message_KexDH_GexReply]
  /// - 34: [SSH_Message_KexDH_GexRequest]
  ///
  ///
  bool _shouldBypassRekeyBuffer(Uint8List data) {
    if (data.isEmpty) return false;

    final messageId = data[0];
    return (messageId >= 20 && messageId <= 49) || messageId <= 4;
  }
}

/// What the server may send next for the key exchange in progress, see
/// [SSHTransport._kexStep].
enum _KexStep {
  /// No exchange in progress: the server may open one with its proposal.
  idle,

  /// A group exchange was agreed on: the group is awaited.
  awaitingGroup,

  /// The answer to the exchange is awaited.
  awaitingAnswer,

  /// The answer was taken: the server's NEWKEYS is awaited.
  awaitingNewKeys,
}
