import 'dart:async';
import 'dart:convert';
import 'dart:math' show Random, max;
import 'dart:typed_data';

import 'package:zest_ssh_core/src/algorithm/ssh_cipher_chacha20_poly1305.dart';
import 'package:zest_ssh_core/src/algorithm/ssh_send_crypto.dart';
import 'package:zest_ssh_core/src/send_crypto_worker.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_ecdsa.dart';
import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/kex/kex_dh.dart';
import 'package:zest_ssh_core/src/kex/kex_nist.dart';
import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
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

/// Called when key exchange algorithms have been negotiated.
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
    this.disableHostkeyVerification = false,
    this.offloadSendCrypto = false,
  }) {
    _initSocket();
    _startHandshake();
  }

  /// When true, ChaCha20-Poly1305 and AES-GCM send-side packet encryption runs
  /// on a background worker isolate instead of the main isolate, so bulk SFTP
  /// uploads no longer block the UI. Purely an optimization: the inline path is
  /// always correct, and a spawn failure silently falls back to it. Default
  /// false so existing behavior and the library's own tests are unchanged.
  final bool offloadSendCrypto;

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

  SSHCipherType? _clientCipherType;

  SSHCipherType? _serverCipherType;

  SSHMacType? _clientMacType;

  SSHMacType? _serverMacType;

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

  /// Shared secret derived from the key exchange process. Kept to derive the
  /// cipher IV, cipher key and MAC key.
  BigInt? _sharedSecret;

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

  /// ChaCha20-Poly1305 cipher for encrypting outbound packets.
  SSHCipherChaCha20Poly1305? _localChaCha;

  /// ChaCha20-Poly1305 cipher for decrypting inbound packets.
  SSHCipherChaCha20Poly1305? _remoteChaCha;

  final _localPacketSN = SSHPacketSN.fromZero();

  final _remotePacketSN = SSHPacketSN.fromZero();

  /// Whether this is the initial (first) key exchange. Used for the Terrapin
  /// attack (CVE-2023-48795) strict KEX mitigation: sequence numbers are reset
  /// to 0 after the first NEWKEYS when both sides advertise strict KEX.
  bool _isInitialKex = true;

  /// Whether the server advertised `kex-strict-s-v00@openssh.com` in its
  /// KEXINIT, indicating support for the Terrapin strict KEX extension.
  bool _serverSupportsStrictKex = false;

  /// Timestamp when the current key exchange round started.
  DateTime? _kexStartTime;

  /// Whether a key exchange is currently in progress (initial or re-key).
  bool _kexInProgress = false;

  /// Whether we have already sent our SSH_MSG_KEXINIT for the ongoing key
  /// exchange round. This is reset when the exchange finishes.
  bool _sentKexInit = false;

  /// Tracks the last sequence number used for an inbound ChaCha20-Poly1305
  /// packet. Used to enforce strict monotonicity (Finding 1.2).
  int? _lastRemoteChaChaSeq;

  /// Cryptographically secure RNG used for padding bytes.
  final Random _secureRandom = Random.secure();

  /// Packets queued during key exchange that will be sent after NEW_KEYS
  final List<Uint8List> _rekeyPendingPackets = [];

  // ── Send-crypto offload (opt-in via offloadSendCrypto) ──────────────
  // Worker isolate that encrypts ChaCha/GCM packets off the main isolate. Null
  // until the first offloadable key install; stays null forever if a spawn
  // fails (inline fallback). The sequence number stays owned here, on the main
  // isolate, and is passed per packet, so a nonce can never desync.
  SendCryptoWorker? _sendWorker;
  bool _spawningSendWorker = false;
  int _nextSendJobId = 0; // monotonic id, assigned in submit order
  int _nextExpectedWriteJobId = 0; // ordering guard for the deferred write
  int _sendEpoch = 0; // bumped each offloadable key install
  ({int epoch, String mode, Uint8List key, Uint8List iv})? _pendingSendInstall;

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
    // Encryption is "established" once ANY local cipher is keyed. AEAD
    // (AES-GCM) keys `_localCipherKey`, ChaCha20-Poly1305 keys `_localChaCha`,
    // and block/stream ciphers key `_encryptCipher`. Checking only
    // `_encryptCipher` (the previous behaviour) wrongly treated a fully
    // encrypted GCM/ChaCha connection - the defaults - as cleartext and
    // refused to send any application data over it.
    final localEncryptionEstablished = _encryptCipher != null ||
        _localCipherKey != null ||
        _localChaCha != null;
    if (!localEncryptionEstablished && data.isNotEmpty) {
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

    // Check if encryption is enabled and if we have MAC types initialized
    final clientMacType = _clientMacType;
    final serverMacType = _serverMacType;
    final macType = isClient ? clientMacType : serverMacType;
    final localCipherType = isClient ? _clientCipherType : _serverCipherType;

    // ChaCha20-Poly1305 has its own packet framing with encrypted length
    if (_localChaCha != null && localCipherType != null && localCipherType.isChaCha) {
      if (_sendWorker != null) {
        _enqueueSendOffload(data, localCipherType, gcm: false);
      } else {
        _sendChaChaPacket(data, localCipherType);
      }
      _localPacketSN.increase();
      return;
    }

    if (localCipherType != null &&
        localCipherType.isAead &&
        _localCipherKey != null &&
        _localIV != null) {
      if (_sendWorker != null) {
        _enqueueSendOffload(data, localCipherType, gcm: true);
      } else {
        _sendAeadPacket(data, localCipherType);
      }
      _localPacketSN.increase();
      return;
    }

    final isEtm = _encryptCipher != null && macType != null && macType.isEtm;

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

      // Add random padding using cryptographically secure RNG.
      for (var i = 0; i < adjustedPaddingLength; i++) {
        payloadToEncrypt[1 + data.length + i] = _secureRandom.nextInt(256);
      }

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

      socket.sink.add(buffer.takeBytes());
    } else {
      // For standard encryption or no encryption:
      // Use the original packet packing logic
      final packetAlign = _encryptCipher == null
          ? SSHPacket.minAlign
          : max(SSHPacket.minAlign, _encryptCipher!.blockSize);

      final packet = SSHPacket.pack(data, align: packetAlign);

      if (_encryptCipher == null) {
        socket.sink.add(packet);
      } else {
        final mac = _localMac!;
        final encryptedPacket = _encryptCipher!.processAll(packet);

        final buffer = BytesBuilder(copy: false);
        buffer.add(encryptedPacket);

        // Calculate MAC on the unencrypted packet
        mac.updateAll(_localPacketSN.value.toUint32());
        mac.updateAll(packet);
        buffer.add(mac.finish());

        socket.sink.add(buffer.takeBytes());
      }
    }

    _localPacketSN.increase();
  }

  void _sendAeadPacket(Uint8List data, SSHCipherType cipherType) {
    final paddingLength =
        _alignedPaddingLength(data.length, cipherType.blockSize);
    final packetLength = 1 + data.length + paddingLength;

    final aad = Uint8List(4)..buffer.asByteData().setUint32(0, packetLength);

    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data);

    for (var i = 0; i < paddingLength; i++) {
      plaintext[1 + data.length + i] = _secureRandom.nextInt(256);
    }

    // Same pure function the crypto worker runs (aad + GCM ciphertext + tag).
    socket.sink.add(encryptGcmPacket(
      _localCipherKey!,
      _localIV!,
      _localPacketSN.value,
      aad,
      plaintext,
    ));
  }

  void _sendChaChaPacket(Uint8List data, SSHCipherType cipherType) {
    final paddingLength = _alignedPaddingLength(data.length, cipherType.blockSize);
    final packetLength = 1 + data.length + paddingLength;

    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data);

    for (var i = 0; i < paddingLength; i++) {
      plaintext[1 + data.length + i] = _secureRandom.nextInt(256);
    }

    // Same pure function the crypto worker runs; _localChaCha was built from
    // _localCipherKey (1121), so this is byte-identical.
    socket.sink.add(encryptChaChaPacket(
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

  // ── Send-crypto offload internals ──────────────────────────────────

  /// Builds the plaintext (padLen || data || random padding) once, on the main
  /// isolate, so the RNG stays on one isolate and the worker is a pure function
  /// of (key, seq, plaintext).
  (Uint8List, int) _buildSendPlaintext(Uint8List data, int blockSize) {
    final paddingLength = _alignedPaddingLength(data.length, blockSize);
    final packetLength = 1 + data.length + paddingLength;
    final plaintext = Uint8List(packetLength)
      ..[0] = paddingLength
      ..setRange(1, 1 + data.length, data);
    for (var i = 0; i < paddingLength; i++) {
      plaintext[1 + data.length + i] = _secureRandom.nextInt(256);
    }
    return (plaintext, packetLength);
  }

  void _enqueueSendOffload(Uint8List data, SSHCipherType cipherType,
      {required bool gcm}) {
    final (plaintext, packetLength) =
        _buildSendPlaintext(data, cipherType.blockSize);
    final aad = gcm
        ? (Uint8List(4)..buffer.asByteData().setUint32(0, packetLength))
        : null;
    final jobId = _nextSendJobId++;
    // In-flight jobs are bounded in practice by the SSH channel remote window
    // (the upload loop pauses at _remoteWindow <= 0) plus the SFTP 1MB write
    // window, so the worker queue cannot grow without limit under normal flow
    // control. Log if it ever climbs unusually high (a very large/tuned window
    // or many concurrent channels) so memory pressure is observable; the queue
    // still drains strictly FIFO.
    final inFlight = jobId - _nextExpectedWriteJobId;
    if (inFlight == 512) {
      printDebug?.call('SSHTransport: send-crypto in-flight high ($inFlight)');
    }
    _sendWorker!.encrypt(
      jobId: jobId,
      epoch: _sendEpoch,
      seq: _localPacketSN.value,
      packetLength: packetLength,
      plaintext: plaintext,
      aad: aad,
    );
  }

  /// Number of send-crypto jobs submitted to the worker but not yet written to
  /// the socket. Bounded by SSH channel flow control; exposed for observability.
  int get sendInFlight => _nextSendJobId - _nextExpectedWriteJobId;

  /// The deferred socket write. The ONLY difference from the inline path is that
  /// the `socket.sink.add` moves here, into the ordered reply callback. Replies
  /// arrive in submit order (single FIFO port + single-threaded worker), so
  /// writes stay in sequence order; the guard converts any violation into a
  /// clean disconnect rather than silent channel corruption.
  void _onSendWorkerDone(int jobId, Uint8List ciphertext) {
    if (jobId != _nextExpectedWriteJobId) {
      closeWithError(SSHStateError(
          'send crypto out of order: got job $jobId, expected '
          '$_nextExpectedWriteJobId'));
      return;
    }
    _nextExpectedWriteJobId++;
    if (isClosed) return; // socket destroyed mid-flight: drop
    socket.sink.add(ciphertext);
  }

  void _onSendWorkerError(String message) {
    // Never re-encrypt inline: a retried packet under an already-consumed seq
    // is nonce reuse. Any worker fault tears the connection down cleanly.
    closeWithError(SSHStateError('send crypto worker: $message'));
  }

  /// Installs an offloadable (ChaCha/GCM) key generation on the worker, spawning
  /// it lazily on first use. Sent in-band on the same FIFO port as encrypt jobs,
  /// so the key swap lands strictly after the NEWKEYS packet of the outgoing
  /// epoch (which was enqueued just before this call).
  void _installSendCipherOffload(String mode, Uint8List key, Uint8List iv) {
    _sendEpoch++;
    final install = (
      epoch: _sendEpoch,
      mode: mode,
      key: Uint8List.fromList(key), // COPY, never a view main zeroes on rekey
      iv: Uint8List.fromList(iv),
    );
    final worker = _sendWorker;
    if (worker != null) {
      worker.installKey(
          epoch: install.epoch,
          mode: install.mode,
          key: install.key,
          iv: install.iv);
      // send() deep-copied synchronously, so scrub our copy now: without this
      // the send key would linger un-zeroed on the main heap, defeating the
      // rekey scrub of _localCipherKey.
      _zeroSendInstall(install);
      return;
    }
    // Not spawned yet: hold the latest key to install on ready, scrubbing any
    // pending copy this one supersedes.
    if (_pendingSendInstall != null) _zeroSendInstall(_pendingSendInstall!);
    _pendingSendInstall = install;
    if (_spawningSendWorker) return; // spawn already in flight; installs latest
    _spawningSendWorker = true;
    SendCryptoWorker.spawn(
      onDone: _onSendWorkerDone,
      onError: _onSendWorkerError,
    ).then((w) {
      _spawningSendWorker = false;
      final p = _pendingSendInstall;
      _pendingSendInstall = null;
      if (isClosed) {
        if (p != null) _zeroSendInstall(p);
        w.dispose();
        return;
      }
      _sendWorker = w;
      if (p != null) {
        w.installKey(epoch: p.epoch, mode: p.mode, key: p.key, iv: p.iv);
        _zeroSendInstall(p);
      }
    }).catchError((Object e) {
      // Spawn failed: stay on the inline path (always correct).
      _spawningSendWorker = false;
      final p = _pendingSendInstall;
      _pendingSendInstall = null;
      if (p != null) _zeroSendInstall(p);
      printDebug?.call(
          'SSHTransport: send crypto worker spawn failed, inline path: $e');
    });
  }

  void _zeroSendInstall(
      ({int epoch, String mode, Uint8List key, Uint8List iv}) install) {
    zeroBytes(install.key);
    zeroBytes(install.iv);
  }

  Uint8List _processAead({
    required Uint8List key,
    required Uint8List iv,
    required int sequence,
    required Uint8List aad,
    required Uint8List input,
    required bool forEncryption,
  }) {
    final cipher = GCMBlockCipher(AESEngine());
    final nonce = _nonceForSequence(iv, sequence);
    cipher.init(
      forEncryption,
      AEADParameters(KeyParameter(key), 128, nonce, aad),
    );
    return cipher.process(input);
  }

  // Delegates to the shared pure helper so send (worker) and receive share one
  // nonce derivation and cannot drift.
  Uint8List _nonceForSequence(Uint8List iv, int sequence) =>
      sshAeadNonceForSequence(iv, sequence);

  void close() {
    printDebug?.call('SSHTransport.close');
    if (isClosed) return;
    _sendWorker?.dispose();
    _sendWorker = null;
    if (_pendingSendInstall != null) {
      _zeroSendInstall(_pendingSendInstall!);
      _pendingSendInstall = null;
    }
    _socketSubscription?.cancel();
    _socketSubscription = null;
    _doneCompleter.complete();
    socket.destroy();
  }

  void closeWithError(SSHError error, [StackTrace? stackTrace]) {
    printDebug?.call('SSHTransport.closeWithError $error');
    if (isClosed) return;
    _sendWorker?.dispose();
    _sendWorker = null;
    if (_pendingSendInstall != null) {
      _zeroSendInstall(_pendingSendInstall!);
      _pendingSendInstall = null;
    }
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

  void _onSocketData(Uint8List data) {
    _buffer.add(data);
    try {
      _processData();
    } on SSHError catch (e, stackTrace) {
      printDebug?.call('SSHTransport: SSH error during packet processing: $e');
      closeWithError(e, stackTrace);
    } catch (e, stackTrace) {
      // Any NON-SSHError thrown while parsing an incoming packet - e.g. a
      // RangeError or FormatException from decoding a truncated/crafted field
      // (readString/readMpint on an attacker-controlled length) during the
      // still-unauthenticated KEX - must tear the connection down cleanly.
      // Rethrowing escapes to the zone as an uncaught async error: the
      // subscription is never cancelled and the connect future never
      // completes, hanging the client forever (a pre-auth DoS). Wrap it as an
      // SSHError so `closeWithError` rejects the pending handshake instead.
      printDebug?.call('SSHTransport: Unexpected error during packet processing: $e\n$stackTrace');
      closeWithError(SSHPacketError('Malformed packet: $e'), stackTrace);
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

  void _processVersionExchange() {
    printDebug?.call('SSHTransport._processVersionExchange');

    if (_buffer.length > 10240) {
      throw SSHHandshakeError('Version exchange too long');
    }

    final bufferString = latin1.decode(_buffer.data);

    // SSH version exchange is terminated by \r\n.
    var index = bufferString.indexOf('\r\n');
    if (index == -1) {
      // In the (rare) case SSH-2 version string is terminated by \n only (observed on Synology DS120j 2021)
      index = bufferString.indexOf('\n');
      if (index == -1) {
        throw SSHHandshakeError('Version exchange not terminated');
      }
      _buffer.consume(index + 1);
    } else {
      _buffer.consume(index + 2);
    }

    final versionString = bufferString.substring(0, index);
    // RFC compatibility: SSH-1.99 banners indicate SSH-2 support with SSH-1 fallback.
    if (!(versionString.startsWith('SSH-2.0-') ||
        versionString.startsWith('SSH-1.99-'))) {
      socket.sink.add(latin1.encode('Protocol mismatch\r\n'));
      throw SSHHandshakeError('Invalid version: $versionString');
    }

    printTrace?.call('<- $socket: $versionString');
    printDebug?.call('SSHTransport._remoteVersion = "$versionString"');
    _remoteVersion = versionString;

    onVersionExchange?.call(_localVersion, versionString);

    if (isServer) {
      _sendKexInit();
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

    try {
      printDebug?.call('SSHTransport._processPackets');
      var processedSinceYield = 0;
      while (_buffer.isNotEmpty && !isClosed) {
        final payload = _consumePacket();
        if (payload == null) {
          break;
        }

        _handleMessage(payload);

        // After a strict-KEX sequence number reset (in _handleMessageNewKeys),
        // skip one increment so the next encrypted packet uses nonce 0.
        if (_skipNextRemoteSNIncrease) {
          _skipNextRemoteSNIncrease = false;
        } else {
          _remotePacketSN.increase();
        }

        // Cooperatively yield after every [_packetsPerYield] packets so a
        // sustained burst can't starve the platform event loop. The loop
        // condition re-reads [_buffer] after the await, so data that arrived
        // during the yield is drained by this same loop (the reentrant call
        // that appended it was a no-op).
        if (++processedSinceYield >= _packetsPerYield) {
          processedSinceYield = 0;
          await Future<void>.delayed(Duration.zero);
        }
      }
    } on SSHError catch (e, stackTrace) {
      printDebug?.call('SSHTransport: SSH error during packet processing: $e');
      closeWithError(e, stackTrace);
    } catch (e, stackTrace) {
      // Mirror [_onSocketData]: any non-SSHError raised while parsing an
      // incoming packet (a RangeError/FormatException from a crafted field)
      // must tear the connection down cleanly rather than escape as an
      // uncaught async error that hangs the connect future forever.
      printDebug?.call(
          'SSHTransport: Unexpected error during packet processing: $e\n$stackTrace');
      closeWithError(SSHPacketError('Malformed packet: $e'), stackTrace);
    } finally {
      _processingPackets = false;
    }
  }

  /// Reads a single SSH packet from the buffer. Returns payload of the packet
  /// WITHOUT `packet length`, `padding length`, `padding` and `MAC`. Returns
  /// `null` if there is not enough data in the buffer to read the packet.
  Uint8List? _consumePacket() {
    return (_decryptCipher == null && _remoteCipherKey == null)
        ? _consumeClearTextPacket()
        : _consumeEncryptedPacket();
  }

  Uint8List? _consumeClearTextPacket() {
    printDebug?.call('SSHTransport._consumeClearTextPacket');

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

  Uint8List? _consumeEncryptedPacket() {
    printDebug?.call('SSHTransport._consumeEncryptedPacket');

    final remoteCipherType = isClient ? _serverCipherType : _clientCipherType;

    // ChaCha20-Poly1305 has its own framing with encrypted length
    if (remoteCipherType != null &&
        remoteCipherType.isChaCha &&
        _remoteChaCha != null) {
      return _consumeChaChaPacket();
    }

    if (remoteCipherType != null &&
        remoteCipherType.isAead &&
        _remoteCipherKey != null &&
        _remoteIV != null) {
      return _consumeAeadPacket(remoteCipherType);
    }

    final blockSize = _decryptCipher!.blockSize;
    if (_buffer.length < blockSize) {
      return null;
    }

    final macType = isClient ? _serverMacType! : _clientMacType!;
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

      if (_buffer.length + _decryptBuffer.length <
          4 + packetLength + macLength) {
        return null;
      }

      while (_decryptBuffer.length < 4 + packetLength) {
        final block = _buffer.consume(blockSize);
        _decryptBuffer.add(_decryptCipher!.process(block));
      }

      final packet = _decryptBuffer.consume(packetLength + 4);
      final paddingLength = SSHPacket.readPaddingLength(packet);
      final payloadLength = packetLength - paddingLength - 1;
      _verifyPacketPadding(payloadLength, paddingLength);

      final mac = _buffer.consume(macLength);
      _verifyPacketMac(packet, mac, isEncrypted: false);

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
    final plaintext = chacha.decrypt(
      encLenBytes,
      encPayload,
      tag,
      _remotePacketSN.value,
    );

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
        sequence: _remotePacketSN.value,
        aad: aad,
        input: encryptedInput,
        forEncryption: false,
      );
    } on InvalidCipherTextException {
      throw SSHPacketError('AEAD authentication failed');
    }

    final paddingLength = plaintext[0];
    final payloadLength = packetLength - paddingLength - 1;
    _verifyPacketPadding(payloadLength, paddingLength);
    return Uint8List.sublistView(plaintext, 1, 1 + payloadLength);
  }

  void _verifyPacketLength(int packetLength) {
    if (packetLength > SSHPacket.maxLength) {
      throw SSHPacketError('Packet too long: $packetLength');
    }
  }

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

    final remoteCipherType = isClient ? _serverCipherType : _clientCipherType;
    int expectedPacketAlign;
    if (_decryptCipher != null) {
      expectedPacketAlign = max(SSHPacket.minAlign, _decryptCipher!.blockSize);
    } else if (remoteCipherType != null && remoteCipherType.isAead) {
      expectedPacketAlign = max(SSHPacket.minAlign, remoteCipherType.blockSize);
    } else {
      expectedPacketAlign = SSHPacket.minAlign;
    }

    int minPaddingLength;

    if (remoteCipherType != null &&
        (remoteCipherType.isChaCha || remoteCipherType.isAead)) {
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

    final macType = isClient ? _serverMacType! : _clientMacType!;
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

    if (!expectedMac.equals(actualMac)) {
      throw SSHPacketError(
        'MAC mismatch, expected: $expectedMac, actual: $actualMac',
      );
    }
  }

  void _startHandshake() {
    socket.sink.add(latin1.encode('$_localVersion\r\n'));

    if (isClient) {
      _sendKexInit();
    }
  }

  void _applyLocalKeys() {
    final cipherType = isClient ? _clientCipherType : _serverCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    // Zero old key material before overwriting references (rekey safety).
    if (_localCipherKey != null) zeroBytes(_localCipherKey!);
    if (_localIV != null && _localIV!.isNotEmpty) zeroBytes(_localIV!);

    _localCipherKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientKey : SSHDeriveKeyType.serverKey,
      cipherType.keySize,
    );

    if (cipherType.isChaCha) {
      // ChaCha20-Poly1305 does not use a derived IV; the nonce is the
      // sequence number. The 64-byte key is split internally.
      _localIV = Uint8List(0);
      _localChaCha = SSHCipherChaCha20Poly1305(key: _localCipherKey!);
      _encryptCipher = null;
      _localMac = null;
      if (offloadSendCrypto) {
        _installSendCipherOffload('chacha', _localCipherKey!, _localIV!);
      }
      return;
    }

    // Not ChaCha20 -- clear any stale ChaCha instance from a prior cipher.
    _localChaCha = null;

    _localIV = _deriveKey(
      isClient ? SSHDeriveKeyType.clientIV : SSHDeriveKeyType.serverIV,
      cipherType.ivSize,
    );

    if (cipherType.isAead) {
      _encryptCipher = null;
      _localMac = null;
      if (offloadSendCrypto) {
        _installSendCipherOffload('gcm', _localCipherKey!, _localIV!);
      }
      return;
    }

    _encryptCipher = cipherType.createCipher(
      _localCipherKey!,
      _localIV!,
      forEncryption: true,
    );

    final macType = isClient ? _clientMacType : _serverMacType;
    if (macType == null) throw StateError('No MAC type selected');

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.clientMacKey : SSHDeriveKeyType.serverMacKey,
      macType.keySize,
    );

    _localMac = macType.createMac(macKey);
  }

  void _applyRemoteKeys() {
    final cipherType = isClient ? _serverCipherType : _clientCipherType;
    if (cipherType == null) throw StateError('No cipher type selected');

    // Zero old key material before overwriting references (rekey safety).
    if (_remoteCipherKey != null) zeroBytes(_remoteCipherKey!);
    if (_remoteIV != null && _remoteIV!.isNotEmpty) zeroBytes(_remoteIV!);

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

    final macType = isClient ? _serverMacType : _clientMacType;
    if (macType == null) throw StateError('No MAC type selected');

    final macKey = _deriveKey(
      isClient ? SSHDeriveKeyType.serverMacKey : SSHDeriveKeyType.clientMacKey,
      macType.keySize,
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

  bool _verifyHostkey({
    required Uint8List keyBytes,
    required Uint8List signatureBytes,
    required Uint8List exchangeHash,
  }) {
    switch (_hostkeyType) {
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
        if (signature.type != expectedSig[_hostkeyType]) {
          printDebug?.call(
            'Rejecting host key: RSA signature algorithm "${signature.type}" '
            'does not match negotiated "${_hostkeyType?.name}" (RFC 8332)',
          );
          return false;
        }
        return publicKey.verify(exchangeHash, signature);
      case SSHHostkeyType.ecdsa256:
      case SSHHostkeyType.ecdsa384:
      case SSHHostkeyType.ecdsa521:
        final publicKey = SSHEcdsaPublicKey.decode(keyBytes);
        final signature = SSHEcdsaSignature.decode(signatureBytes);
        return publicKey.verify(exchangeHash, signature);
      case null:
        throw StateError('No hostkey type negotiated');
      default:
        throw UnimplementedError('Unsupported hostkey type: $_hostkeyType');
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
    } else {
      throw StateError('No key exchange algorithm negotiated');
    }

    sendPacket(message.encode());
    printTrace?.call('-> $socket: $message');
  }

  void _sendKexDHGexRequest() {
    printDebug?.call('SSHTransport._sendKexDHGexRequest');

    final message = SSH_Message_KexDH_GexRequest(
      minN: SSHKexDH.gexMin,
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
    // DISCONNECT(1), KEXINIT(20), NEWKEYS(21) and the method-specific KEX
    // range (30-49); fail closed on anything else. This is stricter than the
    // generic pre-handshake gate below (which tolerates ids 1-4), and only
    // applies while strict KEX is active during the initial exchange.
    if (_serverSupportsStrictKex && _isInitialKex) {
      const disconnectId = 1; // SSH_Message_Disconnect.messageId
      final allowed = messageId == disconnectId ||
          messageId == SSH_Message_KexInit.messageId || // 20
          messageId == SSH_Message_NewKeys.messageId || // 21
          (messageId >= 30 && messageId <= 49); // method-specific KEX
      if (!allowed) {
        closeWithError(SSHHandshakeError(
          'Strict KEX violation: unexpected message id $messageId during the '
          'initial key exchange (possible Terrapin attack).',
        ));
        return;
      }
    }

    switch (messageId) {
      case SSH_Message_KexInit.messageId:
        return _handleMessageKexInit(message);
      case SSH_Message_KexDH_Reply.messageId:
      case SSH_Message_KexDH_GexReply.messageId:
        return _handleMessageKexReply(message);
      case SSH_Message_NewKeys.messageId:
        return _handleMessageNewKeys(message);
      default:
        // SECURITY: do not hand post-KEX messages to the connection layer
        // until the host key has been verified.
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
        // Anything legal this early is handled above or allowed through
        // here; everything else is a protocol violation and we fail closed.
        if (!_hostkeyVerified && messageId > _maxPreHandshakeMessageId) {
          closeWithError(SSHStateError(
            'Server sent message id $messageId before host-key verification '
            'completed - refusing to continue.',
          ));
          return;
        }
        onPacket?.call(message);
    }
  }

  void _handleMessageKexInit(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexInit');

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
      throw SSHHandshakeError('No matching key exchange algorithm');
    }
    if (_hostkeyType == null) {
      throw SSHHandshakeError('No matching host key algorithm');
    }
    if (_clientCipherType == null) {
      throw SSHHandshakeError('No matching client cipher algorithm');
    }
    if (_serverCipherType == null) {
      throw SSHHandshakeError('No matching server cipher algorithm');
    }
    if (_clientMacType == null && !_clientCipherType!.isAead) {
      throw SSHHandshakeError('No matching client MAC algorithm');
    }
    if (_serverMacType == null && !_serverCipherType!.isAead) {
      throw SSHHandshakeError('No matching server MAC algorithm');
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
      cipher: _clientCipherType?.name ?? 'none',
      mac: _clientMacType?.name ?? 'none',
      hostKey: _hostkeyType!.name,
    );

    switch (_kexType) {
      case SSHKexType.x25519:
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
  void _handleMessageKexReply(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_REPLY');

    final kex = _kex;
    final kexType = _kexType;

    if (kexType == null) {
      throw SSHStateError('kexType has not been negotiated');
    }

    if (kex == null) {
      if (kexType.isGroupExchange == true) {
        return _handleMessageKexGexReply(payload);
      } else {
        throw SSHStateError('No key exchange algorithm');
      }
    }

    late Uint8List hostkey;
    late Uint8List hostSignature;
    late Uint8List serverKexKey;
    late Uint8List clientKexKey;
    late BigInt sharedSecret;

    if (kex is SSHKexDH) {
      final message = kexType.isGroupExchange
          ? SSH_Message_KexDH_GexReply.decode(payload)
          : SSH_Message_KexDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = encodeBigInt(message.f);
      clientKexKey = encodeBigInt(kex.e);
      sharedSecret = kex.computeSecret(message.f);
    } else if (kex is SSHKexECDH) {
      final message = SSH_Message_KexECDH_Reply.decode(payload);
      printTrace?.call('<- $socket: $message');
      hostkey = message.hostPublicKey;
      hostSignature = message.signature;
      serverKexKey = message.ecdhPublicKey;
      clientKexKey = kex.publicKey;
      sharedSecret = kex.computeSecret(message.ecdhPublicKey);
    } else {
      throw UnimplementedError('$kex');
    }

    final exchangeHash = SSHKexUtils.computeExchangeHash(
      digest: _kexType!.createDigest(),
      groupExchange: kexType.isGroupExchange ? kex as SSHKexDH : null,
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
      if (!verified) throw SSHHostkeyError('Signature verification failed');
    }

    // Re-key host-key pinning: after the initial exchange the server's host
    // key is fixed for the lifetime of the connection. A byte-for-byte
    // mismatch on any later KEX means the peer we're talking to changed -
    // a MITM takeover - so tear down rather than silently accept it. The
    // signature check above proves the key owns the exchange, but NOT that
    // it is the SAME key the user already trusted; this closes that gap.
    final pinnedHostKey = _verifiedHostKey;
    if (pinnedHostKey != null && !_hostKeyBytesEqual(pinnedHostKey, hostkey)) {
      closeWithError(SSHHostkeyError('Host key changed during re-key'));
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
      _sendNewKeys();
      _applyLocalKeys();
      return;
    }

    // Pass the RAW host key blob (not the MD5 digest) so the app computes
    // the standard OpenSSH SHA256 fingerprint and stores the real key.
    final userVerified = onVerifyHostKey != null
        ? onVerifyHostKey!(_hostkeyType!.name, hostkey)
        : true;

    Future.value(userVerified).then(
      (verified) {
        if (!verified) {
          closeWithError(SSHHostkeyError('Hostkey verification failed'));
        } else {
          _hostkeyVerified = true;
          // Pin the accepted key so every later re-key is checked against it.
          _verifiedHostKey = Uint8List.fromList(hostkey);
          _sendNewKeys();
          _applyLocalKeys();
          onReady?.call();
        }
      },
      onError: (error) {
        closeWithError(error);
      },
    );
  }

  void _handleMessageKexGexReply(Uint8List payload) {
    printDebug?.call('SSHTransport._handleMessageKexGexReply');
    if (isServer) throw SSHStateError('Unexpected KEX_GEX_REPLY');

    final message = SSH_Message_KexDH_GexGroup.decode(payload);
    printTrace?.call('<- $socket: $message');

    // Validate the server-chosen prime size (RFC 4419). Without this a
    // malicious server could pick a tiny, easily-broken modulus and
    // downgrade the DH strength while we believe we negotiated a strong
    // group. Enforce the same [min, max] window the client requested.
    final pBits = message.p.bitLength;
    if (pBits < SSHKexDH.gexMin || pBits > SSHKexDH.gexMax) {
      // SSHStateError (an SSHError) so `on SSHError` handles the teardown
      // cleanly, rather than a FormatException leaking to the zone.
      throw SSHStateError('DH group-exchange prime size $pBits bits out of '
          'range [${SSHKexDH.gexMin}, ${SSHKexDH.gexMax}]');
    }

    _kex = SSHKexDH(p: message.p, g: message.g, secretBits: 256);
    _sendKexDHGexInit();
  }

  void _handleMessageNewKeys(Uint8List message) {
    printDebug?.call('SSHTransport._handleMessageNewKeys');
    printTrace?.call('<- $socket: SSH_Message_NewKeys');

    _applyRemoteKeys();

    // Terrapin (CVE-2023-48795) strict KEX mitigation: reset the RECEIVE
    // sequence number after receiving server's NEWKEYS. The SEND sequence
    // number is reset separately in _sendNewKeys() after we send ours.
    // Each direction resets independently per the strict KEX spec.
    //
    // We also set _skipNextRemoteSNIncrease because _processPackets()
    // increments _remotePacketSN AFTER this handler returns. Without
    // skipping that increment, the first encrypted packet would be
    // decrypted with nonce=1 instead of nonce=0.
    if (_isInitialKex && _serverSupportsStrictKex) {
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
    if (_kexInProgress) {
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
