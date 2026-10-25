import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_key_pair.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:zest_ssh_core/src/ssh_transport.dart';

abstract class SSHAgentHandler {
  Future<Uint8List> handleRequest(Uint8List request);
}

class SSHKeyPairAgent implements SSHAgentHandler {
  SSHKeyPairAgent(this._identities, {this.comment});

  final List<SSHKeyPair> _identities;
  final String? comment;

  @override
  Future<Uint8List> handleRequest(Uint8List request) async {
    if (request.isEmpty) {
      return _failure();
    }
    final reader = SSHMessageReader(request);
    final messageType = reader.readUint8();
    switch (messageType) {
      case SSHAgentProtocol.requestIdentities:
        return _handleRequestIdentities();
      case SSHAgentProtocol.signRequest:
        return _handleSignRequest(reader);
      default:
        return _failure();
    }
  }

  Uint8List _handleRequestIdentities() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.identitiesAnswer);
    writer.writeUint32(_identities.length);
    for (final identity in _identities) {
      final publicKey = identity.toPublicKey().encode();
      writer.writeString(publicKey);
      writer.writeUtf8(comment ?? '');
    }
    return writer.takeBytes();
  }

  Future<Uint8List> _handleSignRequest(SSHMessageReader reader) async {
    final keyBlob = reader.readString();
    final data = reader.readString();
    final flags = reader.readUint32();

    final identity = _findIdentity(keyBlob);
    if (identity == null) {
      return _failure();
    }

    final SSHSignature signature;
    try {
      signature = await _sign(identity, data, flags);
    } catch (_) {
      // A refused touch, a locked token or a local agent that went away:
      // the requester gets a plain failure and can try its next key.
      return _failure();
    }
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.signResponse);
    writer.writeString(signature.encode());
    return writer.takeBytes();
  }

  Future<SSHSignature> _sign(
    SSHKeyPair identity,
    Uint8List data,
    int flags,
  ) async {
    // A certificate signs with the key inside it. Unwrap it so an RSA
    // request gets the hash it asked for: the requester announces that
    // hash to the server, which refuses any other.
    final signer = switch (identity) {
      SSHWrappedKeyPair(:final innerKey) => innerKey,
      _ => identity,
    };
    // An RSA key signs with the hash that was asked for, and its signature
    // is checked with the key's public half before it is given out
    // (signRsaChecked): one that is not the key's own would give the key
    // away to the host the agent is forwarded to.
    switch (signer) {
      case OpenSSHRsaKeyPair(:final n, :final e, :final d, :final p, :final q) ||
            RsaPrivateKey(:final n, :final e, :final d, :final p, :final q):
        return signRsaChecked(n: n, e: e, d: d, p: p, q: q, data: data, type: _rsaSignatureTypeForFlags(flags));
    }
    // Hardware-token and agent-backed keys can only sign asynchronously
    // (their sign() throws), so forwarding them used to fail every time.
    // Software keys answer through the same path.
    return signer.signAsync(data);
  }

  String _rsaSignatureTypeForFlags(int flags) {
    if (flags & SSHAgentProtocol.rsaSha2_512 != 0) {
      return SSHRsaSignatureType.sha512;
    }
    if (flags & SSHAgentProtocol.rsaSha2_256 != 0) {
      return SSHRsaSignatureType.sha256;
    }
    return SSHRsaSignatureType.sha1;
  }

  SSHKeyPair? _findIdentity(Uint8List keyBlob) {
    for (final identity in _identities) {
      final publicKey = identity.toPublicKey().encode();
      if (_bytesEqual(publicKey, keyBlob)) {
        return identity;
      }
    }
    return null;
  }

  Uint8List _failure() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.failure);
    return writer.takeBytes();
  }

  /// Constant-time byte comparison to prevent timing side-channel attacks
  /// when matching agent keys.
  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }
}

class SSHAgentChannel {
  SSHAgentChannel(this._channel, this._handler, {this.printDebug}) {
    _subscription = _channel.stream.listen(
      _handleData,
      onDone: _handleDone,
      onError: (_, __) => _handleDone(),
    );
  }

  final SSHChannel _channel;
  final SSHAgentHandler _handler;
  final SSHPrintHandler? printDebug;

  /// Largest agent request we will ever buffer. A forwarded agent request is
  /// a public key blob + data to sign + flags - a few KB at most. The 4-byte
  /// length prefix is 32-bit and fully attacker-controlled, so without this
  /// cap a hostile forwarded connection could declare a 4 GB frame and force
  /// us to buffer unbounded data. 256 KB is comfortably above any legitimate
  /// request while bounding memory.
  static const int _maxFrameLength = 256 * 1024;

  StreamSubscription<SSHChannelData>? _subscription;
  Uint8List _buffer = Uint8List(0);
  bool _processing = false;
  bool _aborted = false;

  void _handleDone() {
    _subscription?.cancel();
  }

  void _handleData(SSHChannelData data) {
    if (_aborted) return;
    _buffer = _appendBytes(_buffer, data.bytes);
    // Hard cap on accumulated bytes: even before a complete frame arrives,
    // never let the pending buffer exceed one max-size frame plus its prefix.
    if (_buffer.length > _maxFrameLength + 4) {
      _abort('agent buffer exceeded ${_maxFrameLength + 4} bytes');
      return;
    }
    _drainRequests();
  }

  /// Tear the agent channel down on protocol abuse. Prevents a hostile
  /// forwarded agent from OOMing the client.
  void _abort(String reason) {
    if (_aborted) return;
    _aborted = true;
    printDebug?.call('SSH agent channel aborted: $reason');
    _buffer = Uint8List(0);
    _subscription?.cancel();
    _channel.close();
  }

  void _drainRequests() {
    if (_processing) return;
    _processing = true;
    _processQueue().whenComplete(() => _processing = false);
  }

  Future<void> _processQueue() async {
    while (!_aborted && _buffer.length >= 4) {
      final length = ByteData.sublistView(_buffer, 0, 4).getUint32(0);
      // Reject an over-large declared frame immediately instead of waiting
      // (forever) for attacker-promised bytes to fill the buffer.
      if (length > _maxFrameLength) {
        _abort('agent frame length $length exceeds cap $_maxFrameLength');
        return;
      }
      if (_buffer.length < 4 + length) return;
      final payload = _buffer.sublist(4, 4 + length);
      _buffer = _buffer.sublist(4 + length);
      Uint8List response;
      try {
        response = await _handler.handleRequest(payload);
      } catch (error) {
        printDebug?.call('SSH agent handler error: $error');
        response = _failureResponse();
      }
      _sendResponse(response);
    }
  }

  Uint8List _failureResponse() {
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.failure);
    return writer.takeBytes();
  }

  void _sendResponse(Uint8List payload) {
    final writer = SSHMessageWriter();
    writer.writeUint32(payload.length);
    writer.writeBytes(payload);
    _channel.addData(writer.takeBytes());
  }

  Uint8List _appendBytes(Uint8List a, Uint8List b) {
    if (a.isEmpty) return b;
    if (b.isEmpty) return a;
    final combined = Uint8List(a.length + b.length);
    combined.setAll(0, a);
    combined.setAll(a.length, b);
    return combined;
  }
}

abstract class SSHAgentProtocol {
  static const int failure = 5;
  static const int requestIdentities = 11;
  static const int identitiesAnswer = 12;
  static const int signRequest = 13;
  static const int signResponse = 14;
  static const int rsaSha2_256 = 2;
  static const int rsaSha2_512 = 4;

  /// SSH_AGENT_SUCCESS: what an agent answers a request that changes it.
  static const int success = 6;

  /// SSH2_AGENTC_ADD_IDENTITY: a key given to the agent to keep.
  static const int addIdentity = 17;

  /// SSH2_AGENTC_ADD_ID_CONSTRAINED: the same, with how it may be kept.
  static const int addIdConstrained = 25;

  /// SSH_AGENT_CONSTRAIN_LIFETIME: the key is kept for so many seconds.
  static const int constrainLifetime = 1;

  /// The request that gives [key] to an agent to keep (draft-miller-ssh-
  /// agent, section 3.2): its type and private numbers as OpenSSH's agent
  /// takes them, with [comment] (what `ssh-add -l` shows for it), and, where
  /// [lifetime] is given, for that long only (whole seconds, at least one;
  /// the agent forgets it after). Without the 4-byte length every message
  /// to an agent goes with. Throws [UnsupportedError] for a key an OpenSSH
  /// agent does not take (Ed448), or one held somewhere else (a hardware or
  /// agent key, which has no numbers here).
  static Uint8List addIdentityRequest(SSHKeyPair key, {String comment = '', Duration? lifetime}) {
    final writer = SSHMessageWriter();
    writer.writeUint8(lifetime == null ? addIdentity : addIdConstrained);
    final inner = key is SSHWrappedKeyPair ? (key as SSHWrappedKeyPair).innerKey : key;
    switch (inner) {
      case OpenSSHRsaKeyPair(:final n, :final e, :final d, :final iqmp, :final p, :final q):
        writer.writeUtf8('ssh-rsa');
        for (final v in [n, e, d, iqmp, p, q]) {
          writer.writeMpint(v);
        }
      case RsaPrivateKey(:final n, :final e, :final d, :final coefficient, :final p, :final q):
        writer.writeUtf8('ssh-rsa');
        for (final v in [n, e, d, coefficient, p, q]) {
          writer.writeMpint(v);
        }
      case OpenSSHEd25519KeyPair(:final publicKey, :final privateKey):
        writer.writeUtf8('ssh-ed25519');
        writer.writeString(publicKey);
        writer.writeString(privateKey);
      case OpenSSHEcdsaKeyPair(:final curveId, :final q, :final d):
        writer.writeUtf8('ecdsa-sha2-$curveId');
        writer.writeUtf8(curveId);
        writer.writeString(q);
        writer.writeMpint(d);
      default:
        throw UnsupportedError('An agent cannot be given a key of this kind (${inner.type})');
    }
    writer.writeUtf8(comment.replaceAll(RegExp(r'[\r\n]+'), ' '));
    if (lifetime != null) {
      final seconds = lifetime.inSeconds < 1 ? 1 : lifetime.inSeconds;
      writer.writeUint8(constrainLifetime);
      writer.writeUint32(seconds);
    }
    return writer.takeBytes();
  }
}
