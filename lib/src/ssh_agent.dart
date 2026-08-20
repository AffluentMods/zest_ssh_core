import 'dart:async';
import 'dart:typed_data';

import 'package:zest_ssh_core/src/hostkey/hostkey_rsa.dart';
import 'package:zest_ssh_core/src/ssh_channel.dart';
import 'package:zest_ssh_core/src/ssh_hostkey.dart';
import 'package:zest_ssh_core/src/ssh_key_pair.dart';
import 'package:zest_ssh_core/src/ssh_message.dart';
import 'package:zest_ssh_core/src/ssh_transport.dart';
import 'package:pointycastle/api.dart' hide Signature;
import 'package:pointycastle/asymmetric/api.dart' as asymmetric;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/signers/rsa_signer.dart';

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

  Uint8List _handleSignRequest(SSHMessageReader reader) {
    final keyBlob = reader.readString();
    final data = reader.readString();
    final flags = reader.readUint32();

    final identity = _findIdentity(keyBlob);
    if (identity == null) {
      return _failure();
    }

    final signature = _sign(identity, data, flags);
    final writer = SSHMessageWriter();
    writer.writeUint8(SSHAgentProtocol.signResponse);
    writer.writeString(signature.encode());
    return writer.takeBytes();
  }

  SSHSignature _sign(SSHKeyPair identity, Uint8List data, int flags) {
    if (identity is OpenSSHRsaKeyPair || identity is RsaPrivateKey) {
      final signatureType = _rsaSignatureTypeForFlags(flags);
      return _signRsa(identity, data, signatureType);
    }
    return identity.sign(data);
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

  SSHRsaSignature _signRsa(
    SSHKeyPair identity,
    Uint8List data,
    String signatureType,
  ) {
    final key = _rsaKeyFrom(identity);
    if (key == null) {
      return identity.sign(data) as SSHRsaSignature;
    }

    final signer = _rsaSignerFor(signatureType);
    signer.init(true, PrivateKeyParameter<asymmetric.RSAPrivateKey>(key));
    return SSHRsaSignature(signatureType, signer.generateSignature(data).bytes);
  }

  asymmetric.RSAPrivateKey? _rsaKeyFrom(SSHKeyPair identity) {
    if (identity is OpenSSHRsaKeyPair) {
      return asymmetric.RSAPrivateKey(
          identity.n, identity.d, identity.p, identity.q);
    }
    if (identity is RsaPrivateKey) {
      return asymmetric.RSAPrivateKey(
          identity.n, identity.d, identity.p, identity.q);
    }
    return null;
  }

  RSASigner _rsaSignerFor(String signatureType) {
    switch (signatureType) {
      case SSHRsaSignatureType.sha1:
        return RSASigner(SHA1Digest(), '06052b0e03021a');
      case SSHRsaSignatureType.sha256:
        return RSASigner(SHA256Digest(), '0609608648016503040201');
      case SSHRsaSignatureType.sha512:
        return RSASigner(SHA512Digest(), '0609608648016503040203');
      default:
        return RSASigner(SHA256Digest(), '0609608648016503040201');
    }
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
}
