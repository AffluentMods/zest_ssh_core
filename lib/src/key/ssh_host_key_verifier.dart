import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:pointycastle/export.dart';

/// Information about a host key received during SSH connection.
class SSHHostKeyInfo {
  /// The hostname or IP address of the server.
  final String host;

  /// The port number of the server.
  final int port;

  /// The SSH key type string (e.g. "ssh-rsa", "ssh-ed25519").
  final String keyType;

  /// The raw key data bytes.
  final Uint8List keyData;

  /// The SHA-256 fingerprint of the key, base64-encoded.
  final String sha256Fingerprint;

  /// The MD5 fingerprint of the key, colon-separated hex.
  final String md5Fingerprint;

  const SSHHostKeyInfo({
    required this.host,
    required this.port,
    required this.keyType,
    required this.keyData,
    required this.sha256Fingerprint,
    required this.md5Fingerprint,
  });

  /// Compute an [SSHHostKeyInfo] from raw key data.
  factory SSHHostKeyInfo.fromKeyData({
    required String host,
    required int port,
    required String keyType,
    required Uint8List keyData,
  }) {
    final sha256 = Digest('SHA-256').process(keyData);
    final md5 = Digest('MD5').process(keyData);

    final sha256Fingerprint = base64.encode(sha256);
    final md5Fingerprint = _formatMd5(md5);

    return SSHHostKeyInfo(
      host: host,
      port: port,
      keyType: keyType,
      keyData: keyData,
      sha256Fingerprint: sha256Fingerprint,
      md5Fingerprint: md5Fingerprint,
    );
  }

  static String _formatMd5(Uint8List bytes) {
    return bytes.map((b) => hex.encode([b])).join(':');
  }

  @override
  String toString() {
    return 'SSHHostKeyInfo(host: $host, port: $port, keyType: $keyType, '
        'sha256: $sha256Fingerprint)';
  }
}

/// Abstract interface for verifying SSH host keys.
abstract class SSHHostKeyVerifier {
  /// Verify the given [info]. Implementations should throw an exception
  /// (typically [SSHHostKeyVerifyError]) if verification fails, or return
  /// normally if the key is accepted.
  Future<void> verify(SSHHostKeyInfo info);
}

/// Error thrown when host key verification fails.
class SSHHostKeyVerifyError implements Exception {
  final String message;

  const SSHHostKeyVerifyError(this.message);

  @override
  String toString() => 'SSHHostKeyVerifyError: $message';
}

/// A verifier that accepts all host keys unconditionally.
/// **For testing only** -- do not use in production.
class SSHAcceptAllHostKeyVerifier implements SSHHostKeyVerifier {
  const SSHAcceptAllHostKeyVerifier();

  @override
  Future<void> verify(SSHHostKeyInfo info) async {}
}

/// A verifier that delegates to a user-provided async callback.
///
/// The callback should throw to reject the key, or return normally to accept.
class SSHCallbackHostKeyVerifier implements SSHHostKeyVerifier {
  final Future<void> Function(SSHHostKeyInfo info) _callback;

  const SSHCallbackHostKeyVerifier(this._callback);

  @override
  Future<void> verify(SSHHostKeyInfo info) => _callback(info);
}

/// A parsed entry from an OpenSSH known_hosts file.
class KnownHostEntry {
  /// Whether this entry has a `@cert-authority` marker.
  final bool isCertAuthority;

  /// Whether this entry has a `@revoked` marker.
  final bool isRevoked;

  /// Raw hostname patterns from the entry. May include comma-separated values,
  /// hashed entries, or `[host]:port` notation.
  final List<String> hostPatterns;

  /// The SSH key type string.
  final String keyType;

  /// The base64-encoded key data.
  final String keyDataBase64;

  /// The decoded key data bytes.
  Uint8List get keyData => base64.decode(keyDataBase64);

  const KnownHostEntry({
    required this.isCertAuthority,
    required this.isRevoked,
    required this.hostPatterns,
    required this.keyType,
    required this.keyDataBase64,
  });

  @override
  String toString() {
    final marker = isCertAuthority
        ? '@cert-authority '
        : isRevoked
            ? '@revoked '
            : '';
    return 'KnownHostEntry(${marker}hosts: $hostPatterns, type: $keyType)';
  }
}

/// A verifier that checks host keys against entries parsed from an OpenSSH
/// known_hosts format file.
///
/// Supports:
/// - Plain hostname entries
/// - Hashed hostname entries (`|1|salt|hash`)
/// - Comma-separated hostnames
/// - Port-qualified entries (`[host]:port`)
/// - `@cert-authority` markers
/// - `@revoked` markers
/// - Comment lines (starting with `#`)
class SSHKnownHostsVerifier implements SSHHostKeyVerifier {
  final List<KnownHostEntry> _entries;

  SSHKnownHostsVerifier._(this._entries);

  /// Parse a known_hosts file from its text content.
  factory SSHKnownHostsVerifier.fromString(String content) {
    final entries = <KnownHostEntry>[];

    for (final rawLine in content.split('\n')) {
      final line = rawLine.trim();

      // Skip empty lines and comments.
      if (line.isEmpty || line.startsWith('#')) continue;

      final entry = _parseLine(line);
      if (entry != null) {
        entries.add(entry);
      }
    }

    return SSHKnownHostsVerifier._(entries);
  }

  /// Create a verifier from a list of pre-parsed entries.
  factory SSHKnownHostsVerifier.fromEntries(List<KnownHostEntry> entries) {
    return SSHKnownHostsVerifier._(List.unmodifiable(entries));
  }

  /// The parsed entries.
  List<KnownHostEntry> get entries => List.unmodifiable(_entries);

  @override
  Future<void> verify(SSHHostKeyInfo info) async {
    final matchingEntries = _findMatches(info.host, info.port, info.keyType);

    if (matchingEntries.isEmpty) {
      throw SSHHostKeyVerifyError(
        'No known_hosts entry found for ${info.host}:${info.port} '
        '(key type: ${info.keyType})',
      );
    }

    // Check for revoked keys first.
    for (final entry in matchingEntries) {
      if (entry.isRevoked) {
        final entryKeyData = entry.keyData;
        if (_keyDataEquals(entryKeyData, info.keyData)) {
          throw SSHHostKeyVerifyError(
            'Host key for ${info.host}:${info.port} is revoked',
          );
        }
      }
    }

    // Check for matching key data among non-revoked entries.
    for (final entry in matchingEntries) {
      if (entry.isRevoked) continue;
      final entryKeyData = entry.keyData;
      if (_keyDataEquals(entryKeyData, info.keyData)) {
        return; // Key matches a known entry.
      }
    }

    throw SSHHostKeyVerifyError(
      'Host key for ${info.host}:${info.port} does not match known key',
    );
  }

  List<KnownHostEntry> _findMatches(String host, int port, String keyType) {
    final results = <KnownHostEntry>[];

    for (final entry in _entries) {
      if (entry.keyType != keyType) continue;

      for (final pattern in entry.hostPatterns) {
        if (_matchesHost(pattern, host, port)) {
          results.add(entry);
          break;
        }
      }
    }

    return results;
  }

  static bool _matchesHost(String pattern, String host, int port) {
    // Hashed hostname entry: |1|salt|hash
    if (pattern.startsWith('|1|')) {
      return _matchesHashedHost(pattern, host, port);
    }

    // Port-qualified entry: [host]:port
    final portQualified = RegExp(r'^\[(.+)\]:(\d+)$').firstMatch(pattern);
    if (portQualified != null) {
      final patternHost = portQualified.group(1)!;
      final patternPort = int.tryParse(portQualified.group(2)!);
      return patternHost == host && patternPort == port;
    }

    // Plain hostname -- only matches if using default port 22.
    return pattern == host && port == 22;
  }

  static bool _matchesHashedHost(String pattern, String host, int port) {
    final parts = pattern.split('|');
    // Format: |1|salt_base64|hash_base64
    if (parts.length != 4 || parts[1] != '1') return false;

    final salt = base64.decode(parts[2]);
    final expectedHash = base64.decode(parts[3]);

    // Try matching with just the hostname.
    if (_hmacMatches(salt, expectedHash, host)) return true;

    // Try matching with [host]:port format.
    if (port != 22) {
      final portQualified = '[$host]:$port';
      if (_hmacMatches(salt, expectedHash, portQualified)) return true;
    }

    return false;
  }

  static bool _hmacMatches(
    Uint8List salt,
    Uint8List expectedHash,
    String data,
  ) {
    final hmac = HMac(SHA1Digest(), 64);
    hmac.init(KeyParameter(salt));
    final dataBytes = utf8.encode(data);
    final computed = hmac.process(Uint8List.fromList(dataBytes));
    return _constantTimeEquals(computed, expectedHash);
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  static bool _keyDataEquals(Uint8List a, Uint8List b) {
    return _constantTimeEquals(a, b);
  }

  /// Maximum allowed length for a single known_hosts line (100 KB).
  static const _maxLineLength = 100 * 1024;

  /// Maximum allowed length for the base64 key data field (50 KB).
  static const _maxKeyDataBase64Length = 50 * 1024;

  /// Maximum allowed length for the key type string (100 chars).
  static const _maxKeyTypeLength = 100;

  static KnownHostEntry? _parseLine(String line) {
    // DoS protection: reject excessively long lines.
    if (line.length > _maxLineLength) return null;

    var isCertAuthority = false;
    var isRevoked = false;
    var working = line;

    // Check for markers.
    if (working.startsWith('@cert-authority ')) {
      isCertAuthority = true;
      working = working.substring('@cert-authority '.length).trimLeft();
    } else if (working.startsWith('@revoked ')) {
      isRevoked = true;
      working = working.substring('@revoked '.length).trimLeft();
    }

    // Split into: hostnames keytype keydata [comment]
    final parts = working.split(RegExp(r'\s+'));
    if (parts.length < 3) return null;

    final hostnamesPart = parts[0];
    final keyType = parts[1];
    final keyDataBase64 = parts[2];

    // DoS protection: reject oversized key type strings.
    if (keyType.length > _maxKeyTypeLength) return null;

    // DoS protection: reject oversized base64 key data.
    if (keyDataBase64.length > _maxKeyDataBase64Length) return null;

    // Validate the base64 key data.
    try {
      base64.decode(keyDataBase64);
    } catch (_) {
      return null; // Invalid base64, skip this entry.
    }

    // Parse comma-separated hostnames.
    final hostPatterns = hostnamesPart.split(',');

    return KnownHostEntry(
      isCertAuthority: isCertAuthority,
      isRevoked: isRevoked,
      hostPatterns: hostPatterns,
      keyType: keyType,
      keyDataBase64: keyDataBase64,
    );
  }
}
