import 'dart:io' show SocketException;

import 'package:zest_ssh_core/zest_ssh_core.dart';

/// Every error and exception of the package that can be made, each with what
/// it prints. Read by the test that holds them to it as the tests run, and
/// by the program that prints them built with its names obfuscated
/// (errors_said_main.dart).
List<(Object, String)> errorsSaid() => [
      // The errors (ssh_errors.dart).
      (SSHInternalError('a state that cannot be'), 'SSHInternalError(a state that cannot be)'),
      (
        SSHHandshakeError('No matching key exchange algorithm'),
        'SSHHandshakeError(No matching key exchange algorithm)',
      ),
      (
        SSHAuthFailError('All authentication methods failed'),
        'SSHAuthFailError(All authentication methods failed)',
      ),
      (
        SSHAuthAbortError('Connection closed before authentication'),
        'SSHAuthAbortError(Connection closed before authentication)',
      ),
      (SSHPacketError('Malformed packet: no length'), 'SSHPacketError(Malformed packet: no length)'),
      (SSHStateError('Transport is closed'), 'SSHStateError(Transport is closed)'),
      (
        SSHDisconnectError(2, 'Too many authentication failures', authentic: true),
        'SSHDisconnectError(The server ended the connection: Too many authentication failures (reason code 2))',
      ),
      (
        SSHNoAnswerError(const Duration(seconds: 45), 3),
        'SSHNoAnswerError(Nothing came from the server for 45 seconds: 3 keep-alives went unanswered)',
      ),
      (
        SSHKeyDecodeError('Failed to decode private key', const FormatException('not a key')),
        'SSHKeyDecodeError(Failed to decode private key, FormatException: not a key)',
      ),
      (SSHKeyDecryptError('Invalid passphrase'), 'SSHKeyDecryptError(Invalid passphrase, null)'),
      (SSHChannelOpenError(2, 'Connection refused'), 'SSHChannelOpenError(2: Connection refused)'),
      (SSHChannelRequestError('Failed to start shell'), 'SSHChannelRequestError(Failed to start shell)'),
      (SSHHostkeyError('Hostkey verification failed'), 'SSHHostkeyError(Hostkey verification failed)'),
      (
        SSHKeySignError('The numbers of this RSA key do not fit each other'),
        'SSHKeySignError(The numbers of this RSA key do not fit each other)',
      ),
      (
        SSHKexGroupError('The server named a group of 1024 bits', bits: 1024, shortestTaken: 2048),
        'SSHKexGroupError(The server named a group of 1024 bits)',
      ),
      (
        SSHSocketError(const SocketException('Connection reset by peer')),
        'SSHSocketError(SocketException: Connection reset by peer)',
      ),

      // The exceptions (exceptions/ssh_exceptions.dart).
      (
        SSHConnectionRefusedException(host: '192.0.2.10', port: 22),
        'SSHConnectionRefusedException: Connection refused by 192.0.2.10:22',
      ),
      (
        SSHConnectionTimedOutException(host: '192.0.2.10', port: 22, timeout: const Duration(seconds: 30)),
        'SSHConnectionTimedOutException: Connection to 192.0.2.10:22 timed out after 30s',
      ),
      (
        SSHConnectionResetException(host: '192.0.2.10', port: 22),
        'SSHConnectionResetException: Connection to 192.0.2.10:22 was reset',
      ),
      (
        SSHNetworkUnreachableException(host: '192.0.2.10', port: 22),
        'SSHNetworkUnreachableException: Network unreachable while connecting to 192.0.2.10:22',
      ),
      (
        SSHDnsResolutionException(host: 'web-01.example.com'),
        'SSHDnsResolutionException: Failed to resolve hostname "web-01.example.com"',
      ),
      (
        SSHVersionMismatchException(serverVersion: 'SSH-1.5-old'),
        'SSHVersionMismatchException: SSH version mismatch: server reported "SSH-1.5-old"',
      ),
      (
        SSHNoMatchingCipherException(clientCiphers: ['aes256-ctr'], serverCiphers: ['3des-cbc']),
        'SSHNoMatchingCipherException: No matching cipher found. Client offered: aes256-ctr; server offered: 3des-cbc',
      ),
      (
        SSHNoMatchingKexException(clientKex: ['curve25519-sha256'], serverKex: ['diffie-hellman-group1-sha1']),
        'SSHNoMatchingKexException: No matching key exchange algorithm found. Client offered: curve25519-sha256; '
            'server offered: diffie-hellman-group1-sha1',
      ),
      (
        SSHNoMatchingMacException(clientMacs: ['hmac-sha2-256'], serverMacs: ['hmac-md5']),
        'SSHNoMatchingMacException: No matching MAC algorithm found. Client offered: hmac-sha2-256; server offered: '
            'hmac-md5',
      ),
      (
        SSHNoMatchingHostKeyException(clientHostKeys: ['ssh-ed25519'], serverHostKeys: ['ssh-dss']),
        'SSHNoMatchingHostKeyException: No matching host key algorithm found. Client offered: ssh-ed25519; server '
            'offered: ssh-dss',
      ),
      (
        SSHHostKeyUnknownException(host: '192.0.2.10', port: 22, keyType: 'ssh-ed25519', fingerprint: 'SHA256:new'),
        'SSHHostKeyUnknownException: Unknown host key for 192.0.2.10:22 (ssh-ed25519 SHA256:new)',
      ),
      (
        SSHHostKeyChangedException(
            host: '192.0.2.10',
            port: 22,
            keyType: 'ssh-ed25519',
            fingerprint: 'SHA256:new',
            previousFingerprint: 'SHA256:old'),
        'SSHHostKeyChangedException: Host key for 192.0.2.10:22 has CHANGED from SHA256:old to SHA256:new '
            '(ssh-ed25519). Possible MITM attack.',
      ),
      (
        SSHHostKeyVerificationFailedException(
            host: '192.0.2.10', port: 22, keyType: 'ssh-ed25519', fingerprint: 'SHA256:new'),
        'SSHHostKeyVerificationFailedException: Host key verification failed for 192.0.2.10:22 (ssh-ed25519 '
            'SHA256:new)',
      ),
      (
        SSHHostKeyRevokedException(host: '192.0.2.10', port: 22, keyType: 'ssh-ed25519', fingerprint: 'SHA256:new'),
        'SSHHostKeyRevokedException: Host key for 192.0.2.10:22 has been revoked (ssh-ed25519 SHA256:new)',
      ),
      (
        SSHAuthAllMethodsFailedException(attemptedMethods: ['publickey', 'password']),
        'SSHAuthAllMethodsFailedException: All authentication methods failed. Tried: publickey, password',
      ),
      (
        SSHPasswordIncorrectException(),
        'SSHPasswordIncorrectException: Password authentication failed: incorrect password',
      ),
      (SSHPasswordExpiredException(), 'SSHPasswordExpiredException: Password has expired'),
      (
        SSHKeyRejectedException(keyType: 'ssh-ed25519'),
        'SSHKeyRejectedException: Public key authentication failed (key type: ssh-ed25519)',
      ),
      (
        SSHNoMatchingKeyException(availableKeyTypes: ['ssh-rsa']),
        'SSHNoMatchingKeyException: No matching key for server. Available: ssh-rsa',
      ),
      (SSHKeyDecryptionException(), 'SSHKeyDecryptionException: Failed to decrypt private key'),
      (
        SSHUserUnknownException(username: 'deploy'),
        'SSHUserUnknownException: User "deploy" is not recognized by the server',
      ),
      (
        SSHInteractiveCancelledException(),
        'SSHInteractiveCancelledException: Keyboard-interactive authentication cancelled',
      ),
      (SSHTooManyAttemptsException(attempts: 6), 'SSHTooManyAttemptsException: Too many authentication attempts (6)'),
      (
        SSHDisconnectException(reasonCode: 11, description: 'bye'),
        'SSHDisconnectException: Disconnected (reason 11): bye',
      ),
      (
        SSHChannelOpenException(code: 2, description: 'Connection refused'),
        'SSHChannelOpenException: Channel open failed (2): Connection refused',
      ),
      (SSHChannelClosedException(channelId: 3), 'SSHChannelClosedException: Channel 3 is closed'),
      (
        SSHChannelRequestFailedException(requestType: 'exec'),
        'SSHChannelRequestFailedException: Channel request "exec" failed',
      ),
      (SSHProtocolViolationException('unexpected message'), 'SSHProtocolViolationException: unexpected message'),
      (
        SSHPacketTooLargeException(packetSize: 300000, maxSize: 262144),
        'SSHPacketTooLargeException: Packet too large: 300000 bytes (max 262144)',
      ),
      (SSHInvalidPacketException('bad padding'), 'SSHInvalidPacketException: bad padding'),
      (SSHMacMismatchException(), 'SSHMacMismatchException: MAC verification failed on received packet'),
      (SSHDecryptionException(), 'SSHDecryptionException: Failed to decrypt packet'),
      (SSHCancelledException(), 'SSHCancelledException: Operation cancelled'),
      (
        SSHCancelledException('Stopped', const FormatException('half a packet')),
        'SSHCancelledException: Stopped (cause: FormatException: half a packet)',
      ),
    ];

/// A type that says what the program calls it, for the test of a program
/// built obfuscated to see that it was: there this is not its name.
class NamedByTheProgram {
  const NamedByTheProgram();

  @override
  String toString() => '$runtimeType';
}
