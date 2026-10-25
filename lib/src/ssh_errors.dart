/// Interface for all the exceptions thrown by the library.
abstract class SSHError {}

/// Errors with a message.
mixin SSHMessageError {
  String get message;

  /// What this kind of error is called in code, spelled out by each kind.
  ///
  /// It is not asked of the program (`runtimeType`): a program that is
  /// built with its names obfuscated, as a released app most often is, has
  /// another name for nearly every type ("Ei"), and whoever reads an error
  /// as text, a person in a log or a program that looks for a name in it,
  /// then reads that one. A kind that spells no name out is an "SSHError".
  String get typeName => 'SSHError';

  @override
  String toString() {
    return '$typeName($message)';
  }
}

/// Errors that are not expected to occur. Most of the time, these are caused
/// by bugs in the library.
class SSHInternalError implements SSHError {
  final Object error;

  SSHInternalError(this.error);

  @override
  String toString() {
    return 'SSHInternalError($error)';
  }
}

/// Errors that happen when the library fails to connect to handshake.
class SSHHandshakeError with SSHMessageError implements SSHError {
  @override
  final String message;

  /// Whether the other side broke the order of the strict key exchange
  /// that both sides had named (`kex-strict-*-v00@openssh.com`): its
  /// proposal was not the first packet it sent, or something came in the
  /// first exchange that is no message of it. A packet put in before the
  /// keys are in force is what an attack on the count of packets is made
  /// of (Terrapin, CVE-2023-48795); a server that names the strict
  /// exchange and does not keep to it does the same.
  final bool strictOrderBroken;

  /// What this side offered of the kind of algorithm that the two sides
  /// have none in common of (the key exchanges, the kinds of host key, the
  /// ciphers or the MACs of one direction: [message] says which), in the
  /// order it offered them. Null for every other end of a handshake.
  final List<String>? offered;

  /// What the other side offered of that kind, in its order, where
  /// [offered] says what this side did. The two marks a proposal carries
  /// among its key exchanges, which are no algorithms (`ext-info-*`,
  /// `kex-strict-*-v00@openssh.com`), are left out.
  ///
  /// They are the other side's own text: whoever shows them keeps of them
  /// what a name can be.
  final List<String>? otherSideOffered;

  /// Whether the handshake ended because the two sides have no algorithm
  /// of one kind in common ([offered], [otherSideOffered]). The next try
  /// offers the same and is offered the same.
  bool get nothingInCommon => otherSideOffered != null;

  SSHHandshakeError(
    this.message, {
    this.strictOrderBroken = false,
    this.offered,
    this.otherSideOffered,
  });

  @override
  String get typeName => 'SSHHandshakeError';
}

/// Errors that happen when the library fails to authenticate.
abstract class SSHAuthError with SSHMessageError implements SSHError {}

/// Errors that happen when the library tried all the authentication methods
/// and failed to authenticate.
class SSHAuthFailError with SSHMessageError implements SSHAuthError {
  @override
  final String message;

  /// The ways of signing in that were tried, in the order they were tried,
  /// by their names in the protocol ("publickey", "password",
  /// "keyboard-interactive"); a way that was tried more than once, as
  /// "publickey" is with several keys, is named once. The question a client
  /// asks first of all ("none") is not among them.
  final List<String> methodsTried;

  /// The ways the server said it takes, at its last refusal
  /// ("authentications that can continue", RFC 4252, 5.1). Null where it
  /// never said. Where none of them is among [methodsTried], the server
  /// takes nothing this client had to offer.
  final List<String>? serverTakes;

  /// The keys the server was not asked about, by their kinds ("ssh-rsa"),
  /// in the order they came up: the server had said which kinds of
  /// signature it takes ([serverSignatureAlgorithms]), and takes none that
  /// such a key can make and this client may make
  /// ([SSHAlgorithms.rsaSignatures]). Nothing was sent to the server of
  /// them. Empty where every key was asked about.
  final List<String> keysPassedOver;

  /// The kinds of signature the server said it takes from a key that signs
  /// in ("server-sig-algs", RFC 8308, 3.1). Null where it did not say.
  final List<String>? serverSignatureAlgorithms;

  SSHAuthFailError(
    this.message, {
    this.methodsTried = const [],
    this.serverTakes,
    this.keysPassedOver = const [],
    this.serverSignatureAlgorithms,
  });

  @override
  String get typeName => 'SSHAuthFailError';
}

/// Errors that happen when the authentication failed due to other reasons.
/// For example network errors.
class SSHAuthAbortError with SSHMessageError implements SSHAuthError {
  @override
  final String message;

  final SSHError? reason;

  SSHAuthAbortError(this.message, [this.reason]);

  @override
  String get typeName => 'SSHAuthAbortError';
}

/// Errors that happen when the library receives an malformed packet.
class SSHPacketError with SSHMessageError implements SSHError {
  @override
  final String message;

  /// Whether the packet came under keys and did not pass the check every
  /// such packet carries (its MAC, or the tag of a cipher that checks its
  /// packets by itself), or had a length no packet has, which is read
  /// before a packet can be checked: it was changed or damaged on the way,
  /// by a line that is failing or by whoever sits on it, or the two sides
  /// do not protect their packets the same way. Nothing of it was used.
  /// False for a packet the other side itself sent wrongly, and for
  /// anything that came before keys were in force.
  final bool damaged;

  SSHPacketError(this.message, {this.damaged = false});

  @override
  String get typeName => 'SSHPacketError';
}

/// Errors that happen when the library receives an unexpected packet.
class SSHStateError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHStateError(this.message);

  @override
  String get typeName => 'SSHStateError';
}

/// The server named a group for a group exchange (RFC 4419) that the
/// library does not take: of a length other than was asked for, or no group
/// at all (a modulus that is an even number, a generator that makes every
/// secret one of two or three numbers). Everything a session carries is as
/// safe as that group and no safer.
class SSHKexGroupError with SSHMessageError implements SSHError {
  @override
  final String message;

  /// How long the modulus of the group is, in bits.
  final int bits;

  /// The shortest group the library takes, in bits.
  final int shortestTaken;

  SSHKexGroupError(this.message, {required this.bits, required this.shortestTaken});

  /// Whether the group was refused for being shorter than the library
  /// takes, and for nothing else: a server that has longer groups, or
  /// another key exchange, can be connected to.
  bool get tooShort => bits < shortestTaken;

  @override
  String get typeName => 'SSHKexGroupError';
}

/// The connection was ended by a message that says so (SSH_MSG_DISCONNECT),
/// with a reason code and, most often, why in words: too many sign-in tries,
/// a limit on idle time, an administrator's notice.
///
/// [description] is that text as it came, and whoever shows it should show
/// it as what was said and nothing more. Whose text it is, [authentic] says.
class SSHDisconnectError with SSHMessageError implements SSHError {
  /// The reason code of RFC 4253 (11.1): 2 a protocol error, 11 by the
  /// application, 12 too many connections, and so on.
  final int reasonCode;

  /// Why, in the words of whoever sent the message. May be empty.
  final String description;

  /// Whether the message is the other side's own: it came under the keys of
  /// a key exchange and, for a client, of one whose host key was approved.
  /// Where this is false it came in the clear, or from whoever holds a host
  /// key that nobody had approved yet: it can be anybody's on the way to the
  /// server, and whoever shows [description] should say so.
  final bool authentic;

  SSHDisconnectError(this.reasonCode, this.description, {required this.authentic});

  @override
  String get message {
    final what = authentic
        ? 'The server ended the connection'
        : 'The connection was ended before the server was verified';
    if (description.isEmpty) return '$what (reason code $reasonCode)';
    return authentic
        ? '$what: $description (reason code $reasonCode)'
        : '$what, with: $description (reason code $reasonCode)';
  }

  @override
  String get typeName => 'SSHDisconnectError';
}

/// The connection went quiet and was given up: keep-alives went unanswered,
/// and nothing else came from the server either. (A network that drops
/// everything, a host that froze, a device that changed networks: the
/// system itself may hold such a connection to be open for very long.)
class SSHNoAnswerError with SSHMessageError implements SSHError {
  /// How long nothing came from the server, at the least.
  final Duration silence;

  /// How many keep-alives in a row went unanswered.
  final int unanswered;

  SSHNoAnswerError(this.silence, this.unanswered);

  @override
  String get message =>
      'Nothing came from the server for ${silence.inSeconds} seconds: $unanswered keep-alives went unanswered';

  @override
  String get typeName => 'SSHNoAnswerError';
}

/// Errors that happen when the library fails to decode a key.
class SSHKeyDecodeError with SSHMessageError implements SSHError {
  @override
  final String message;

  final Object? error;

  SSHKeyDecodeError(this.message, [this.error]);

  @override
  String get typeName => 'SSHKeyDecodeError';

  @override
  String toString() {
    return '$typeName($message, $error)';
  }
}

/// Errors that happen when the library fails to decrypt the host key.
class SSHKeyDecryptError extends SSHKeyDecodeError {
  SSHKeyDecryptError(super.message, [super.error]);

  @override
  String get typeName => 'SSHKeyDecryptError';
}

/// Errors that happen when the library fails to open a channel.
class SSHChannelOpenError implements SSHError {
  final int code;

  final String description;

  SSHChannelOpenError(this.code, this.description);

  @override
  String toString() {
    return 'SSHChannelOpenError($code: $description)';
  }
}

/// Errors that happen when the library fails to send a channel request.
class SSHChannelRequestError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHChannelRequestError(this.message);

  @override
  String get typeName => 'SSHChannelRequestError';
}

/// What the library found wrong with a host key that it refused by itself,
/// before anybody was asked about the key ([SSHHostkeyError.fault]).
enum SSHHostkeyFault {
  /// The key did not sign the exchange it came with: whoever showed it has
  /// not proved that the key is theirs. That is what a host key is there to
  /// tell: somebody who answers in a host's place has its key, and cannot
  /// sign with it.
  notSigned,

  /// The server showed another key than the one the connection began with,
  /// when new keys were taken on a connection that was open.
  changed,

  /// What the server showed is no key a server has: of another kind than
  /// was agreed on, of a size no key has, with a signature of another kind
  /// than the key's, or not to be read as a key at all.
  noKey,

  /// The key is an RSA key shorter than is taken
  /// (`SSHAlgorithms.minRsaHostKeyBits`): one that whoever has the means
  /// can work out, and then answer in the server's place.
  /// [SSHHostkeyError.bits] says how long it is, and
  /// [SSHHostkeyError.shortestTaken] what the shortest taken is.
  tooShort,
}

/// A signature that a key made was not given out: it is not the key's own,
/// or the numbers of the key do not fit each other.
///
/// An RSA signature that comes out wrong gives away the key that made it
/// to whoever sees it and knows what was signed, so each one is checked
/// with the key's public half before anybody is sent it. It comes out
/// wrong where the numbers of a key file do not fit, and where a machine,
/// or the arithmetic it computes with, makes a mistake.
class SSHKeySignError with SSHMessageError implements SSHError {
  @override
  final String message;

  SSHKeySignError(this.message);

  @override
  String get typeName => 'SSHKeySignError';
}

/// Errors that happen when the library fails to verify the host key.
class SSHHostkeyError with SSHMessageError implements SSHError {
  @override
  final String message;

  /// What was wrong with the key, where the library refused it by itself.
  /// Null where whoever verifies host keys said no to it
  /// (`onVerifyHostKey`), or could not say, and for an error an
  /// application makes of its own.
  final SSHHostkeyFault? fault;

  /// Whether the key was refused when new keys were taken on a connection
  /// that was open, and not at the start of one. Such a connection had a
  /// host key that was accepted: what went over it until then went to
  /// whoever showed that key, where a connection that is refused at its
  /// start was sent nothing.
  final bool duringRekey;

  /// How long the key is, in bits, where it was refused for its length
  /// ([SSHHostkeyFault.tooShort]).
  final int? bits;

  /// The shortest key that is taken, in bits, where [bits] says how long
  /// the key was.
  final int? shortestTaken;

  SSHHostkeyError(this.message, {this.fault, this.duringRekey = false, this.bits, this.shortestTaken});

  @override
  String get typeName => 'SSHHostkeyError';
}

/// Errors related to the underlying socket.
class SSHSocketError implements SSHError {
  final Object error;

  SSHSocketError(this.error);

  @override
  String toString() {
    return 'SSHSocketError($error)';
  }
}
