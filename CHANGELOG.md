# Changelog

This is the changelog for `zest_ssh_core`. For the history of dartssh2 up to the fork point, see
`CHANGELOG-dartssh2.md`.

## Unreleased

## 0.2.2 - 2026-10-29

### Changed

- **RSA host keys of at least 2048 bits by default** (`SSHAlgorithms.minRsaHostKeyBits`, was 1024 as in
  OpenSSH): NIST's floor for RSA until 2030 (SP 800-131A), and the OpenSSF Best Practices
  `crypto_keylength` criterion. A server with a shorter RSA host key is refused before anything is
  computed with the key, with `SSHHostkeyError(fault: tooShort)` naming both lengths.
  `minRsaHostKeyBits: 1024` takes what OpenSSH takes, and `0` any length, for an old device that
  has no other.

### Added

- **A server that sends its version and no key exchange proposal is said so, in ten seconds.**
  `SSHTransport.kexInitPatience` (and `SSHClient.kexInitPatience`), 10 seconds where nothing is
  said, is how long a client waits from the server's version for its SSH_MSG_KEXINIT; then the
  connection ends with `SSHHandshakeError(kexUnanswered: true)`, and not with a sign-in that ran out
  of time later. The SSH inspection of a SonicWall firewall (DPI-SSH, which answers with
  `SSH-2.0-libssh_0.9.0`) did this to a client's default offer (a user, 28 October 2026). What is
  offered is unchanged.

### Changed

- **AES-GCM is in the default proposal**, after the ciphers that were in it:
  `chacha20-poly1305@openssh.com`, `aes256-ctr`, `aes128-ctr`, `aes256-gcm@openssh.com`,
  `aes128-gcm@openssh.com`. A server set to GCM ciphers alone, which a default client had nothing in
  common with ("No matching client cipher algorithm"), is connected to now. Nothing changes for any
  other server: the first cipher of the client's list that the server has is the one agreed on, and
  the three that were offered before still come first. Whoever passes a cipher list of their own
  gets exactly that list, as before. Held against a real OpenSSH that has the two GCM ciphers and no
  other (`tool/test_sshd.sh` starts it as a seventh server; `tool/test_sshd.sh add` starts what is
  not running and leaves the other servers alone).
- **A group exchange can take a group of 1024 bits, where whoever connects says so.**
  `SSHAlgorithms.minDhGroupBits` is the shortest Diffie-Hellman group a group exchange asks for and
  takes: 2048 where nothing is said (`SSHKexDH.gexMin`), as before. 1024
  (`SSHKexDH.gexMinOldServers`) is for an old server whose SSH server has no longer group and cannot
  be updated (an old OpenSSH, some embedded devices), which could not be connected to at all: the
  request asks for 1024 at the least (3072 for choice and 8192 at the most, as before), the group
  the server names is held to that, and the exchange hash is made of the lengths that were asked
  for. Nothing under 1024 bits is ever asked for or taken, whatever is said (`SSHKexDH.shortestAskedFor`).
  A group of 1024 bits can be broken by whoever has the means: it is for a server that has nothing
  better. `SSHKexDH.requireGroupOfAnExchange` takes the shortest that was asked for (`shortest`).

### Security

- **Nothing in the clear is taken once the host key is approved.** Until the server's first
  NEWKEYS, what arrives comes in the clear, and anybody on the way can have written it. Where no
  strict key exchange was agreed (a server older than OpenSSH 9.6, or one set without it), the
  transport handed such a message up once the host key had been approved, so whoever sat between
  the client and the server could answer the client's request for a service and its sign-in in the
  clear and play it a session it took for the server's: output that was never the server's, a
  sign-in that never happened. What the client sent went under the new keys, so none of it could
  be read. Every version of this package before this one is affected. Now nothing but the
  exchange's own messages and those of any time (1 to 4) is taken until what the server sends comes
  under keys whose host key was approved; anything else ends the connection with an
  `SSHStateError` that says it came in the clear. An `SSH_MSG_EXT_INFO` before the server's NEWKEYS
  ends it too: RFC 8308 sends it after, and it was handed up as a message nobody knows.

- **New keys are asked for.** The client took new keys when the server asked for them, and never
  asked by itself: nothing counted what had gone out or come in under a set of keys, and the number
  of a packet went from 2^32 - 1 to nought without a word. RFC 4253 (9) recommends new keys after
  each gigabyte, and RFC 4344 (3.1) says a side must not send more than 2^32 packets under one set
  of keys. Under chacha20-poly1305 the number of the packet is the nonce: with a server that never
  asks, the 2^32nd packet came under a nonce that had been used with the same keys, which undoes
  the cipher for both packets; with a MAC, a packet of 2^32 packets ago passes its check again. An
  OpenSSH server asks after about a gigabyte, so with one this did not come about. Every version of
  this package before this one is affected.
  Now a side asks for new keys once a gigabyte, or 2^31 packets, have gone one way under those in
  force (`SSHTransport.rekeyAfterBytes`, `rekeyAfterPackets`, and the same two on `SSHClient`), as
  OpenSSH does. Where the new keys do not come and twice that many packets, less one, have gone one
  way, the connection ends with an `SSHHandshakeError`. New keys taken at the other side's asking
  put the counts at nought as well.
- **An RSA host key shorter than 1024 bits is refused.** A server's RSA key of any length down to
  what holds a signature was taken, and put to whoever verifies host keys as any other. A key of 512
  bits can be worked out in hours on a computer anybody can rent, and one of 768 by whoever brings
  more; who has done so answers in the server's place, with the server's own key. Such a key ends
  the connection now, before its signature is checked and before anybody is asked, with an
  `SSHHostkeyError` whose `fault` is `SSHHostkeyFault.tooShort` and which says how long the key is
  (`bits`) and what the shortest taken is (`shortestTaken`). OpenSSH refuses the same since 7.6.
  The shortest taken is `SSHAlgorithms.minRsaHostKeyBits`, 1024 where nothing is said; 0 takes a key
  of any length, for an old device that has no other.
- **The answer to a key exchange is taken once.** The client took every answer a server sent to
  one key exchange, each replacing the secret of the one before, while the host key that came with
  an answer was still being verified (a lookup of known hosts, a prompt on screen). Someone between
  the client and the server could let the real server's answer through, signed by the host key the
  client trusts, with an answer of their own right behind it: the trusted key was approved, and the
  keys put in force were those of the answer that came last. The session then ran encrypted to them
  under the approval of the real host's key, and a password or a signature that followed went to
  them. Every version of this package before this one is affected. The strict key exchange
  extension does not prevent it: no packet is dropped or reordered.
  An exchange is now one proposal, one answer (the group first, in a group exchange) and one
  NEWKEYS, in that order and each taken once. Anything else for the exchange ends the connection
  with an `SSHHandshakeError`. The keys put in force are those of the answer whose host key was
  approved, or the connection ends. A server may not open another exchange before the client's
  NEWKEYS for the last one is out, and `SSHTransport.rekey()` waits for the same.
- A host key check (`onVerifyHostKey`) that failed with an error other than an `SSHError` left the
  connection open and waiting for ever, with the error thrown where nothing could catch it. It now
  ends the connection with an `SSHHostkeyError` that says what the check failed with.
- An approval that arrives after the connection has ended is dropped. It used to throw an error
  nothing could catch.
- **A password is sent only to a server that takes passwords.** A server says, with every sign-in
  it refuses, which ways of signing in it takes (RFC 4252, 5.1). The client read that list and
  dropped it, and tried what it had in an order of its own: every key, then the password, then
  the server's questions, then `none`. A server that had just said it takes only keys was sent
  the password all the same (seen against OpenSSH with password sign-in turned off), a server
  that lets everybody in was sent the key and the password first, and each of those tries counts
  against the tries a server allows a connection. The client now asks first, with `none`, which
  ways the server takes, and tries only those, in the same order of preference; after a step
  that the server accepts as one of several it goes on with what the server names. A way the
  server does not take at one step is kept for a later one. `SSHAuthFailError` says what was
  tried (`methodsTried`) and what the server takes (`serverTakes`), so that an application can
  tell "the key was refused" from "this server takes only keys and there was no key".
- **What an exchange agrees on is taken into use with its keys.** A key exchange on a live
  connection may agree on another cipher or MAC than the one in use (RFC 4253, 9), and each side
  takes them into use with the new keys: for what it sends from its own NEWKEYS on, and for what
  it reads from the other side's NEWKEYS on. The transport put them to use the moment the
  proposals were compared. At the first exchange of a connection nothing is in force yet, so
  nothing came of it there. At a later exchange that agreed on something else, what the client
  sent for the rest of that exchange (its start of the exchange, its NEWKEYS, and any message
  that may not wait) went out under the framing of the new algorithms with the keys of the old
  ones, or, where the old cipher checks its packets by itself and the new one does not, with no
  keys at all: in the clear. What the server sent before its NEWKEYS was read as if it were
  under the new ones. No such exchange ended well: the connection was lost at the server's
  answer. Nothing secret is in those packets (a public value of the exchange, a NEWKEYS that
  holds nothing), and only the server whose host key was approved can propose other algorithms
  on a connection, since a later proposal comes under the keys in force; a server does not
  usually change what it proposes. But a packet left the client in the clear with keys in
  force. That cannot happen any more: what protects the packets of each direction is kept apart
  from what was agreed on, is set where that direction's keys are installed and nowhere else,
  and is all that the code that packs and reads packets asks. A packet goes out in the clear
  only while no keys of its direction were ever installed. With the OpenSSH client as the judge
  of what is right: asked for new keys under each other suite, it sends its part of the
  exchange as before, and what follows under the new.
- **An RSA host key of a size no key has is refused before anything is computed with it.** The
  signature that comes with a server's host key is checked before anybody is asked whether they
  trust the key, and for an RSA key that check takes as long as whoever sends the key wants: it
  grows with the length of the modulus and with the length of the public exponent, which is
  65537 in any key that anybody makes and as long as the modulus in one that is made up. The
  transport checked a key of any size with any exponent, before the sign-in, on the isolate the
  client lives on: more than a second of a busy processor for 16384 bits with an exponent as
  long (on a desktop), eighty seconds for 65536 bits, and by that growth more than ten minutes
  for the longest key one packet holds, in which the program does nothing else. Whoever stands
  between a client and its server can send such a key in the server's place. A key is now taken
  as far as OpenSSH takes one: a modulus of at most 16384 bits, and a public exponent that is
  odd, at least 3, and at most 64 bits long. Anything else ends the connection with an
  `SSHHostkeyError` that says what was wrong with the key, before the check and before
  `onVerifyHostKey` is asked. A modulus that is even, or nought, is refused the same way (nought
  ended the connection as a "Malformed packet" with a range error in its text). A key that is
  merely short (1024 bits, 768) is checked as it was: what is too weak to trust is the
  application's to say.
- **A host key is of the kind that was agreed on, and a key that is refused is refused as a host
  key.** The two sides agree on the kind of host key the server shows, and a client takes no
  other (RFC 4253, 7.1). The transport read whatever key came by what was agreed on, with
  nothing held to it. An ECDSA key reads the same for each of its three curves, so a server
  that had agreed on one curve was taken with a key of another, also by a client that offers
  one curve only, and the key was put to whoever verifies host keys under the name of the kind
  that was agreed on. A key of another kind altogether, bytes that are no key, and a signature
  under another name than its key's did not read, and ended the connection as an
  `SSHPacketError` ("Malformed packet: ..."). So did an Ed25519 key with a signature that was
  not its own, which is the one thing a host key is there to tell: the library that checks
  such a signature says no by throwing, and that was taken for a packet that could not be
  read. An application that asks whether a connection failed over the host's key
  (`SSHHostkeyError`) was told that it had not. Now the key a server shows has to say that it
  is of the kind agreed on (`ssh-rsa` also under the two newer names an RSA signature has), an
  ECDSA signature has to be of the kind of its key and an RSA signature of the kind agreed on,
  and whatever of a host key or its signature cannot be read ends the connection with an
  `SSHHostkeyError` that says what was wrong. A signature that does not fit is "Signature
  verification failed" for every kind of key. What a server calls its key is its own text: it
  goes into the error with nothing but the characters a name has, and no longer than a name
  is. `SSHEd25519PublicKey.decode` refuses a key that is not 32 bytes long, and its `verify`
  answers false for a signature that is not the key's, of whatever length.
- **The group of a group exchange is one that can be used.** In a group exchange (RFC 4419,
  `diffie-hellman-group-exchange-sha256` and its `-sha1`) the client says how long a group it
  wants and the server names one, a modulus and a generator, and everything the session carries
  is as safe as that group. The client asked for a group of at least 1024 bits and took one of
  1024, which whoever has the means can break, and with it everything that was recorded of the
  sessions under it. It took any generator: nought and one, with which the secret is nought or
  one whatever either side does, and the modulus less one, with which it is one of two numbers.
  And it took a modulus that is an even number. Now the client asks for 2048 bits at the least
  (`SSHKexDH.gexMin`), as OpenSSH does, and the group a server names is held to it
  (`SSHKexDH.requireGroupOfAnExchange`): 2048 to 8192 bits, an odd modulus, and a generator
  that is more than one and less than the modulus less one. Anything else ends the connection
  with an `SSHKexGroupError` (it was an `SSHStateError` for the length), which says what was
  wrong, how long the group is and the shortest that is taken, and whether it was refused for
  being too short and nothing else (`tooShort`): that is what its server can mend. Whether the
  modulus is a prime is not found out, which no client does. A server that has only groups
  under 2048 bits is no longer connected to by a group exchange; OpenSSH has taken none under
  2048 bits since its release 7.2 (2016).
- **The library computes its powers itself, and gives out no RSA signature that is not the
  key's own.** `BigInt.modPow` of the Dart SDK answers wrong for some numbers (seen with Dart
  3.10.8 on x64, as a script and compiled): not for numbers picked at random, but for any odd
  modulus of 192 bits or more a base can be computed from the modulus whose powers it gets
  wrong. The other side of a connection picks the numbers that went into it here: its public
  value in a Diffie-Hellman exchange (such values exist for the groups of RFC 3526 and RFC
  2409, within what a server may send), the generator and the modulus of a group exchange, and
  the signature that is checked with an RSA host key. No way was found to use this against a
  session: a secret that is computed wrongly makes the exchange fail, and a wrong result is no
  valid signature. But the library computed with a tool that is wrong where it is told to be.
  Now a Diffie-Hellman exchange computes with the library's own arithmetic (squaring and
  multiplying with `*` and `%`, which were right for every number tried; under a millisecond
  for a group of 2048 bits on a desktop), and so does the check of an RSA signature, which is
  the library's own as well (`SSHRsaPublicKey.verify`, RFC 8017, 8.2.2): what a signature
  comes back to under the key is compared, byte for byte, with the one thing it has to come
  back to. It
  takes what OpenSSH takes and refuses what OpenSSH refuses, measured against the OpenSSH
  client of the machine the tests run on: a signature with the nought it begins with left out
  is taken, and one that is longer than the key, or that names its hash without the empty
  part of the name, is refused (the library that checked before took those two). A key too
  short to hold a signature of the kind asked for is a `FormatException` that says so (it was
  a `RangeError`).
  An RSA key signs in two halves, one for each of its primes, and a signature of which one
  half is wrong gives one of the primes away to whoever sees it and knows what was signed: a
  server sees every signature a client signs in with, and so does a host an agent is
  forwarded to. Every RSA signature a key makes (`OpenSSHRsaKeyPair.sign`,
  `RsaPrivateKey.sign`, `SSHKeyPairAgent`) is now checked with the key's public half before
  it is given out (`signRsaChecked`), and one that is not the key's own is an
  `SSHKeySignError` and goes nowhere. So is a key whose numbers do not fit each other, which
  was an error of the library that signs. A client that signs in with such a key ends the
  sign-in with an `SSHAuthAbortError` whose reason is that error, where it passed the key over
  without a word and went on to the next way of signing in; an agent answers that it could
  not sign.
- **A packet that does not pass its check is said as that, with nothing of the session's keys
  in the words, and nothing of a packet is looked into before it has passed.** Every packet
  under keys carries a check value (a MAC, or the tag of a cipher that checks its packets by
  itself), and one that was changed on the way, by a line that is failing or by whoever sits
  on it, ends the connection. What the client said of it went by the cipher: `MAC mismatch,
  expected: [...], actual: [...]` with both check values in the text, the right one for the
  changed packet among them, which is made with the session's key and went wherever an
  application puts an error's words (a log, a report somebody copies); `AEAD authentication
  failed`; or, under chacha20-poly1305, `Malformed packet: SSHMacMismatchException: ...`. An
  application could not tell such an end from a packet that the server had sent wrongly. And
  with a MAC of the older kind (`hmac-sha2-256` and the like without `-etm`, where the packet
  is encrypted whole) the client read the packet's padding before it had checked the MAC: a
  packet whose padding had been changed ended the connection as `Invalid padding:
  paddingLength=138 payloadLength=-111`, with what the packet held there in the words, of a
  packet that nothing had yet shown to be the other side's own. (Nothing of an error goes to
  the other side: the connection is closed without a word.) Now all of them end the
  connection with the same `SSHPacketError`, whose `damaged`
  says that the packet did not pass, and whose words hold nothing of the packet and say what
  is known and no more: "A packet from the other side did not pass its check: it was changed
  or damaged on the way, or the two sides do not protect their packets the same way" (keys
  that differ, or a count of packets that differs, fail the same check).
  The MAC is checked before anything of the packet is looked into. A length that no packet
  has, under keys, is said the same way (the length is read before a packet can be checked):
  one longer than any packet, and, with a MAC of the older kind, one that is no whole number
  of blocks of the cipher, which was read past its end into the MAC behind it. Before keys
  are in force a packet said to be too long is `Packet too long`, as it was.
- **The strict key exchange is held to its whole order.** Where both sides name the strict
  key exchange (`kex-strict-*-v00@openssh.com`, OpenSSH's answer to the Terrapin attack,
  CVE-2023-48795), the first exchange of a connection carries the messages of that exchange
  and nothing else, and the server's proposal is the first packet it sends. The client kept
  the second half only. A message that may come at any time (`IGNORE`, `DEBUG`,
  `UNIMPLEMENTED`) passed when it came before the server's proposal, since nothing is known
  of a strict exchange until the proposal is read: the connection was made, with the count of
  the server's packets shifted by what had been put in. And after the proposal the client let
  through every number from 30 to 49, where a server answers an exchange under 31 (and 33 in
  a group exchange): a message under another of those numbers was handed to the application
  once the host key had been looked at. Now a strict proposal that is not the server's first
  packet ends the connection, and so does every message in the first exchange that is not the
  proposal, the answer (the group and the answer, in a group exchange), `NEWKEYS` or a
  `DISCONNECT`. Both end it with an `SSHHandshakeError` whose `strictOrderBroken` says so. The
  two OpenSSH clients this was measured against (9.8p1 and 9.5p2 for Windows) end a
  connection whose strict proposal comes after an `IGNORE` ("KEXINIT was not the first
  packet"), and pass the same `IGNORE` over where the server names no strict exchange, as
  this client does. No way was found to use what was let through: the count of packets
  starts again at every `NEWKEYS` under the strict exchange, which is what defeats the attack
  and was complete before. Exchanges after the first are not held to this, as OpenSSH has it.
- **A trace does not print the answers to a server's questions.** A trace (`printTrace`) prints
  every message the client sends, and the message that carries the answers to a server's
  questions (keyboard-interactive: a password, a one-time code) printed the answers:
  `SSH_Message_Userauth_InfoResponse(responses: [...])`. It prints how many there are now
  (`responses.length=2`), as a message of channel data prints its length and not its data. The
  message that carries a password never printed it. A program that does not set `printTrace`
  was not affected.

- **A group exchange asks for a group of 3072 bits.** In a group exchange the client says how long a
  group it would like, and a server names the shortest it has that is at least that long. The
  client said 2048 bits, the shortest it takes at all, so a server with longer groups too (OpenSSH
  ships them from 2048 to 8192 bits) named its weakest: about 112 bits of work to break, where
  every other key exchange this client offers stands at 128 or more, and the secret the client
  brings to a group exchange is made for 128. `SSHKexDH.gexPref` is 3072 now; the shortest group
  that is taken (2048) and the longest that is asked for (8192) are as they were. A real OpenSSH
  server named a group of 2048 bits before and names one of 3072 now
  (`test/kex/gex_group_length_interop_test.dart`). The client's debug lines say how long the group
  is that a server named (its length only).

### Fixed

- **An RSA key signs in with the kind of signature the server takes.** An RSA key makes three
  kinds of signature (RFC 8332): with SHA-512, with SHA-256, and the first kind, with SHA-1
  ("ssh-rsa"). The client signed with SHA-256 whatever a server had said, so an RSA key was
  refused by a server that takes only SHA-512 (measured on OpenSSH 10.2 with
  `PubkeyAcceptedAlgorithms rsa-sha2-512`) and by one that knows only the first kind, as an
  OpenSSH older than 7.2 does, with nothing to say why. Now the key is asked about with the
  first of `SSHAlgorithms.rsaSignatures` (new: `rsa-sha2-512`, `rsa-sha2-256` unless you say
  otherwise) that the server lists in its "server-sig-algs". Where the server lists none of
  them, the key is not asked about at all, and a refused sign-in says so:
  `SSHAuthFailError.keysPassedOver` and `serverSignatureAlgorithms`. Where the server has not
  said what it takes, the key is asked about with SHA-256 as before, and then, if you have put
  `ssh-rsa` into `rsaSignatures`, with that; not with SHA-512 as well, since a question a server
  refuses is one of the tries it allows. `OpenSSHRsaKeyPair` and `RsaPrivateKey` sign with the
  kind they are made for (`type`, `signingAsRsa`); what wraps a key pair and signs with it (a
  certificate, a key in an agent) takes part by implementing `SSHRsaSignatureChoice`.
  `SSHRsaSignatureType` is exported. A key of another kind is asked about as before, whatever
  the list says.
- **A key signs only for a server that has said it takes the key.** To sign in with a key, the
  client signed at once and sent the signature with its request: every key it had signed for
  every server that takes keys at all. An agent was asked and a hardware key touched for each of
  them, and where an agent would not sign (a hardware key nobody touched), the sign-in ended
  there, over a key the server would not have taken. The client asks first now, as the protocol
  provides (RFC 4252, 7): the request goes out with no signature, and the key signs once the
  server has answered `SSH_MSG_USERAUTH_PK_OK` for it. A key the server refuses is passed over
  with nothing signed. A yes is taken for the key it names: one that names another key signs
  nothing, and the kind of signature named beside the key is not held against it, since a server
  may put the key's own kind there ("ssh-rsa" where "rsa-sha2-256" was asked). A yes with no
  question open (a second one, or one after the sign-in has ended) is passed over, so a key signs
  once for each time it is asked about. A real OpenSSH server counts a question it refuses as one
  failed try, as it counted a signature it refused, and a question it says yes to as none; it
  writes "Postponed publickey for ..." and then "Accepted publickey for ...", as it does of its
  own client.
- **A client that closes its connection says so first.** `SSHTransport.close()` (and with it
  `SSHClient.close()`) destroyed the socket and said nothing, so a server wrote "Connection
  closed by ..." of every session that was simply ended, which is what it writes of a
  connection that broke. Where its keys are in force the client now sends `SSH_MSG_DISCONNECT`
  first (RFC 4253, 11.1; reason 11, by application: "disconnected by application"), gives the
  socket up to two seconds to send it, and closes it then; a real OpenSSH server writes
  "Received disconnect from ... port N:11: disconnected by application" where it wrote
  "Connection closed by ...". Nothing is said before keys are in force, nothing while the
  socket is being drained, and nothing where the connection ends over an error
  (`closeWithError`): what was wrong with a connection is not told to the other side. `done`
  completes at once, as before.
- **What is thrown once a host key was approved ends the connection.** When the key a server
  showed is approved, the client sends its `NEWKEYS`, puts its keys in force and calls
  `onReady`, in what follows the approval. Whatever was thrown there (the write of `NEWKEYS`
  failing on a socket that had gone, or `onReady` itself throwing at its first request) had
  nobody to catch it: it became an error of the zone, the connection stayed open, and whoever
  waited for a sign-in waited until their own time limit. It ends the connection now, as it is
  where it is one of this package's errors, and otherwise as an `SSHStateError` with what was
  thrown in its words.
- **A version string that arrives in pieces is put together.** The client read the server's
  version line once, from whatever the first read brought, and ended the connection with "Version
  exchange not terminated" when the line had not ended yet. On a slow link, or through a proxy
  that passes data on as it reads it, a banner comes in more than one piece: a connection that
  failed now and then for no reason anyone could see. The line is now taken when it has ended,
  however many reads that takes.
- Lines a server sends before its version string are passed over, as RFC 4253 (4.2) allows a
  server to send them. They were taken for the version string and the connection was refused with
  "Invalid version". A line that begins with `SSH-` is still the version string, and still has to
  be SSH-2.0 or SSH-1.99.
- Both are bounded: a line of more than 10240 bytes, or more than 32768 bytes of lines before the
  version string, ends the connection with an `SSHHandshakeError`.
- **A request that waits for a reply ends when its channel or its connection does.** A request on
  a channel that asks for the server's answer (a terminal, a shell, a command, a subsystem, an
  environment variable, X11 or agent forwarding) waited for that answer for ever when the channel
  ended first, and so did a request to the server as a whole (`forwardRemote`,
  `cancelForwardRemote`, `ping`) when the connection ended. Whoever had asked never heard anything
  again. Such a request now fails: with what ended the connection, as the connection says it (an
  `SSHSocketError`, or an `SSHStateError` "Connection closed before the request was answered"
  where it closed with no error), or, where the server closed the channel without answering and
  the connection is still there, with an `SSHChannelRequestError`. A request made on a channel
  that has ended fails at once, and nothing is sent for it.
- A channel that was still being opened when the connection ended fails with what ended the
  connection too. It failed with "Connection closed while waiting for channel open" whatever had
  ended it, so a network that broke at that moment read as a connection that had closed by
  itself. That message is still what it fails with where the connection closed with no error.
- `SSHClient.sftp()` and `SSHClient.subsystem()` wait for the server's answer to the subsystem
  request, and throw an `SSHChannelRequestError` that names the subsystem when the server refuses
  it. They went on without looking at the answer: on a server with no SFTP, `sftp()` returned a
  client whose every request waited for ever.
- A channel on which the server refused what it was opened for is closed in full. It was closed
  half way, to be finished when the server closed its side, which a server does not do for a
  session in which nothing was started: the channel stayed open there for as long as the
  connection lasted. OpenSSH allows one connection ten sessions unless told otherwise, so after
  ten refusals (a terminal a key may not have, an environment variable the server does not take)
  nothing more could be opened on that connection.
- The X11 forwarding request carries its screen number as the uint32 RFC 4254 (6.3.1) says. It
  was sent as a string, which a server that reads the request by the RFC cannot parse: OpenSSH
  ends the connection over it.
- A keep-alive whose `ping` fails (the connection ended with it on its way) no longer throws out
  of its timer, where nothing could catch it.
- **Text from a server that is not UTF-8 no longer ends the connection.** What a server writes
  for a person to read (its notice before sign-in, the questions of a keyboard-interactive
  sign-in, the prompt for a new password, why it disconnects, why it opens no channel, what a
  killed program ended with, why an SFTP request failed) was read as strict UTF-8, and one byte
  that is none was taken for a packet that cannot be read: the connection ended, or, for an SFTP
  status, the whole SFTP session. A server whose notice is kept in an older encoding could not
  be signed in to at all. Such text is read as far as it can be now, with U+FFFD where a byte
  could not be read. The names the protocol itself defines (request types, algorithms) are held
  to UTF-8 as before.
- **A server that ends the connection and says why is heard.** Before it closes a connection of
  its own accord, a server sends SSH_MSG_DISCONNECT, with a reason code and a reason in words
  ("Too many authentication failures", a limit on idle time, an administrator's notice). The
  transport handed the message on, where nothing read it, and the connection then ended with the
  socket: `SSHClient.done` completed as for a connection that was closed, and `authenticated`
  failed with "Connection closed before authentication" and no reason. The connection now ends
  with an `SSHDisconnectError` that carries the code and the words, and whatever waited on it
  fails with that (`SSHAuthAbortError.reason` while signing in). The error also says whose words
  they are (`authentic`): the server's own only where the message came under keys whose host key
  was approved. The message may come at any time, and one in the clear, or under the keys of a
  host key that is still being looked at, can be anybody's on the way to the server: an
  application should show its words as that. A message without the language tag, as some servers
  send it, is read as OpenSSH's own client reads it.
- **How a program ended is known when it ends at once.** A server says how a program ended (its
  exit status, or the signal that ended it) in a request on the program's channel, right before it
  closes the channel. `execute` and `shell` made the `SSHSession`, which takes such requests, only
  after they had waited for the server's yes to the program. For a program that ends at once
  (`true`, `exit 3`, an account whose shell prints a notice and leaves) the yes and the end can
  come in one read, and mostly do on a slow link or through a tunnel: the request found no session
  and was dropped, and `exitCode` and `exitSignal` stayed null for a program that had failed. The
  session is now there before the program is asked for.
- **Keep-alives notice a connection that has gone quiet.** A keep-alive was sent every
  `keepAliveInterval`, and nothing looked at whether anything came back: a connection whose other
  side was gone (a network that drops everything, a host that froze) stayed open for as long as
  the system held it to be, which can be very long. When three keep-alives in a row
  (`keepAliveMaxUnanswered`, as OpenSSH's ServerAliveCountMax) go by with nothing at all coming
  from the server, the connection now ends with an `SSHNoAnswerError`, and whatever waited on it
  fails with that. A server is judged this way only once it has answered a keep-alive on the
  connection: a device that answers none (against RFC 4254, which wants an answer to every
  request that asks for one) is left alone, as it was. What is counted is keep-alives, not time,
  so a device that slept does not find its connections dead on waking for that alone.
- **An SFTP session that ends, ends for everyone who waits on it.** `SftpClient` listened to its
  channel for data and for nothing else. When the channel ended (the connection dropped, or the
  server's SFTP server ended), a request that waited for its reply waited for ever, and so did
  every request made afterwards, and after the client itself had been closed: a transfer under
  way never returned. A session that ended before the server's first packet left the handshake
  unanswered, on which every request waits first. Each of these fails now: with what ended the
  connection where that is why (`SSHChannel.endedBecause` says it), and with an `SftpAbortError`
  where the server closed the session or it was closed from here. Nothing is sent for a session
  that is over, and what a server goes on sending to one is dropped.
- What a server sends first that is no SFTP ends the session with an `SftpNotSftpError`, which
  carries the start of what came. Most often it is text the account's shell prints when a
  session starts; it was read as a packet length, and every request then waited for ever on a
  handshake that never came. (OpenSSH's own client says "Received message too long" of it.)
- What is not waited for in an SFTP session no longer fails at nobody: the close of an
  `SftpFile` in a session that is over, or that ends with the close on its way (there is nothing
  left to close, and it completes), and the reads a download had asked for ahead when an earlier
  one failed or the session ended. A session torn down over a packet that could not be read
  threw an error nothing could catch as well, and its channel is now torn down with it.
- A second version packet from an SFTP server ends the session with an `SftpError` that says so.
- **A file the server reports no size for is read to where it ends.** `SftpFile.read` (and
  `readBytes`, `downloadTo`, `SftpClient.download`) with no length asked the server for the
  file's size and read that many bytes. Linux reports no size for what the kernel makes up as it
  is read: everything under /proc came out empty. Such a file is now read to where the server
  says it ends: one piece is asked for, and for each that comes back whole twice as many may be
  on their way. A server that reports no size at all was an error ("Can not get file size"), and
  so was an offset past the end of a file; neither is now. A size the server does report bounds
  the read as before, so a file that is being written is read as far as it went when its size
  was asked, and is not followed; and the read ends sooner where the file does (the few bytes
  that Linux reports as a whole page, under /sys).
- A piece of a file that comes back short ends the read there: what had been asked for ahead of
  it is past the end, whatever the server answers for it (a file that was cut short and written
  again while it was read came out with a gap in it). And a server that answers a read with more
  bytes than were asked for is refused with an `SftpError`: taken as it was, the file came out
  with bytes in it twice, and was called done.
- **A server's no to agent forwarding ends no session.** With an `agentHandler` set, the client
  asked for agent forwarding at the start of every session and gave the session up when the
  server said no ("Failed to request agent forwarding"). A server says no for one of two reasons,
  and neither is one to give a session up for. OpenSSH sets the agent up once for a connection,
  for every session on it, and says no to setting it up again: on a server that allows agent
  forwarding, the first session of a connection started and every one after it failed. And a
  server that allows none (`AllowAgentForwarding no`, or a key marked `no-agent-forwarding`)
  could not be used at all with an agent set. A session now starts whatever the answer, as it
  does with OpenSSH's own client, which does not wait for it. The answer is kept for the
  connection: after a no the server is not asked again, and a server that says yes each time
  goes on being asked.
- **A channel whose reader stops for a while goes on when the reader comes back.** How much the
  other side may send on a channel (its window) is opened again as what came is read, and is held
  where it is while nobody reads, so that no more than a window's worth waits in memory. It was
  opened again only when more data came, and only while some of the window was left. Where the
  other side had used the window up to its last byte while the reader was stopped, or had not
  begun to read yet, nothing more could come to open it by: the channel stood still for good,
  with no error. Against OpenSSH, a program that prints eight megabytes, read by someone who
  stops for a second after the first piece, stood still at 2129920 bytes. The window is now
  opened again when a reader begins and when one comes back, by as much as has come since.
  Whoever reads a channel no faster than it can pass the data on (`addStream` into a socket, a
  download written to a slow disk) relies on this.
- **An upload whose source fails, fails.** `SftpFile.write` listened to the stream it was given
  for its data and its end, and for nothing else. Where that stream failed (a file on a stick
  that is pulled out, a file that another program holds), the error went to nobody, the stream
  ended behind it, and the writer's `done` completed without a failure, with as much written as
  had come: whoever uploaded a file was told that it was done. `done` now fails with what the
  stream failed with, at once, and the stream is let go of.
- **A listing that does not reach its end closes its directory.** `SftpClient.readdir` (and
  `listdir`, which reads it) closed the directory's handle where the listing had been read to its
  end, and nowhere else: a listing that the server refused half way, and one whose listener
  cancelled, left the directory open on the server for as long as the session lasted, and a server
  lets a session hold only so many. Both now send the close. What the server answers to it is not
  waited for and fails nothing: the listing has failed with what it failed with. A listing that is
  read to its end is done when the server has answered the close, as before.
- `SftpClient.isClosed` says whether the session is over (closed from here, closed by the server,
  or gone with its connection). There was no way to ask but to make a request and see it fail.
- A list of names with nothing in it (RFC 4251, 5) is read as no names. `SSHMessageReader.readNameList`
  read it as one name that is empty, so a server that takes no way of signing in any more, or
  offers no language, was read as offering one with no name.
- `SSH_Message_Userauth_Request.decode` reads a request as `encode` writes it: a request to sign
  in with a key was read without the flag that says whether a signature follows (nothing after it
  was read as what it is), and a request to change a password with the old and the new one
  exchanged. (A client does not read these; whoever plays a server to it does.)
- **An error says its own name in an obfuscated build.** The errors (`SSHAuthFailError`,
  `SSHKeyDecryptError`, `SSHNoAnswerError` and the others of `ssh_errors.dart`) and the exceptions
  of `ssh_exceptions.dart` printed the name the program has for their type (`runtimeType`) with
  their message. A program that is built with its names obfuscated, as a released Flutter app
  most often is, has another name for nearly every type: there
  `SSHAuthFailError(All authentication methods failed)` printed as
  `Ei(All authentication methods failed)`. That is what a person then read in a log, and a program
  that tells failures apart by the name in the text found the name in every test and never in the
  build it shipped. Each kind now spells its name out (`typeName`, which the text begins with), so
  what an error prints is the same however the program was built. A class made from one of them
  says the name of what it was made from unless it gives its own; a class that mixes in
  `SSHMessageError`, or extends `SSHException`, without giving one says `SSHError` or
  `SSHException` where it said its own class's name. A test builds a program obfuscated and reads
  what every one of them prints there (`test/src/ssh_errors_said_test.dart`).
- **So does everything else that printed the program's name for its type.** The algorithms a
  connection agreed on (`SSHKexType`, `SSHHostkeyType`, `SSHCipherType`, `SSHMacType`), which
  the client's debug lines print: `SSHTransport._kexType: SSHKexType(curve25519-sha256)` was
  `SSHTransport._kexType: il(curve25519-sha256)` in a program built obfuscated. Four messages a
  trace prints (the group and the reply of a group exchange, a server's questions and the
  answers), a question (`SSHUserInfoPrompt`), the keys and what a key file is made of
  (`OpenSSHKeyPairs`, `OpenSSHBcryptKdfOptions`, the four `OpenSSH...KeyPair`,
  `RsaKeyPairDEKInfo`, `RsaPrivateKey`, `SSHPem`), `SftpFileMode` and `SSHRemoteForward`. Each
  spells its name out now; an algorithm has a `typeName` as an error has, and a kind of
  algorithm that gives none says `SSHAlgorithm`. `SSHForwardChannel`, which a client that goes
  through a jump host has for its socket and names in its debug lines and its trace, wrote no
  text of its own and so printed `Instance of 'SSHForwardChannel'` (`Instance of 'Qk'` built
  obfuscated): it prints `SSHForwardChannel(SSHChannel(3:7))`. Nothing in `lib/` asks the
  program for the name of a type any more, and the test that builds a program obfuscated reads
  what each of these prints there too.
- `SSHChannel.remoteChannelId` gave the channel's own number, where it is documented to give the
  number the other side has for the channel. A channel so printed its own number twice
  (`SSHChannel(3:3)`). Nothing else in the package read it.
- **What is thrown while a message is handled is said of that message.** Whatever was thrown
  while what came over a connection was handled, and was none of the package's own errors, ended
  the connection as `SSHPacketError('Malformed packet: ...')`. That was said also where the packet
  was a good one and what failed was the client's own handler of it, or something an application
  had asked to be told of (an `onUserauthBanner` that throws), and where it was thrown in the
  exchange of versions, before any packet had come: whoever read it went looking for what the
  server had sent wrong. A packet that cannot be taken off the line, or has no message in it, is
  a `Malformed packet` as before. Once the message is known by its number, the error says
  `Message 53 could not be read or handled: ...` (an `SSHPacketError` still): what was thrown may
  come of the message, a field cut short, or of what handles it, and the transport cannot tell
  which. What is thrown in the exchange of versions ends the connection with
  `SSHHandshakeError('The version exchange failed: ...')`.
- **AES-GCM packets are counted from the keys.** Under `aes128-gcm@openssh.com` and
  `aes256-gcm@openssh.com` every packet has a nonce of its own: the one the keys give, counted on
  by one for each packet since those keys were taken into use (RFC 5647, 7.1). The transport
  counted by the number of the packet. The two are the same where packet numbers start again
  with the keys, which is under the strict key exchange and nowhere else. With a server that
  does not have the strict exchange (OpenSSH before 9.6 where it was not added to an older
  version, and servers that are not OpenSSH), the client's first packet under keys went out with
  the nonce three further on, the server's first was read with the one three further on, and
  neither side could read the other: the connection ended right after the key exchange, with
  "AEAD authentication failed" here or "message authentication code incorrect" there. After new
  keys in such a session the count did not start again either. Each direction now has a count
  of its own, which starts with its keys. chacha20-poly1305, whose nonce is the number of the
  packet, is as it was. AES-GCM is not in the default proposal, so this was met by whoever asked
  for it and by nobody else. Seen with the OpenSSH client as the judge: it counts from the keys,
  and ends the connection with a server that counts by the number of the packet.
- **A MAC is said only where one is used.** What a client says it agreed on
  (`SSHClient.diagnostics.negotiatedMac`, `SSHEventKexStarted.mac`, and
  `SSHTransport.onKexNegotiated`) named the MAC that the two proposals had in common also where
  the cipher checks its packets by itself (chacha20-poly1305, AES-GCM) and no MAC is used, and
  the word "none" where the proposals had none in common. An application that shows a
  connection's algorithms showed, beside chacha20-poly1305, a MAC that protected nothing of it.
  It is empty there now. For a cipher with a MAC beside it nothing changes, and the cipher and
  the MAC that are said are still those of what the client sends.

### Added

- **A key exchange with nothing in common says what each side offered.** Where the two sides have
  no algorithm of one kind in common, the connection ends with an `SSHHandshakeError` whose
  message says which kind ("No matching client cipher algorithm"), as before. It said nothing of
  what either side had offered. It carries both now: `offered`, what this side offered of that
  kind, and `otherSideOffered`, what the other side did, each in its order and without the two
  marks a proposal carries among its key exchanges (`ext-info-*`,
  `kex-strict-*-v00@openssh.com`); `nothingInCommon` says that this is why the handshake ended.
  What the error prints is unchanged: the other side's names are its own text, and whoever shows
  them keeps of them what a name can be. An application can tell from the two lists whether
  another set of algorithms of its own would find something in common, and need not try such a
  server again as it is (`test/src/ssh_nothing_in_common_test.dart`).
- `tool/test_sshd.sh` starts two more servers, each of which takes one kind of signature from an
  RSA key (the one with SHA-512; the first one, with SHA-1), and makes an RSA key they know
  (`client_bare_rsa`): for `test/src/ssh_rsa_signature_kind_test.dart`.
  `RealOpenSshServer.sha512Only()` and `sha1Only()` find them.
- **A server is asked which signatures it takes, and what it says is kept.** The first proposal
  of a connection names `ext-info-c` (RFC 8308), and what a server then says of itself with
  `SSH_MSG_EXT_INFO` is read: `SSHClient.serverSignatureAlgorithms` and
  `SSHTransport.serverSignatureAlgorithms` are its "server-sig-algs" list (null where it has not
  said, empty where it takes none), `SSHTransport.serverExtensions` and
  `SSHConnectionDiagnostics.serverExtensions` the names of what it said (the second was never
  filled in before), and `SSHTransport.onExtInfo` is called when it has said something. The
  message comes right after the server's `NEWKEYS`, which is while the host key may still be
  looked at, where the client took nothing but the four messages that may come at any time and
  ended the connection over any other: it is taken under the server's keys only, kept, and
  handed to nobody, and nothing of it is used before the host key is approved. Where a server
  says it again, what it says last holds. Only what the protocol calls a name is kept of a
  server's text (RFC 4251, 6). Nothing signs in differently yet: an RSA key still signs as
  rsa-sha2-256 whatever the list says. `SSH_Message_ExtInfo` is the message;
  `PlayedServer.exchangeKeys`, `greet` and `letIn` take `afterNewKeys`, what a played server
  says right after its `NEWKEYS` in the same read, and `PlayedServer.clientProposals` is what
  the client proposed (`test/src/ssh_ext_info_test.dart`).
- `SSH_Message_Userauth_PkOk`: a server's yes to a question about a key (RFC 4252, 7).
  `PlayedServer.takesKey(question)` says it in a test, and `PlayedServer.sessionId` is what a
  key signs along with a sign-in, for a test that checks the signature it was sent
  (`test/src/ssh_publickey_asked_first_test.dart`). `test/src/real_openssh_server.dart` finds the
  first server `tool/test_sshd.sh` starts and reads what it wrote of one connection in its log.
- `tool/test_sshd.sh` starts the two local OpenSSH servers the integration tests log in to (one
  of them asks for new keys every megabyte), as the ordinary user on the loopback address. The
  tests name no user and no machine any more: they find the servers by the script's variables.
  It makes three client keys: one that may do what the account may, one the servers give no
  terminal and no agent forwarding, and one they give everything but agent forwarding, for the
  tests of what the client does when a server refuses those (`test/src/ssh_waiters_test.dart`,
  `test/src/ssh_agent_refused_test.dart`).
- `SSHClient.keepAliveMaxUnanswered` (three unless set), `SSHNoAnswerError`, and
  `SSHTransport.bytesReceived`, which says how much has come from the other side.
- `SSHDisconnectError`: the reason code and the words of a server that ended the connection,
  and whether they are the server's own (`authentic`).
- `SSHSession.endedBecause`: what ended the connection, where that is why the session ended (its
  program was cut off, and how it would have ended is not known). Null for a session that was
  closed in order, by the server or from here: with no `exitCode`, that is a server that reports
  none.
- `test/src/played_server.dart`: a server played by a test to a real `SSHClient` (the versions,
  a key exchange, a sign-in, and then whatever the test says, message by message), for what no
  real server does when a test wants it: an answer and what follows it in one read, a refusal a
  real server never gives. It is played to whoever is made on its socket (`PlayedServer.socket`,
  then `letIn`), so an application can play it to its own connection code, and it has nothing of
  a test framework in it. And a fourth test key (`tool/test_sshd.sh`), which runs one command
  whatever is asked for, a shell too: it prints a word and ends at once.
- `SftpClient.posixRename` puts a file in the place of another in one step, as rename(2) does
  (OpenSSH's `posix-rename@openssh.com`), and `SftpClient.canPosixRename` says whether the
  server has it. SFTP's own rename is refused for a name that is taken by most servers, so a
  file could only be replaced by removing it first, with a moment in which there is none.
- `SftpClient.open` takes the attributes a file that it makes is to be made with (`attrs`): a
  file that only its owner may read is that from the moment it is there, and not once its
  permissions are set afterwards.
- A third test server, whose notice before sign-in is in ISO 8859-1, with a test that signs in
  to it (`test/src/ssh_server_text_test.dart`).
- A connection passed on to another host (`SSHClient.forwardLocal`, what a jump host is made
  of) is tested against real servers for the first time (`test/src/ssh_forward_local_test.dart`):
  a whole connection through it, and what the server answers when it does not open the way,
  which an application tells its person apart by: reason code 1 where it passes no connections
  on, reason code 2 where it could not reach the other host itself, with its own words. For
  that, a fifth test key that may open no connection on, and a fourth test server, which allows
  one failed sign-in and ends the connection, saying why, at the first key it does not know
  (`tool/test_sshd.sh`).
- The second test server has SFTP (the first has none, for the tests of a server without it),
  and SFTP is tested against it for the first time: a file of three megabytes written and read
  back, and a session ending under its requests (`test/src/sftp/sftp_real_server_test.dart`).
- A test that holds when closing the sink of a forwarded channel (`SSHForwardChannel.sink`) is
  over: once everything written to it has been sent, and not while some of it waits for the other
  side to take more. Whoever hands a forwarded connection on waits for that before it ends the
  channel, so that the end of what was sent is not cut off.
- `SSHClient.onAgentForwardingRefused` is called, once for a connection, when the server refuses
  agent forwarding (it said no, and had not set the agent up before), and
  `SSHClient.agentForwardingRefused` says so afterwards: for an application to tell its person
  that the agent is not there on that host.
- Integration tests of later key exchanges on a live session against OpenSSH, asked for by either
  side (`test/kex/rekey_interop_test.dart`).
- The server a test plays to the client (`test/src/played_server.dart`) speaks any of five suites
  (aes256-ctr with hmac-sha2-256 or with its "etm" kind, aes256-cbc, aes256-gcm,
  chacha20-poly1305), one for each direction if a test wants that, with the strict key exchange
  or without it, and asks for new keys under another suite. What it reads from the client it
  reads under the keys in force and nothing else, and says so where a packet came in the clear.
  And it is held to a client that was not written with it
  (`test/src/played_server_openssh_test.dart`): the OpenSSH client of the machine goes through a
  key exchange with it, signs in, runs a command and is asked for new keys, for every suite and
  every change from one to another. Where a machine has no OpenSSH client those tests are
  skipped. The client is started so that it reads no configuration, no agent and no key of
  whoever runs the tests (`test/src/played_openssh_client.dart`), and its own account of what it
  looked at is checked for that. A played server shows the host key a test gives it
  (`PlayedHostKey`): a key of another kind from a key file, or numbers that are no key at all.
- `SSHHostkeyError.fault` says what the library found wrong with a host key that it refused by
  itself (`SSHHostkeyFault`): `notSigned` for a key that did not sign the exchange it came with,
  which is what somebody who answers in a host's place cannot do; `noKey` for what is no key a
  server has (another kind than was agreed on, a size no key has, a signature of another kind
  than its key's, bytes that do not read as a key); and `changed` for another key than the
  connection began with, shown when new keys are taken. It is null where whoever verifies host
  keys said no (`onVerifyHostKey`) or could not say, and for an error an application makes of
  its own. `SSHHostkeyError.duringRekey` says when the key was refused: at the start of a
  connection, which was sent nothing then, or when new keys were taken on one that was open,
  which had gone on under a key that was accepted. An application can say all of that to its
  person without reading the error's words. That a connection keeps its host key at every
  later exchange, which had no test, has tests now (`test/src/ssh_hostkey_fault_test.dart`):
  the played server shows another key when it asks for new keys if a test wants that
  (`PlayedServer.rekey(hostKey: ...)`).
- `SSHPacketError.damaged`. The played server of the tests can send packets that were changed
  on the way (`PlayedServer.sendChanged`, with `PlayedSuite.checkLength` for where a packet's
  check value begins) and bytes that are no packet (`sendRaw`).
- `SSHHandshakeError.strictOrderBroken`. The played server of the tests can put messages
  into a first exchange where none belongs (`PlayedServer.exchangeKeys(first:, beforeAnswer:,
  beforeNewKeys:)`).
- `SSHKeySignError`, and `signRsaChecked`, which signs with an RSA key and checks the signature
  before it gives it out. The OpenSSH client a test starts against a played server can be
  shown a host key of the test's (`OpenSshClient.connect(hostKey: ...)`), which is how the
  check of an RSA signature is held to what OpenSSH takes
  (`test/src/ssh_hostkey_rsa_signature_openssh_test.dart`).
- `test/src/played_group_exchange.dart`: a server that offers a group exchange and nothing else,
  played to a client as far as the group it names: what the client asked for, and whether it
  went on with the exchange or ended the connection (`test/src/ssh_kex_gex_group_test.dart`).
  An application can play it to its own connection code.

- `MlKem768` is exported from the library. It is the ML-KEM-768 (FIPS 203) implementation the
  post-quantum key exchanges already use, by itself: key generation, encapsulation and
  decapsulation, with the sizes as constants. For an application that builds its own hybrid key
  agreement next to X25519 (ZestSSH's session sharing does).

## 0.2.1 - 2026-09-23

### Agent forwarding

- The forwarded agent signs asynchronously, so hardware-token and agent-backed keys (whose
  synchronous `sign()` throws) can answer a forwarded request. A key that refuses (a declined touch,
  a locked token, a local agent that went away) now returns a plain agent failure instead of an
  error, so the requester can try its next key.
- New `SSHWrappedKeyPair` interface for a key pair that presents other public material than the key
  it signs with, such as an SSH certificate wrapping a private key. The agent unwraps it, so an RSA
  sign request gets the hash it asked for (the server refuses any other).

## 0.2.0 - 2026-09-22

### Post-quantum key exchange

- `mlkem768x25519-sha256` (OpenSSH 9.9+ default) and `sntrup761x25519-sha512` plus its
  `@openssh.com` spelling (OpenSSH 9.0 to 9.8 default) are implemented and offered FIRST by
  default. Both are hybrids: the post-quantum KEM secret and the X25519 secret are hashed together,
  so a session is only as weak as the stronger of the two, and a recording of it cannot be
  decrypted by a future quantum computer. An older server that lists neither simply falls through
  to the classic exchanges.
- ML-KEM-768 is a pure Dart implementation of FIPS 203, checked against the NIST ACVP vectors
  (key generation, encapsulation, decapsulation including implicit rejection). Streamlined NTRU
  Prime 761 is a port of the public-domain reference (supercop-20240808 compact kem.c, as vendored
  by OpenSSH), keeping its data-independent control flow. Both verified end to end against an
  OpenSSH 10.2 server.
- `SSHKexType.isHybridPostQuantum` / `SSHKexType.isPostQuantumName` for callers that want to show
  it.
- `curve25519-sha256` (the RFC 8731 name) is now offered next to the `@libssh.org` one.

### Fixed

- Incoming-packet padding was validated with the AEAD alignment rule as soon as ChaCha20-Poly1305
  or AES-GCM was NEGOTIATED, before NEWKEYS, so a cleartext KEX reply whose payload length made the
  two rules differ was rejected with `Invalid padding length`. Seen with `ecdh-sha2-nistp256` and an
  Ed25519 host key against OpenSSH 10.2. The rule now follows the cipher actually in force.

### Changed

- The shared secret is carried in its wire encoding (`mpint` for the classic exchanges, `string`
  for the hybrids) through `SSHKexUtils.computeExchangeHash` and `deriveKey`; callers that used
  those helpers directly pass the encoded bytes now (`encodeSharedSecretMpint` /
  `encodeSharedSecretString`).

## 0.1.0 - 2026-08-19

First public release of the fork. Forked from dartssh2 `2.14.0`.

### Hardened defaults

Weak algorithms are still implemented, but a connection no longer offers them unless the caller opts
in with a custom `SSHAlgorithms` profile.

- Removed from default key exchange: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `diffie-hellman-group-exchange-sha1`. SHA-1 is collision broken, so strong defaults must not be
  negotiable down to it.
- Removed from default host keys: `ssh-rsa` (SHA-1 signatures).
- Removed from default ciphers: all CBC modes (CVE-2008-5161 plaintext recovery when not paired with
  ETM MACs).
- Removed from default MACs: `hmac-md5`.
- Encrypt-then-MAC variants are preferred over plain HMAC, and AES-256 is preferred over AES-128.

### Added

- `chacha20-poly1305@openssh.com` AEAD cipher.
- Strict key exchange (`kex-strict-c-v00@openssh.com`), which is the mitigation for Terrapin
  (CVE-2023-48795).
- SSH certificate authentication.
- Ed448 host key support (implemented, not offered by default).
- AES-GCM ciphers (implemented, not offered by default).
- Client identification string `zest_ssh_core_<version>`, so this library is identifiable in server
  logs and scan results rather than being attributed to upstream.

### Security fixes

- ECDH now validates the peer's public key before using it: the point must be well formed, not the
  point at infinity, and actually on the negotiated curve. Without this check a malicious server can
  mount an invalid-curve attack and recover the ephemeral private key over repeated connections. A
  degenerate shared secret (0 or 1) is also rejected.
- One-time Poly1305 keys are zeroed immediately after use.
- SFTP read no longer loses data when a server returns fewer bytes than requested. The protocol
  explicitly permits a short read; the previous loop advanced its offset by the full requested length,
  so the gap was never re-requested and the download was silently truncated. Merged from upstream.
- P-521 ECDH private scalars are drawn from the full 521-bit range. The previous byte calculation
  produced 520 bits. Merged from upstream.

### Deliberately not taken from upstream

- The per-handshake `Isolate.run` offload of key exchange (upstream 2.20.0 through 3.3.0). Spawning an
  isolate per connection costs several times more than the curve operation it hides, and it can lose a
  race against a server's handshake timeout (upstream issue #226). This fork computes X25519 and the
  NIST curves synchronously, which is what upstream reverted to.
