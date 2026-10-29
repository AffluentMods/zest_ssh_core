# Security assurance case

Why zest_ssh_core meets its security requirements: what it protects, against whom, where the trust
boundaries are, and how its design and checks counter the usual weaknesses of an SSH client. The
details are in [ARCHITECTURE.md](../ARCHITECTURE.md) and in the code it names.

## What it protects

- **Confidentiality and integrity of a session** between the client and an SSH server: commands,
  output, files and forwarded traffic.
- **The user's credentials:** private keys, passwords and one-time codes are sent only to the
  server that proved its host key, and only in the way the server asked for.
- **Recorded traffic against later decryption,** including by a quantum computer, through hybrid
  post-quantum key exchange.

## Threat model

- **A network attacker** who can read, change, drop, reorder or inject traffic between the client
  and the server (on-path, man-in-the-middle).
- **A hostile or broken server** that sends malformed, oversized or out-of-order data.
- **Out of scope:** an attacker who already controls the client's device or the server itself, and
  the application around the library (how it stores keys and known hosts).

## Trust boundaries

1. **Everything from the socket is untrusted** until the key exchange has finished under a host key
   the caller approved. Until then the transport takes only the messages of the exchange itself
   (and disconnect, ignore, unimplemented and debug).
2. **The host key is trusted only by the caller.** The library verifies the signature and the key's
   form; whether this key belongs to this host is the caller's decision (`onVerifyHostKey`).
3. **Credentials cross only after both** of the above, to a server that listed the method.

## Secure design principles applied

- **Secure by default, opt-in for the old:** the default lists hold only current algorithms. SHA-1
  exchanges, `ssh-rsa`, CBC ciphers, `hmac-md5`, RSA host keys under 2048 bits and Diffie-Hellman
  groups under 2048 bits come only with an explicit opt-in; Group 1 is never offered.
- **Fail closed:** anything unexpected in the handshake ends the connection rather than being
  skipped.
- **Least exposure:** a credential is offered only for a method the server's latest answer lists;
  a public key is asked about unsigned before anything is signed with it.
- **Economy of mechanism:** one key exchange in flight at a time, each message taken once.
- **Reviewed primitives:** ML-KEM-768 follows FIPS 203 and passes the NIST ACVP vectors; sntrup761
  ports the public-domain reference code OpenSSH uses; other primitives come from PointyCastle and pinenacl.

## How common weaknesses are countered

| Weakness | Counter |
|---|---|
| Downgrade or prefix truncation (Terrapin, CVE-2023-48795) | Strict key exchange (`kex-strict-c-v00@openssh.com`): sequence numbers reset at each exchange, only exchange messages pass during the first one, and the server's proposal must come first. |
| Weak or broken algorithms | Default lists without SHA-1, CBC, `hmac-md5` or Group 1; floors of 2048 bits for RSA host keys and Diffie-Hellman groups. |
| Forged or malformed host keys | The key's type must match what was agreed, its signature must match its kind, and an RSA key with an even modulus, a modulus outside 2048 to 16384 bits, or an even, too small or too long exponent is refused before use. |
| Invalid Diffie-Hellman values | Groups outside the asked range, even moduli, generators outside 1 to p - 1 and server values outside 1 < f < p - 1 are refused. |
| Plaintext injection after the handshake | Until traffic runs under approved keys, a service acceptance or sign-in success in the clear ends the connection. |
| Memory exhaustion from a hostile server | Version lines of at most 10240 bytes, at most 32768 bytes before the version, and packets of at most 35000 bytes. |
| Wrong arithmetic in the platform | Diffie-Hellman and the RSA host key check use the library's own modular exponentiation (Dart's `BigInt.modPow` was found to return wrong results for some inputs); every RSA signature is checked against the public key before it is sent. |
| Key reuse and stale keys | Every KEM key pair serves one handshake; keys are zeroed when new ones are installed; the client rekeys after 1 GiB or 2^31 packets. |
| A server that never answers | A server that sends its version and no key exchange proposal ends the connection after ten seconds, with a clear error. |
| Parsing bugs | Fuzz tests over packets, messages and keys (`test/fuzz`), and a test for every fix. |

## How this is kept true

- Every change needs a test, a clean `dart analyze` and `dart format` (see
  [CONTRIBUTING.md](../CONTRIBUTING.md)); CI runs them on each push.
- The OpenSSF Scorecard runs on the repository, and a monthly review goes over dependencies and
  open reports.
- Release tags are signed (see [VERIFYING.md](VERIFYING.md)).
- Vulnerabilities are reported privately and handled as in [SECURITY.md](../SECURITY.md).
