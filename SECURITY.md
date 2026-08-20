# Security policy

zest_ssh_core is maintained by one person, and security reports are read and answered personally.

## Reporting

Two ways, pick either:

- Open a private advisory through GitHub, under this repository's Security tab ("Report a vulnerability").
- Email support@zestssh.com.

Please include:

- What the vulnerability is
- How to reproduce it, ideally with a proof of concept
- Which versions and platforms are affected
- How you would like to be credited, if at all

If the issue is sensitive, ask for a PGP key and we will trade one before you send details.

## What happens next

- Acknowledgment within 72 hours.
- Triage within 7 days: severity and exploitability.
- A fix proportional to severity. A real break takes priority over anything else in progress.
- Coordinated disclosure. We agree on a date before a fix ships, usually 14 to 90 days depending on severity and exposure.
- Credit in the release notes, if you want it.

## Scope

In scope is this library: the SSH and SFTP protocol implementation, key exchange, authentication, host-key handling, and the cryptographic primitives it uses.

Out of scope:

- Upstream dartssh2 issues that also affect this fork. Report them upstream too, and tell us so we can merge the fix.
- The ZestSSH apps, sync server, and websites. Those go through [zestssh.com](https://zestssh.com); this file is for the library only.
- Anything that needs an already-compromised host as a precondition.

## Safe harbor

Good-faith research is welcome. We will not pursue anyone who reports promptly, gives us reasonable time before going public, does not touch data that is not theirs, and stays within the law.
