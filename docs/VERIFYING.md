# Verifying a release

Every release tag from v0.2.2 on is signed with the maintainer's SSH signing key. Earlier tags
(v0.2.1 and before) are not signed.

The key:

- Fingerprint: `SHA256:PY4yzQvz59/VM4CF2MB9GrXLe7jmwaPKECQEl+n+mVk` (Ed25519)
- Public key and the identity it signs as: [allowed_signers](allowed_signers)

## Check a tag

With Git 2.34 or later and OpenSSH 8.2 or later:

```bash
git clone https://github.com/AffluentMods/zest_ssh_core.git
cd zest_ssh_core
git config gpg.ssh.allowedSignersFile docs/allowed_signers
git tag -v v0.2.2
```

A good tag ends with:

```
Good "git" signature for affluentlabs@gmail.com with ED25519 key SHA256:PY4yzQvz59/VM4CF2MB9GrXLe7jmwaPKECQEl+n+mVk
```

Anything else (no signature, another key, `Could not verify signature`) means the tag is not one the
maintainer signed: do not use it, and report it as in [SECURITY.md](../SECURITY.md).

Check the fingerprint above against the one GitHub shows for the key, and against this file in a
copy you got another way, rather than trusting a single copy of this repository: a changed
repository could carry a changed file.

## Depending on a checked version

zest_ssh_core is not on pub.dev. Depend on it by Git, pinned to the commit of the tag you checked:

```yaml
dependencies:
  zest_ssh_core:
    git:
      url: https://github.com/AffluentMods/zest_ssh_core.git
      ref: ab69ae6fcef67eaebca4e3020272a3aac9bc1692 # v0.2.2
```
