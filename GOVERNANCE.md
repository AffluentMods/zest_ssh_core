# Governance

zest_ssh_core is the SSH engine of [ZestSSH](https://zestssh.com), a fork of
[dartssh2](https://github.com/TerminalStudio/dartssh2) hardened for it. This file says who runs the
project, how decisions are made, and what happens if the maintainer can no longer do it.

## Who runs it

- **The maintainer** (GitHub: [@AffluentMods](https://github.com/AffluentMods)) writes and reviews the
  code, merges changes, answers issues and security reports, and cuts releases.
- **Affluent Labs LLC** owns the project: the repository, the GitHub account, the release signing
  key and the zestssh.com addresses used for reports. It is the project's backup: if the maintainer
  cannot carry on, Affluent Labs LLC holds the access to name a new maintainer and keep the project
  going, including the ability to create and close issues, accept changes and publish releases.

The project is small and has one maintainer today. That is said plainly so that nobody relies on it
as if a team stood behind every review.

## How decisions are made

- **Day to day,** the maintainer decides: what is merged, what goes into a release, and when.
- **Security first.** A change that weakens a default algorithm or check is not accepted. Older
  algorithms are added only behind an explicit opt-in. A real break takes priority over anything
  else in progress (see [SECURITY.md](SECURITY.md)).
- **In the open.** Proposals and their reasons are discussed in issues and pull requests, where
  anyone can comment. A change that is refused is answered with why.
- **Upstream.** Fixes that also apply to dartssh2 are offered upstream where they fit.

## Contributing

Anyone can contribute: see [CONTRIBUTING.md](CONTRIBUTING.md) for what a change needs and how it is
reviewed, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for how people treat each other here.

## Changing this file

This file is changed like any other: by a pull request, reviewed and merged by the maintainer, with
the change noted in its history.
