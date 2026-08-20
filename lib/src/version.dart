/// Version of this library. Keep in step with the `version:` field in
/// pubspec.yaml - it is the source of the client identification string sent
/// during the SSH version exchange.
const String kZestSshCoreVersion = '0.1.0';

/// Default SSH client identification string (the part after `SSH-2.0-`).
///
/// This is what every server logs and every scanner reports, so it names the
/// library and its version rather than inheriting upstream dartssh2's
/// `DartSSH_2.0`. A host operator fingerprinting clients, or anyone reading a
/// scan, sees `zest_ssh_core` and can attribute the behaviour correctly.
const String kDefaultClientIdent = 'zest_ssh_core_$kZestSshCoreVersion';
