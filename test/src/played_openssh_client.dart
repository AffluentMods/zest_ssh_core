import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'played_group_exchange.dart';
import 'played_listener.dart';
import 'played_server.dart';

/// The OpenSSH client of the machine a test runs on, as the client of a
/// [PlayedServer].
///
/// A played server is written by whoever writes the tests, so it is only
/// worth as much as its reading of the protocol. This puts a client on its
/// line that was not written here: where the OpenSSH client gets through a
/// key exchange with the played server, takes what it sends and is read by
/// it, the played server speaks what OpenSSH speaks.
///
/// The client is started so that nothing of whoever runs the tests is read
/// or written: no configuration file, no agent, no key files, and a list of
/// known hosts in a folder made for the run and removed after it. It is told
/// to sign in with nothing, so it asks once with the way called "none" and
/// gives up when that is refused.
class OpenSshClient {
  OpenSshClient._(this.program, this.version, this.ciphers);

  /// The program, as it is started.
  final String program;

  /// What it says it is, for example `OpenSSH_9.8p1`.
  final String version;

  /// The ciphers it has.
  final Set<String> ciphers;

  /// The OpenSSH clients of this machine, each kind once: the one that is
  /// found by its name, and where Windows or Git for Windows has its own.
  /// None where there is none.
  static List<OpenSshClient> found() {
    final environment = Platform.environment;
    final candidates = <String>[
      'ssh',
      if (Platform.isWindows) ...[
        for (final root in [environment['SystemRoot'], environment['windir']])
          if (root != null) '$root${Platform.pathSeparator}System32${Platform.pathSeparator}OpenSSH${Platform.pathSeparator}ssh.exe',
        for (final root in [environment['ProgramFiles'], environment['ProgramW6432']])
          if (root != null)
            '$root${Platform.pathSeparator}Git${Platform.pathSeparator}usr${Platform.pathSeparator}bin${Platform.pathSeparator}ssh.exe',
      ],
    ];
    final clients = <String, OpenSshClient>{};
    for (final program in candidates) {
      try {
        final said = Process.runSync(program, const ['-V']);
        final version = RegExp(r'OpenSSH[^ ,]*').firstMatch('${said.stderr}${said.stdout}')?.group(0);
        if (version == null || clients.containsKey(version)) continue;
        final has = Process.runSync(program, const ['-Q', 'cipher']);
        clients[version] =
            OpenSshClient._(program, version, const LineSplitter().convert('${has.stdout}').map((l) => l.trim()).toSet());
      } on ProcessException {
        continue;
      }
    }
    return clients.values.toList();
  }

  /// Whether the client can speak every one of [suites].
  bool speaks(Iterable<PlayedSuite> suites) => suites.every((suite) => ciphers.contains(suite.cipher.name));

  /// Starts the client against a played server that speaks [suite] first
  /// (its own packets under [toClient] where the two directions are to
  /// differ), with or without the [strict] key exchange. The client offers
  /// the ciphers and MACs of [offers], which have to hold whatever the
  /// played server will ever propose.
  ///
  /// The played server shows the Ed25519 host key it makes for itself, or
  /// [hostKey], which is then the one kind of host key the client is told
  /// to take.
  Future<OpenSshRun> connect({
    required List<PlayedSuite> offers,
    required PlayedSuite suite,
    PlayedSuite? toClient,
    bool strict = true,
    PlayedHostKey? hostKey,
  }) async {
    final ciphers = {for (final offer in offers) offer.cipher.name};
    final macs = {for (final offer in offers) (offer.mac ?? PlayedSuite.ctr.mac!).name};
    final started = await _start(
      kex: 'curve25519-sha256',
      ciphers: ciphers,
      macs: macs,
      hostKeys: hostKey?.algorithm ?? 'ssh-ed25519',
    );
    final server = PlayedServer(
      line: PlayedSocketLine(started.socket),
      suite: suite,
      toClient: toClient,
      strict: strict,
      hostKey: hostKey,
    );
    return OpenSshRun._(server, null, started.process, started.socket, started.scratch, started.said, started.saidAll);
  }

  /// Starts the client against a played server that offers a group exchange
  /// and nothing else ([PlayedGroupExchange]), which is what the client is
  /// told to offer too.
  Future<OpenSshRun> groupExchange() async {
    final started = await _start(
      kex: 'diffie-hellman-group-exchange-sha256',
      ciphers: {PlayedSuite.ctr.cipher.name},
      macs: {PlayedSuite.ctr.mac!.name},
    );
    final server = PlayedGroupExchange(line: PlayedSocketLine(started.socket));
    return OpenSshRun._(null, server, started.process, started.socket, started.scratch, started.said, started.saidAll);
  }

  /// Starts the client, told to offer [kex], [ciphers] and [macs] and to
  /// take a host key of the kind [hostKeys], and takes the connection it
  /// makes.
  Future<({Process process, Socket socket, Directory scratch, List<String> said, Future<void> saidAll})> _start({
    required String kex,
    required Set<String> ciphers,
    required Set<String> macs,
    String hostKeys = 'ssh-ed25519',
  }) async {
    final scratch = await Directory.systemTemp.createTemp('zest_ssh_core_played_');
    final listener = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final path = scratch.path + Platform.pathSeparator;
    // A key file that is there and holds nothing: with none named, or one
    // that is not there, the client looks at the key files of whoever runs
    // it, although it is told to sign in with no key.
    await File('${path}no_key').create();
    final process = await Process.start(program, [
      '-F', 'none',
      '-T',
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=no',
      '-o', 'UserKnownHostsFile=${path}known_hosts',
      '-o', 'GlobalKnownHostsFile=${path}global_known_hosts',
      '-o', 'UpdateHostKeys=no',
      '-o', 'IdentityAgent=none',
      '-o', 'IdentitiesOnly=yes',
      '-o', 'IdentityFile=${path}no_key',
      '-o', 'PubkeyAuthentication=no',
      '-o', 'PasswordAuthentication=no',
      '-o', 'KbdInteractiveAuthentication=no',
      '-o', 'GSSAPIAuthentication=no',
      '-o', 'HostbasedAuthentication=no',
      '-o', 'ForwardAgent=no',
      '-o', 'Ciphers=${ciphers.join(',')}',
      '-o', 'MACs=${macs.join(',')}',
      '-o', 'KexAlgorithms=$kex',
      '-o', 'HostKeyAlgorithms=$hostKeys',
      '-o', 'ConnectTimeout=10',
      '-o', 'LogLevel=DEBUG1',
      '-p', '${listener.port}',
      '-l', 'deploy',
      '127.0.0.1',
      'true',
    ]);
    unawaited(process.stdin.close().catchError((Object _) {}));
    unawaited(process.stdout.drain<void>().catchError((Object _) {}));
    final said = <String>[];
    final saidAll =
        process.stderr.transform(const Utf8Decoder(allowMalformed: true)).transform(const LineSplitter()).forEach(said.add);
    final Socket socket;
    try {
      socket = await listener.first.timeout(PlayedServer.patience);
    } catch (_) {
      process.kill();
      await listener.close();
      await scratch.delete(recursive: true);
      rethrow;
    }
    await listener.close();
    return (process: process, socket: socket, scratch: scratch, said: said, saidAll: saidAll);
  }

  @override
  String toString() => version;
}

/// One run of the OpenSSH client against a played server.
class OpenSshRun {
  OpenSshRun._(this._server, this._group, this._process, this._socket, this._scratch, this._said, this._saidAll);

  final PlayedServer? _server;
  final PlayedGroupExchange? _group;

  /// The played server the client is connected to ([OpenSshClient.connect]).
  PlayedServer get server => _server!;

  /// The played group exchange the client is connected to
  /// ([OpenSshClient.groupExchange]).
  PlayedGroupExchange get group => _group!;

  final Process _process;
  final Socket _socket;
  final Directory _scratch;
  final List<String> _said;
  final Future<void> _saidAll;

  /// How the client ended, once it has: 255 where it gave up or was cut off.
  Future<int> get exitCode async {
    final code = await _process.exitCode.timeout(PlayedServer.patience);
    await _saidAll.timeout(PlayedServer.patience, onTimeout: () {});
    return code;
  }

  /// The name of the folder made for the run, which is in every path under
  /// it however the client writes its paths.
  String get _mark => _scratch.uri.pathSegments.lastWhere((segment) => segment.isNotEmpty);

  /// What the client said of the connection so far, line by line, without
  /// the lines that name files of the machine.
  List<String> get said => [
        for (final line in _said)
          if (!line.contains(_mark) && !_namesAFile.hasMatch(line)) line,
      ];

  static final _namesAFile = RegExp(r'identity file|Will attempt key|known_hosts|\.ssh');

  /// How many lines of what the client said name a key file that is not in
  /// the folder made for the run: none, where no key of whoever runs the
  /// tests was looked at.
  int get lookedAtOthersKeys => _said.where((line) => _namesAKey.hasMatch(line) && !line.contains(_mark)).length;

  static final _namesAKey = RegExp(r'identity file|Will attempt key|\.ssh[/\\]id_');

  /// The cipher the client says it agreed on, for what it sends and for what
  /// it is sent: the last it said, which is the one of the last exchange.
  ({String? toServer, String? toClient}) get agreedOn {
    String? last(String direction) {
      final lines = _said.where((l) => l.contains('kex: $direction cipher: '));
      if (lines.isEmpty) return null;
      return RegExp(r'cipher: (\S+)').firstMatch(lines.last)!.group(1);
    }

    return (toServer: last('client->server'), toClient: last('server->client'));
  }

  /// Ends the run: the client is stopped if it is still there, and the
  /// folder made for the run is removed.
  Future<void> end() async {
    _process.kill();
    _socket.destroy();
    await _process.exitCode.timeout(PlayedServer.patience, onTimeout: () => -1);
    await _saidAll.timeout(PlayedServer.patience, onTimeout: () {});
    if (await _scratch.exists()) await _scratch.delete(recursive: true);
  }
}
