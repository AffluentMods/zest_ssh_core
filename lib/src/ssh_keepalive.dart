// SPDX-License-Identifier: MIT
import 'dart:async';

import 'package:meta/meta.dart';

/// A wrapper around [Timer] that calls [ping] every [interval], and can be
/// started or stopped idempotently.
///
/// It also notices silence. A ping asks the server for an answer, so on a
/// connection that works something comes from the server at least once an
/// interval. Where [heard] is given (how much has come from the server so
/// far), each tick looks at whether anything came since the tick before;
/// when [maxUnanswered] pings in a row were sent with nothing at all coming
/// back, [onNoAnswer] is called, once, and the pings stop: the connection
/// has gone quiet, and whoever holds it should give it up. Without this a
/// connection that had gone quiet was kept until the system gave it up,
/// which can take very long.
///
/// A server is judged by its keep-alives only once it has answered one.
/// There are devices that answer none (against the protocol, which wants an
/// answer to every request that asks for one): their idle sessions are
/// quiet by nature, and are left alone, as they always were.
///
/// What is counted is pings, not time: a device that was asleep, its timers
/// with it, does not find the connection silent for as long as it slept; it
/// sends its next ping and counts from there.
class SSHKeepAlive {
  Timer? _timer;

  final Duration interval;

  /// Asks the server for an answer; completes when the answer has come.
  final Future Function() ping;

  /// How many pings in a row may go by with nothing heard from the server
  /// before the connection is called quiet. (Three, as OpenSSH's
  /// ServerAliveCountMax.)
  final int maxUnanswered;

  /// How much has come from the server so far: any count that grows when
  /// something comes. Null: silence is not looked for.
  final int Function()? heard;

  /// Called once when [maxUnanswered] pings in a row went by with nothing
  /// heard, with how long that was at the least.
  final void Function(Duration silence)? onNoAnswer;

  SSHKeepAlive({
    required this.ping,
    this.interval = const Duration(seconds: 10),
    this.maxUnanswered = 3,
    this.heard,
    this.onNoAnswer,
  });

  /// Pings sent since something was last heard from the server.
  int _unanswered = 0;

  /// What [heard] said at the tick before.
  int? _heardBefore;

  /// Whether the server has answered a ping on this connection.
  bool _answers = false;

  void start() {
    if (_timer != null) return;
    // (Whatever was counted before, nothing is said of a server until it has
    // answered a ping since this start.)
    _answers = false;
    _timer = Timer.periodic(interval, (timer) => _tick());
  }

  /// What the timer does at each interval, for tests (which do not wait for
  /// a timer).
  @visibleForTesting
  void debugTick() => _tick();

  void _tick() {
    final heard = this.heard;
    if (heard != null) {
      final now = heard();
      if (now != _heardBefore) {
        _heardBefore = now;
        _unanswered = 0;
      } else if (_answers && _unanswered >= maxUnanswered) {
        final silence = interval * _unanswered;
        stop();
        onNoAnswer?.call(silence);
        return;
      }
    }
    _unanswered++;
    unawaited(_ping());
  }

  Future<void> _ping() async {
    try {
      await ping();
      // It answers keep-alives: from here on, their going unanswered says
      // something about the connection. (That its answer came is seen at
      // the next tick, by what was heard.)
      _answers = true;
    } catch (_) {
      // The connection ended with this ping on its way. Whoever watches
      // the connection hears of its end from the connection itself; an
      // error thrown out of a timer would reach nobody who could act on it.
    }
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}
