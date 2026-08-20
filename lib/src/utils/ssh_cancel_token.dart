import 'dart:async';

/// A cooperative cancellation token for SSH operations.
///
/// Create a token and pass it into long-running SSH methods. The holder of the
/// token can call [cancel] at any time to signal that the operation should be
/// abandoned. Listeners await [onCancel] to react to the cancellation.
///
/// ```dart
/// final token = SSHCancelToken();
///
/// // In calling code:
/// token.cancel('User pressed disconnect');
///
/// // In SSH internals:
/// await Future.any([doWork(), token.onCancel.then((_) => throw ...)]);
/// ```
class SSHCancelToken {
  final Completer<void> _completer = Completer<void>();
  String? _reason;

  /// Whether [cancel] has already been called.
  bool get isCancelled => _completer.isCompleted;

  /// The human-readable reason passed to [cancel], or `null` if not yet
  /// cancelled (or no reason was given).
  String? get reason => _reason;

  /// Completes when [cancel] is called. Await this to react to cancellation.
  Future<void> get onCancel => _completer.future;

  /// Signal cancellation. Subsequent calls are safe no-ops.
  ///
  /// [reason] is an optional human-readable explanation stored in [reason].
  void cancel([String? reason]) {
    if (!_completer.isCompleted) {
      _reason = reason;
      _completer.complete();
    }
  }
}
