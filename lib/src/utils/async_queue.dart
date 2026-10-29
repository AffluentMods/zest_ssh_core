// SPDX-License-Identifier: MIT
import 'dart:async';

import 'dart:collection';

/// A queue that consumers can wait asynchronously for items to be added.
class AsyncQueue<T> {
  final _data = Queue<T>();

  final _completers = Queue<Completer<T>>();

  /// What the queue was closed with; null while it is open.
  Object? _closedWith;

  /// The length of the queue.
  int get length => _completers.length;

  /// Return true if the queue has consumers waiting for items.
  bool get hasWaiters => _completers.isNotEmpty;

  /// Whether [close] was called: nothing more will be added.
  bool get isClosed => _closedWith != null;

  /// Returns a [Future] that completes when an item is added to the queue.
  /// Once the queue is closed and what it held has been handed out, the
  /// future fails with what the queue was closed with.
  FutureOr<T> get next {
    if (_data.isNotEmpty) {
      return _data.removeFirst();
    }
    final closedWith = _closedWith;
    if (closedWith != null) {
      return Future<T>.error(closedWith);
    }
    final completer = Completer<T>();
    _completers.add(completer);
    return completer.future;
  }

  /// Adds an item to the queue. An item for a queue that is closed is
  /// dropped: nobody waits for it any more.
  void add(T value) {
    if (_closedWith != null) return;
    if (_completers.isNotEmpty) {
      _completers.removeFirst().complete(value);
    } else {
      _data.add(value);
    }
  }

  /// Ends the queue: nothing more will come. Everyone waiting for an item
  /// gets [error] in its place, and so does whoever asks for one later. What
  /// was added before and not taken yet is still handed out, in order.
  ///
  /// Without this, a consumer whose item will never come (the reply to a
  /// request on a connection that has ended) waits for ever.
  void close(Object error) {
    if (_closedWith != null) return;
    _closedWith = error;
    while (_completers.isNotEmpty) {
      _completers.removeFirst().completeError(error);
    }
  }
}
