import 'dart:async';
import 'dart:io';

import 'package:zest_ssh_core/src/sftp/sftp_client.dart';
import 'package:zest_ssh_core/src/sftp/sftp_file_open_mode.dart';

/// Progress reporting for SFTP transfers.
class SFTPProgress {
  /// Number of bytes transferred so far.
  final int bytesTransferred;

  /// Total bytes expected for this transfer.
  final int totalBytes;

  /// Time elapsed since the transfer started.
  final Duration elapsed;

  const SFTPProgress({
    required this.bytesTransferred,
    required this.totalBytes,
    required this.elapsed,
  });

  /// Fraction of the transfer that is complete, between 0.0 and 1.0.
  double get fractionComplete =>
      totalBytes > 0 ? bytesTransferred / totalBytes : 0;

  /// Average transfer speed in bytes per second.
  int get bytesPerSecond => elapsed.inMilliseconds > 0
      ? (bytesTransferred * 1000 ~/ elapsed.inMilliseconds)
      : 0;

  /// Estimated time remaining based on current transfer speed.
  /// Returns null if the speed is zero or the transfer is complete.
  Duration? get estimatedRemaining {
    if (bytesPerSecond == 0 || fractionComplete >= 1.0) return null;
    final remaining = totalBytes - bytesTransferred;
    return Duration(seconds: remaining ~/ bytesPerSecond);
  }

  @override
  String toString() {
    final pct = (fractionComplete * 100).toStringAsFixed(1);
    return 'SFTPProgress($pct%, $bytesTransferred/$totalBytes bytes, '
        '${bytesPerSecond}B/s)';
  }
}

/// Callback invoked to report transfer progress.
typedef SFTPProgressCallback = void Function(SFTPProgress progress);

/// Resumable file transfer that can pick up a download from where it left off.
///
/// If a partial local file already exists, the download resumes from the
/// byte offset matching the local file size, appending to the existing file.
class SFTPResumableTransfer {
  /// Path of the file on the remote server.
  final String remotePath;

  /// Path of the file on the local filesystem.
  final String localPath;

  /// Byte offset from which the transfer started (or resumed).
  final int startOffset;

  /// Total size of the remote file in bytes.
  final int totalSize;

  const SFTPResumableTransfer({
    required this.remotePath,
    required this.localPath,
    required this.startOffset,
    required this.totalSize,
  });

  /// Resume a download from where it left off.
  ///
  /// Checks the local file size and seeks to that offset on the remote file,
  /// then appends remaining data to the local file. If no local file exists,
  /// the download starts from the beginning.
  ///
  /// Returns an [SFTPResumableTransfer] describing the completed operation.
  static Future<SFTPResumableTransfer> resume({
    required SftpClient sftp,
    required String remotePath,
    required String localPath,
    SFTPProgressCallback? onProgress,
  }) async {
    // Stat remote file for total size.
    final attrs = await sftp.stat(remotePath);
    final totalSize = attrs.size;
    if (totalSize == null) {
      throw StateError('Cannot determine remote file size for "$remotePath"');
    }

    // Check local file size for start offset.
    final localFile = File(localPath);
    int startOffset = 0;
    if (await localFile.exists()) {
      startOffset = await localFile.length();
    }

    // Nothing left to download.
    if (startOffset >= totalSize) {
      onProgress?.call(SFTPProgress(
        bytesTransferred: totalSize,
        totalBytes: totalSize,
        elapsed: Duration.zero,
      ));
      return SFTPResumableTransfer(
        remotePath: remotePath,
        localPath: localPath,
        startOffset: startOffset,
        totalSize: totalSize,
      );
    }

    // Open remote file, seek to offset, append to local file.
    final remoteFile = await sftp.open(remotePath, mode: SftpFileOpenMode.read);
    try {
      final sink = localFile.openWrite(mode: FileMode.append);
      final stopwatch = Stopwatch()..start();
      var bytesWritten = 0;
      final remainingLength = totalSize - startOffset;

      try {
        await for (final chunk in remoteFile.read(
          offset: startOffset,
          length: remainingLength,
        )) {
          sink.add(chunk);
          bytesWritten += chunk.length;
          onProgress?.call(SFTPProgress(
            bytesTransferred: startOffset + bytesWritten,
            totalBytes: totalSize,
            elapsed: stopwatch.elapsed,
          ));
        }
      } finally {
        await sink.flush();
        await sink.close();
        stopwatch.stop();
      }
    } finally {
      await remoteFile.close();
    }

    return SFTPResumableTransfer(
      remotePath: remotePath,
      localPath: localPath,
      startOffset: startOffset,
      totalSize: totalSize,
    );
  }

  @override
  String toString() =>
      'SFTPResumableTransfer(remote: $remotePath, local: $localPath, '
      'offset: $startOffset, total: $totalSize)';
}

/// Parallel file transfer manager for downloading multiple files concurrently.
class SFTPParallelTransfer {
  /// Maximum number of concurrent downloads.
  final int maxConcurrent;

  const SFTPParallelTransfer({this.maxConcurrent = 4});

  /// Download multiple files concurrently.
  ///
  /// Files from [remotePaths] are downloaded into [localDir], preserving the
  /// basename of each remote path. Progress is reported as an aggregate across
  /// all files.
  ///
  /// Returns a list of [SFTPTransferResult] for each file, in the same order
  /// as [remotePaths].
  Future<List<SFTPTransferResult>> downloadMany({
    required SftpClient sftp,
    required List<String> remotePaths,
    required String localDir,
    SFTPProgressCallback? onProgress,
  }) async {
    // Pre-stat all remote files to get total bytes for aggregate progress.
    final statResults = await Future.wait(
      remotePaths.map((p) => sftp.stat(p)),
    );

    final totalBytes = statResults.fold<int>(
      0,
      (sum, attrs) => sum + (attrs.size ?? 0),
    );

    // Ensure the local directory exists.
    final dir = Directory(localDir);
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    // Build work items.
    final results = List<SFTPTransferResult?>.filled(remotePaths.length, null);
    final aggregateBytesPerFile = List<int>.filled(remotePaths.length, 0);
    var aggregateBytes = 0;
    final overallStopwatch = Stopwatch()..start();

    // Semaphore: limit concurrency via a simple queue approach.
    var runningCount = 0;
    final pendingIndices = List<int>.generate(remotePaths.length, (i) => i);
    final allDone = Completer<void>();
    var completedCount = 0;

    void reportAggregateProgress() {
      if (onProgress == null) return;
      aggregateBytes =
          aggregateBytesPerFile.fold<int>(0, (sum, b) => sum + b);
      onProgress(SFTPProgress(
        bytesTransferred: aggregateBytes,
        totalBytes: totalBytes,
        elapsed: overallStopwatch.elapsed,
      ));
    }

    Future<void> processIndex(int index) async {
      final remotePath = remotePaths[index];
      // Split on both / and \ to prevent path traversal via backslashes.
      final basename = remotePath.split(RegExp(r'[/\\]')).last;
      final localPath =
          localDir.endsWith('/') ? '$localDir$basename' : '$localDir/$basename';
      final stopwatch = Stopwatch()..start();

      try {
        final remoteFile =
            await sftp.open(remotePath, mode: SftpFileOpenMode.read);
        try {
          // Use append mode if the local file already exists (resume
          // semantics) instead of truncating existing data.
          final localFile = File(localPath);
          final fileMode =
              await localFile.exists() ? FileMode.append : FileMode.write;
          final sink = localFile.openWrite(mode: fileMode);
          var fileBytesWritten = 0;

          try {
            await for (final chunk in remoteFile.read()) {
              sink.add(chunk);
              fileBytesWritten += chunk.length;
              aggregateBytesPerFile[index] = fileBytesWritten;
              reportAggregateProgress();
            }
          } finally {
            await sink.flush();
            await sink.close();
          }

          stopwatch.stop();
          results[index] = SFTPTransferResult(
            remotePath: remotePath,
            localPath: localPath,
            success: true,
            bytesTransferred: fileBytesWritten,
            elapsed: stopwatch.elapsed,
          );
        } finally {
          await remoteFile.close();
        }
      } catch (e) {
        stopwatch.stop();
        results[index] = SFTPTransferResult(
          remotePath: remotePath,
          localPath: localPath,
          success: false,
          bytesTransferred: aggregateBytesPerFile[index],
          elapsed: stopwatch.elapsed,
          error: e.toString(),
        );
      }
    }

    Future<void> scheduleNext() async {
      while (pendingIndices.isNotEmpty && runningCount < maxConcurrent) {
        final index = pendingIndices.removeAt(0);
        runningCount++;
        // ignore: unawaited_futures
        processIndex(index).then((_) {
          runningCount--;
          completedCount++;
          if (completedCount == remotePaths.length) {
            allDone.complete();
          } else {
            scheduleNext();
          }
        });
      }
    }

    if (remotePaths.isEmpty) {
      return [];
    }

    await scheduleNext();
    await allDone.future;
    overallStopwatch.stop();

    return results.cast<SFTPTransferResult>();
  }
}

/// Result of a single file transfer operation.
class SFTPTransferResult {
  /// Path of the file on the remote server.
  final String remotePath;

  /// Path of the downloaded file on the local filesystem.
  final String localPath;

  /// Whether the transfer completed successfully.
  final bool success;

  /// Number of bytes transferred.
  final int bytesTransferred;

  /// Time elapsed for this transfer.
  final Duration elapsed;

  /// Error message if the transfer failed, or null on success.
  final String? error;

  const SFTPTransferResult({
    required this.remotePath,
    required this.localPath,
    required this.success,
    required this.bytesTransferred,
    required this.elapsed,
    this.error,
  });

  @override
  String toString() {
    if (success) {
      return 'SFTPTransferResult(ok, $remotePath -> $localPath, '
          '$bytesTransferred bytes in ${elapsed.inMilliseconds}ms)';
    }
    return 'SFTPTransferResult(FAILED, $remotePath, error: $error)';
  }
}
