import 'package:zest_ssh_core/src/kex/kex_x25519.dart';
import 'package:zest_ssh_core/src/kex/kex_nist.dart';

void main() {
  const iterations = 100;

  // --- X25519 key generation + shared secret ---
  print('=== X25519 Key Exchange ===');
  {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      SSHKexX25519();
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Key generation: ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  {
    final alice = SSHKexX25519();
    final bob = SSHKexX25519();

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      alice.computeSecret(bob.publicKey);
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Shared secret:  ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  print('');

  // --- NIST P-256 key generation + shared secret ---
  print('=== ECDH NIST P-256 ===');
  {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      SSHKexNist.p256();
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Key generation: ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  {
    final alice = SSHKexNist.p256();
    final bob = SSHKexNist.p256();

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      alice.computeSecret(bob.publicKey);
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Shared secret:  ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  print('');

  // --- NIST P-384 key generation + shared secret ---
  print('=== ECDH NIST P-384 ===');
  {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      SSHKexNist.p384();
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Key generation: ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  {
    final alice = SSHKexNist.p384();
    final bob = SSHKexNist.p384();

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      alice.computeSecret(bob.publicKey);
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Shared secret:  ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  print('');

  // --- NIST P-521 key generation + shared secret ---
  print('=== ECDH NIST P-521 ===');
  {
    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      SSHKexNist.p521();
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Key generation: ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }

  {
    final alice = SSHKexNist.p521();
    final bob = SSHKexNist.p521();

    final sw = Stopwatch()..start();
    for (var i = 0; i < iterations; i++) {
      alice.computeSecret(bob.publicKey);
    }
    sw.stop();

    final opsPerSec = iterations / (sw.elapsedMilliseconds / 1000);
    print(
      '  Shared secret:  ${opsPerSec.toStringAsFixed(1)} ops/s '
      '($iterations iterations in ${sw.elapsedMilliseconds}ms)',
    );
  }
}
