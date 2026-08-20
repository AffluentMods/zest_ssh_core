# Benchmarks

Performance benchmarks for zest_ssh_core crypto primitives.

These are standalone Dart scripts, not test files.

## Running

From `packages/zest_ssh_core/`:

```bash
# Cipher encrypt/decrypt throughput (AES-CTR, AES-CBC)
dart run benchmark/cipher_benchmark.dart

# Key exchange operations (X25519, NIST P-256/P-384/P-521)
dart run benchmark/kex_benchmark.dart
```

## What they measure

- **cipher_benchmark.dart** -- Block cipher encrypt/decrypt throughput in MB/s for 1 MB and 10 MB payloads across all non-AEAD cipher types (AES-128/192/256 in CTR and CBC modes).
- **kex_benchmark.dart** -- Key generation and shared secret derivation rates in ops/s for X25519 and NIST elliptic curve key exchanges.
