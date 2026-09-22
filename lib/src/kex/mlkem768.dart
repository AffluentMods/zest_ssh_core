import 'dart:typed_data';

import 'package:pointycastle/digests/sha3.dart';
import 'package:pointycastle/digests/shake.dart';

/// ML-KEM-768 (FIPS 203), the NIST post-quantum key encapsulation
/// mechanism, in pure Dart. Used by the `mlkem768x25519-sha256` hybrid key
/// exchange, where the client generates an ephemeral encapsulation key,
/// the server encapsulates against it, and the client decapsulates.
///
/// Parameters (FIPS 203 Table 2): n = 256, q = 3329, k = 3, eta1 = eta2 = 2,
/// du = 10, dv = 4. Sizes: encapsulation key 1184 bytes, decapsulation key
/// 2400 bytes, ciphertext 1088 bytes, shared secret 32 bytes.
///
/// The keys are ephemeral (one per handshake), so the decapsulation is not
/// a long-lived oracle; the implicit-rejection compare is still done
/// without an early exit. Every algorithm below is named after the one in
/// the standard so the code can be read next to it.
class MlKem768 {
  MlKem768._();

  static const int n = 256;
  static const int q = 3329;
  static const int k = 3;
  static const int eta1 = 2;
  static const int eta2 = 2;
  static const int du = 10;
  static const int dv = 4;

  static const int encapsulationKeySize = 384 * k + 32; // 1184
  static const int decapsulationKeySize = 768 * k + 96; // 2400
  static const int ciphertextSize = 32 * (du * k + dv); // 1088
  static const int sharedSecretSize = 32;

  /// ML-KEM.KeyGen_internal (Algorithm 16) with the two 32-byte seeds
  /// [d] and [z]. Returns the encapsulation key and the decapsulation key.
  static ({Uint8List ek, Uint8List dk}) keyGenInternal(Uint8List d, Uint8List z) {
    if (d.length != 32 || z.length != 32) {
      throw ArgumentError('ML-KEM seeds must be 32 bytes');
    }
    final pke = _pkeKeyGen(d);
    final ek = pke.ek;
    final dk = Uint8List(decapsulationKeySize);
    dk.setRange(0, 384 * k, pke.dk);
    dk.setRange(384 * k, 768 * k + 32, ek);
    dk.setRange(768 * k + 32, 768 * k + 64, _h(ek));
    dk.setRange(768 * k + 64, 768 * k + 96, z);
    return (ek: ek, dk: dk);
  }

  /// ML-KEM.KeyGen (Algorithm 19) from a source of random bytes.
  static ({Uint8List ek, Uint8List dk}) keyGen(Uint8List Function(int) random) {
    return keyGenInternal(random(32), random(32));
  }

  /// ML-KEM.Encaps_internal (Algorithm 17): the shared secret and the
  /// ciphertext for encapsulation key [ek] and 32-byte randomness [m].
  /// Throws [ArgumentError] when [ek] fails the FIPS 203 input checks.
  static ({Uint8List sharedSecret, Uint8List ciphertext}) encapsInternal(
      Uint8List ek, Uint8List m) {
    checkEncapsulationKey(ek);
    if (m.length != 32) throw ArgumentError('m must be 32 bytes');
    final g = _g(_concat([m, _h(ek)]));
    final kk = Uint8List.sublistView(g, 0, 32);
    final r = Uint8List.sublistView(g, 32, 64);
    final c = _pkeEncrypt(ek, m, r);
    return (sharedSecret: Uint8List.fromList(kk), ciphertext: c);
  }

  /// ML-KEM.Encaps (Algorithm 20).
  static ({Uint8List sharedSecret, Uint8List ciphertext}) encaps(
      Uint8List ek, Uint8List Function(int) random) {
    return encapsInternal(ek, random(32));
  }

  /// ML-KEM.Decaps_internal (Algorithm 18): the shared secret for
  /// ciphertext [c] under decapsulation key [dk]. A ciphertext that does not
  /// re-encrypt to itself yields the implicit-rejection secret derived from
  /// z and c, never an error (the caller cannot tell the two apart, which is
  /// the point).
  static Uint8List decaps(Uint8List dk, Uint8List c) {
    if (c.length != ciphertextSize) {
      throw ArgumentError('ML-KEM-768 ciphertext must be $ciphertextSize bytes');
    }
    if (dk.length != decapsulationKeySize) {
      throw ArgumentError(
          'ML-KEM-768 decapsulation key must be $decapsulationKeySize bytes');
    }
    final dkPke = Uint8List.sublistView(dk, 0, 384 * k);
    final ekPke = Uint8List.sublistView(dk, 384 * k, 768 * k + 32);
    final h = Uint8List.sublistView(dk, 768 * k + 32, 768 * k + 64);
    final z = Uint8List.sublistView(dk, 768 * k + 64, 768 * k + 96);
    // Hash check (FIPS 203 section 7.3): the key was not corrupted.
    if (!_equal(_h(ekPke), h)) {
      throw ArgumentError('ML-KEM decapsulation key failed its hash check');
    }
    final mPrime = _pkeDecrypt(dkPke, c);
    final g = _g(_concat([mPrime, h]));
    final kPrime = Uint8List.fromList(Uint8List.sublistView(g, 0, 32));
    final rPrime = Uint8List.sublistView(g, 32, 64);
    final kBar = _j(_concat([z, c]));
    final cPrime = _pkeEncrypt(ekPke, mPrime, rPrime);
    // Constant-time select: all of kPrime or all of kBar.
    var diff = 0;
    for (var i = 0; i < c.length; i++) {
      diff |= c[i] ^ cPrime[i];
    }
    // mask = 0xFF when the ciphertexts differ (reject), else 0x00, without
    // a branch: (diff - 1) is negative only for diff == 0.
    final mask = (~((diff - 1) >> 63)) & 0xff;
    for (var i = 0; i < 32; i++) {
      kPrime[i] = (kPrime[i] & ~mask) | (kBar[i] & mask);
    }
    return kPrime;
  }

  /// The FIPS 203 encapsulation-key input checks: length, and every
  /// coefficient already reduced modulo q (ByteEncode(ByteDecode(ek)) == ek).
  static void checkEncapsulationKey(Uint8List ek) {
    if (ek.length != encapsulationKeySize) {
      throw ArgumentError(
          'ML-KEM-768 encapsulation key must be $encapsulationKeySize bytes');
    }
    for (var i = 0; i < k; i++) {
      final block = Uint8List.sublistView(ek, 384 * i, 384 * (i + 1));
      final poly = _byteDecode(block, 12);
      final again = _byteEncode(poly, 12);
      if (!_equal(again, block)) {
        throw ArgumentError('ML-KEM-768 encapsulation key is not reduced');
      }
    }
  }

  // ── K-PKE (FIPS 203 section 5) ───────────────────────────────────

  static ({Uint8List ek, Uint8List dk}) _pkeKeyGen(Uint8List d) {
    // (rho, sigma) = G(d || k)
    final g = _g(_concat([
      d,
      Uint8List.fromList([k])
    ]));
    final rho = Uint8List.sublistView(g, 0, 32);
    final sigma = Uint8List.sublistView(g, 32, 64);
    final a = _generateMatrix(rho);
    var nonce = 0;
    final s = List<Int32List>.generate(k, (_) => Int32List(n));
    final e = List<Int32List>.generate(k, (_) => Int32List(n));
    for (var i = 0; i < k; i++) {
      s[i] = _samplePolyCbd(_prf(eta1, sigma, nonce++), eta1);
    }
    for (var i = 0; i < k; i++) {
      e[i] = _samplePolyCbd(_prf(eta1, sigma, nonce++), eta1);
    }
    for (var i = 0; i < k; i++) {
      _ntt(s[i]);
      _ntt(e[i]);
    }
    // t = A o s + e
    final t = List<Int32List>.generate(k, (_) => Int32List(n));
    for (var i = 0; i < k; i++) {
      for (var j = 0; j < k; j++) {
        _addInto(t[i], _multiplyNtts(a[i][j], s[j]));
      }
      _addInto(t[i], e[i]);
    }
    final ek = Uint8List(encapsulationKeySize);
    for (var i = 0; i < k; i++) {
      ek.setRange(384 * i, 384 * (i + 1), _byteEncode(t[i], 12));
    }
    ek.setRange(384 * k, 384 * k + 32, rho);
    final dk = Uint8List(384 * k);
    for (var i = 0; i < k; i++) {
      dk.setRange(384 * i, 384 * (i + 1), _byteEncode(s[i], 12));
    }
    return (ek: ek, dk: dk);
  }

  static Uint8List _pkeEncrypt(Uint8List ek, Uint8List m, Uint8List r) {
    final t = List<Int32List>.generate(
        k, (i) => _byteDecode(Uint8List.sublistView(ek, 384 * i, 384 * (i + 1)), 12));
    final rho = Uint8List.sublistView(ek, 384 * k, 384 * k + 32);
    final a = _generateMatrix(rho);
    var nonce = 0;
    final y = List<Int32List>.generate(k, (_) => Int32List(n));
    final e1 = List<Int32List>.generate(k, (_) => Int32List(n));
    for (var i = 0; i < k; i++) {
      y[i] = _samplePolyCbd(_prf(eta1, r, nonce++), eta1);
    }
    for (var i = 0; i < k; i++) {
      e1[i] = _samplePolyCbd(_prf(eta2, r, nonce++), eta2);
    }
    final e2 = _samplePolyCbd(_prf(eta2, r, nonce++), eta2);
    for (var i = 0; i < k; i++) {
      _ntt(y[i]);
    }
    // u = INTT(A^T o y) + e1
    final u = List<Int32List>.generate(k, (_) => Int32List(n));
    for (var i = 0; i < k; i++) {
      for (var j = 0; j < k; j++) {
        _addInto(u[i], _multiplyNtts(a[j][i], y[j]));
      }
      _invNtt(u[i]);
      _addInto(u[i], e1[i]);
    }
    // v = INTT(t^T o y) + e2 + Decompress1(ByteDecode1(m))
    final v = Int32List(n);
    for (var i = 0; i < k; i++) {
      _addInto(v, _multiplyNtts(t[i], y[i]));
    }
    _invNtt(v);
    _addInto(v, e2);
    final mu = _byteDecode(m, 1);
    for (var i = 0; i < n; i++) {
      mu[i] = _decompress(mu[i], 1);
    }
    _addInto(v, mu);
    final c = Uint8List(ciphertextSize);
    for (var i = 0; i < k; i++) {
      final ui = Int32List(n);
      for (var j = 0; j < n; j++) {
        ui[j] = _compress(u[i][j], du);
      }
      c.setRange(32 * du * i, 32 * du * (i + 1), _byteEncode(ui, du));
    }
    final vc = Int32List(n);
    for (var j = 0; j < n; j++) {
      vc[j] = _compress(v[j], dv);
    }
    c.setRange(32 * du * k, ciphertextSize, _byteEncode(vc, dv));
    return c;
  }

  static Uint8List _pkeDecrypt(Uint8List dk, Uint8List c) {
    final u = List<Int32List>.generate(k, (i) {
      final p = _byteDecode(
          Uint8List.sublistView(c, 32 * du * i, 32 * du * (i + 1)), du);
      for (var j = 0; j < n; j++) {
        p[j] = _decompress(p[j], du);
      }
      return p;
    });
    final v = _byteDecode(
        Uint8List.sublistView(c, 32 * du * k, ciphertextSize), dv);
    for (var j = 0; j < n; j++) {
      v[j] = _decompress(v[j], dv);
    }
    final s = List<Int32List>.generate(
        k, (i) => _byteDecode(Uint8List.sublistView(dk, 384 * i, 384 * (i + 1)), 12));
    // w = v - INTT(s^T o NTT(u))
    final acc = Int32List(n);
    for (var i = 0; i < k; i++) {
      _ntt(u[i]);
      _addInto(acc, _multiplyNtts(s[i], u[i]));
    }
    _invNtt(acc);
    final w = Int32List(n);
    for (var j = 0; j < n; j++) {
      w[j] = _mod(v[j] - acc[j]);
      w[j] = _compress(w[j], 1);
    }
    return _byteEncode(w, 1);
  }

  // ── Sampling (section 4.2.2) ─────────────────────────────────────

  /// A_hat[i][j] = SampleNTT(XOF(rho || j || i)).
  static List<List<Int32List>> _generateMatrix(Uint8List rho) {
    return List.generate(
      k,
      (i) => List.generate(k, (j) {
        final xof = SHAKEDigest(128);
        xof.update(rho, 0, 32);
        xof.updateByte(j);
        xof.updateByte(i);
        return _sampleNtt(xof);
      }),
    );
  }

  /// Algorithm 7: rejection-sample 256 coefficients in [0, q) from the XOF
  /// three bytes at a time.
  static Int32List _sampleNtt(SHAKEDigest xof) {
    final a = Int32List(n);
    final buf = Uint8List(168 * 3);
    var j = 0;
    while (j < n) {
      xof.doOutput(buf, 0, buf.length);
      for (var i = 0; i + 2 < buf.length && j < n; i += 3) {
        final d1 = buf[i] + 256 * (buf[i + 1] & 0x0f);
        final d2 = (buf[i + 1] >> 4) + 16 * buf[i + 2];
        if (d1 < q) {
          a[j++] = d1;
        }
        if (d2 < q && j < n) {
          a[j++] = d2;
        }
      }
    }
    return a;
  }

  /// Algorithm 8: centered binomial distribution from 64 * eta bytes.
  static Int32List _samplePolyCbd(Uint8List b, int eta) {
    final f = Int32List(n);
    var bitPos = 0;
    int bit() {
      final v = (b[bitPos >> 3] >> (bitPos & 7)) & 1;
      bitPos++;
      return v;
    }

    for (var i = 0; i < n; i++) {
      var x = 0;
      var y = 0;
      for (var j = 0; j < eta; j++) {
        x += bit();
      }
      for (var j = 0; j < eta; j++) {
        y += bit();
      }
      f[i] = _mod(x - y);
    }
    return f;
  }

  // ── NTT (section 4.3) ────────────────────────────────────────────

  /// zeta^BitRev7(i) mod q for i in 0..127 (FIPS 203 Appendix A).
  static final Int32List _zetas = _computeZetas();

  static Int32List _computeZetas() {
    final z = Int32List(128);
    for (var i = 0; i < 128; i++) {
      z[i] = _powMod(17, _bitRev7(i));
    }
    return z;
  }

  static int _bitRev7(int i) {
    var r = 0;
    for (var b = 0; b < 7; b++) {
      r = (r << 1) | ((i >> b) & 1);
    }
    return r;
  }

  static int _powMod(int base, int exp) {
    var result = 1;
    var b = base % q;
    var e = exp;
    while (e > 0) {
      if (e & 1 == 1) result = (result * b) % q;
      b = (b * b) % q;
      e >>= 1;
    }
    return result;
  }

  /// Algorithm 9, in place.
  static void _ntt(Int32List f) {
    var i = 1;
    for (var len = 128; len >= 2; len >>= 1) {
      for (var start = 0; start < n; start += 2 * len) {
        final zeta = _zetas[i++];
        for (var j = start; j < start + len; j++) {
          final t = (zeta * f[j + len]) % q;
          f[j + len] = _mod(f[j] - t);
          f[j] = _mod(f[j] + t);
        }
      }
    }
  }

  /// Algorithm 10, in place.
  static void _invNtt(Int32List f) {
    var i = 127;
    for (var len = 2; len <= 128; len <<= 1) {
      for (var start = 0; start < n; start += 2 * len) {
        final zeta = _zetas[i--];
        for (var j = start; j < start + len; j++) {
          final t = f[j];
          f[j] = _mod(t + f[j + len]);
          f[j + len] = (zeta * _mod(f[j + len] - t)) % q;
        }
      }
    }
    for (var j = 0; j < n; j++) {
      f[j] = (f[j] * 3303) % q; // 128^-1 mod q
    }
  }

  /// Algorithm 11: product in the NTT domain.
  static Int32List _multiplyNtts(Int32List f, Int32List g) {
    final h = Int32List(n);
    for (var i = 0; i < 128; i++) {
      // gamma = zeta^(2 BitRev7(i) + 1) = zetas[i] * zeta... computed
      // directly to keep the table small.
      final gamma = (_zetas[i] * _zetas[i] % q) * 17 % q;
      final a0 = f[2 * i], a1 = f[2 * i + 1];
      final b0 = g[2 * i], b1 = g[2 * i + 1];
      h[2 * i] = (a0 * b0 + (a1 * b1 % q) * gamma) % q;
      h[2 * i + 1] = (a0 * b1 + a1 * b0) % q;
    }
    return h;
  }

  static void _addInto(Int32List acc, Int32List x) {
    for (var i = 0; i < n; i++) {
      acc[i] = _mod(acc[i] + x[i]);
    }
  }

  static int _mod(int x) {
    final r = x % q;
    return r < 0 ? r + q : r;
  }

  // ── Compression and encoding (section 4.2.1) ─────────────────────

  static int _compress(int x, int d) =>
      (((x << d) + (q >> 1)) ~/ q) & ((1 << d) - 1);

  static int _decompress(int y, int d) => ((q * y) + (1 << (d - 1))) >> d;

  /// Algorithm 5: 256 d-bit integers, little-endian bit packed, 32 d bytes.
  static Uint8List _byteEncode(Int32List f, int d) {
    final out = Uint8List(32 * d);
    var bitPos = 0;
    for (var i = 0; i < n; i++) {
      var a = f[i];
      for (var j = 0; j < d; j++) {
        out[bitPos >> 3] |= (a & 1) << (bitPos & 7);
        a >>= 1;
        bitPos++;
      }
    }
    return out;
  }

  /// Algorithm 6. For d = 12 the values are reduced modulo q (the caller
  /// checks an encapsulation key was already reduced, see
  /// [checkEncapsulationKey]).
  static Int32List _byteDecode(Uint8List b, int d) {
    final f = Int32List(n);
    final m = d < 12 ? (1 << d) : q;
    var bitPos = 0;
    for (var i = 0; i < n; i++) {
      var a = 0;
      for (var j = 0; j < d; j++) {
        a |= ((b[bitPos >> 3] >> (bitPos & 7)) & 1) << j;
        bitPos++;
      }
      f[i] = a % m;
    }
    return f;
  }

  // ── Hash functions (section 4.1) ─────────────────────────────────

  static Uint8List _h(Uint8List x) => SHA3Digest(256).process(x);

  static Uint8List _g(Uint8List x) => SHA3Digest(512).process(x);

  /// J(s) = SHAKE256(s, 32 bytes).
  static Uint8List _j(Uint8List x) {
    final xof = SHAKEDigest(256);
    xof.update(x, 0, x.length);
    final out = Uint8List(32);
    xof.doOutput(out, 0, 32);
    return out;
  }

  /// PRF_eta(s, b) = SHAKE256(s || b, 64 eta bytes).
  static Uint8List _prf(int eta, Uint8List s, int b) {
    final xof = SHAKEDigest(256);
    xof.update(s, 0, s.length);
    xof.updateByte(b);
    final out = Uint8List(64 * eta);
    xof.doOutput(out, 0, out.length);
    return out;
  }

  static Uint8List _concat(List<Uint8List> parts) {
    final b = BytesBuilder(copy: false);
    for (final p in parts) {
      b.add(p);
    }
    return b.takeBytes();
  }

  static bool _equal(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
