import 'dart:typed_data';

import 'package:pointycastle/digests/sha512.dart';

/// Streamlined NTRU Prime `sntrup761`, the post-quantum KEM behind OpenSSH's
/// `sntrup761x25519-sha512` (its default exchange from 9.0 to 9.8, still
/// offered by 10.x). A faithful port of the public-domain "compact" reference
/// (Bernstein, Chuengsatiansup, Lange, van Vredendaal; supercop-20240808
/// crypto_kem/sntrup761/compact/kem.c, as vendored in OpenSSH sntrup761.c),
/// keeping its data-independent control flow: the sorting network, the
/// constant-time inversions and the masked implicit rejection.
///
/// Parameters: p = 761, q = 4591, w = 286. Sizes: public key 1158 bytes,
/// secret key 1763 bytes, ciphertext 1039 bytes, shared secret 32 bytes.
/// Dart integers are 64-bit, so the reference's int16 / int32 arithmetic
/// never overflows here; every shift is arithmetic on signed values as in
/// the C original.
class Sntrup761 {
  Sntrup761._();

  static const int p = 761;
  static const int q = 4591;
  static const int w = 286;
  static const int q12 = (q - 1) ~/ 2; // 2295
  static const int smallBytes = (p + 3) ~/ 4; // 191
  static const int roundedBytes = 1007;
  static const int rqBytes = 1158;
  static const int hashBytes = 32;
  static const int confirmBytes = 32;
  static const int secretKeysBytes = 2 * smallBytes; // 382

  static const int publicKeySize = rqBytes; // 1158
  static const int ciphertextSize = roundedBytes + confirmBytes; // 1039
  static const int secretKeySize =
      secretKeysBytes + publicKeySize + smallBytes + hashBytes; // 1763
  static const int sharedSecretSize = 32;

  // ── Public API ─────────────────────────────────────────────────

  /// crypto_kem_sntrup761_keypair. [random] must return cryptographically
  /// random bytes of the requested length.
  static ({Uint8List pk, Uint8List sk}) keyPair(Uint8List Function(int) random) {
    final pk = Uint8List(publicKeySize);
    final sk = Uint8List(secretKeySize);
    _zKeyGen(pk, sk, random);
    sk.setRange(secretKeysBytes, secretKeysBytes + publicKeySize, pk);
    final rhoOff = secretKeysBytes + publicKeySize;
    sk.setRange(rhoOff, rhoOff + smallBytes, random(smallBytes));
    sk.setRange(rhoOff + smallBytes, secretKeySize, _hashPrefix(4, pk));
    return (pk: pk, sk: sk);
  }

  /// crypto_kem_sntrup761_enc: ciphertext and shared secret for [pk].
  static ({Uint8List ciphertext, Uint8List sharedSecret}) encaps(
      Uint8List pk, Uint8List Function(int) random) {
    if (pk.length != publicKeySize) {
      throw ArgumentError('sntrup761 public key must be $publicKeySize bytes');
    }
    final cache = _hashPrefix(4, pk);
    final r = _shortRandom(random);
    final c = Uint8List(ciphertextSize);
    final rEnc = Uint8List(smallBytes);
    _hide(c, rEnc, r, pk, cache);
    return (ciphertext: c, sharedSecret: _hashSession(1, rEnc, c));
  }

  /// crypto_kem_sntrup761_dec: the shared secret for [c] under [sk]. A
  /// ciphertext that does not re-encrypt to itself yields the implicit
  /// rejection secret (hash of rho and c), never an error.
  static Uint8List decaps(Uint8List sk, Uint8List c) {
    if (sk.length != secretKeySize) {
      throw ArgumentError('sntrup761 secret key must be $secretKeySize bytes');
    }
    if (c.length != ciphertextSize) {
      throw ArgumentError('sntrup761 ciphertext must be $ciphertextSize bytes');
    }
    final pk = Uint8List.sublistView(
        sk, secretKeysBytes, secretKeysBytes + publicKeySize);
    final rhoOff = secretKeysBytes + publicKeySize;
    final rho = Uint8List.sublistView(sk, rhoOff, rhoOff + smallBytes);
    final cache = Uint8List.sublistView(sk, rhoOff + smallBytes, secretKeySize);
    final r = _zDecrypt(c, sk);
    final cNew = Uint8List(ciphertextSize);
    final rEnc = Uint8List(smallBytes);
    _hide(cNew, rEnc, r, pk, cache);
    final mask = _ciphertextsDiffMask(c, cNew); // -1 differ, 0 equal
    for (var i = 0; i < smallBytes; i++) {
      rEnc[i] ^= mask & (rEnc[i] ^ rho[i]);
    }
    return _hashSession(1 + mask, rEnc, c);
  }

  // ── Constant-time integer helpers ──────────────────────────────

  /// -1 when x != 0, else 0.
  static int _nonzeroMask(int x) => (x | -x) >> 63;

  /// -1 when x < 0, else 0.
  static int _negativeMask(int x) => x >> 63;

  /// Sort two values in place semantics: returns (min, max) without a branch.
  static int _minmaxLo = 0, _minmaxHi = 0;
  static void _minmax(int a, int b) {
    final c = b - a;
    final m = _negativeMask(c); // -1 when b < a
    final t = m & (a ^ b);
    _minmaxLo = a ^ t;
    _minmaxHi = b ^ t;
  }

  // ── Ring arithmetic ────────────────────────────────────────────

  /// x mod 3 into {-1, 0, 1}.
  static int _f3Freeze(int x) => x - 3 * ((10923 * x + 16384) >> 15);

  /// x mod q into {-q12, ..., q12}.
  static int _fqFreeze(int x) {
    const q16 = (0x10000 + q ~/ 2) ~/ q;
    const q20 = (0x100000 + q ~/ 2) ~/ q;
    const q28 = (0x10000000 + q ~/ 2) ~/ q;
    x -= q * ((q16 * x) >> 16);
    x -= q * ((q20 * x) >> 20);
    return x - q * ((q28 * x + 0x8000000) >> 28);
  }

  /// -1 when the weight of r is not w, else 0.
  static int _weightwMask(Int8List r) {
    var weight = 0;
    for (var i = 0; i < p; i++) {
      weight += r[i] & 1;
    }
    return _nonzeroMask(weight - w);
  }

  /// out = r mod 3 for each coefficient.
  static Int8List _r3FromRq(Int16List r) {
    final out = Int8List(p);
    for (var i = 0; i < p; i++) {
      out[i] = _f3Freeze(r[i]);
    }
    return out;
  }

  /// h = f * g in R3 = Z3[x]/(x^p - x - 1).
  static Int8List _r3Mult(Int8List f, Int8List g) {
    final fg = Int32List(p + p - 1);
    // No skipping of zero coefficients: f is secret-derived, so the work
    // must not depend on it (same shape as the reference).
    for (var i = 0; i < p; i++) {
      final fi = f[i];
      for (var j = 0; j < p; j++) {
        fg[i + j] += fi * g[j];
      }
    }
    for (var i = p; i < p + p - 1; i++) {
      fg[i - p] += fg[i];
    }
    for (var i = p; i < p + p - 1; i++) {
      fg[i - p + 1] += fg[i];
    }
    final h = Int8List(p);
    for (var i = 0; i < p; i++) {
      h[i] = _f3Freeze(fg[i]);
    }
    return h;
  }

  /// Constant-time inverse in R3; returns (out, ok) where ok is false when
  /// the input is not invertible.
  static (Int8List, bool) _r3Recip(Int8List input) {
    final f = Int32List(p + 1);
    final g = Int32List(p + 1);
    final v = Int32List(p + 1);
    final r = Int32List(p + 1);
    r[0] = 1;
    f[0] = 1;
    f[p - 1] = -1;
    f[p] = -1;
    for (var i = 0; i < p; i++) {
      g[p - 1 - i] = input[i];
    }
    g[p] = 0;
    var delta = 1;
    for (var loop = 0; loop < 2 * p - 1; loop++) {
      for (var i = p; i > 0; i--) {
        v[i] = v[i - 1];
      }
      v[0] = 0;
      final sign = -g[0] * f[0];
      final swap = _negativeMask(-delta) & _nonzeroMask(g[0]);
      delta ^= swap & (delta ^ -delta);
      delta += 1;
      for (var i = 0; i < p + 1; i++) {
        var t = swap & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
        t = swap & (v[i] ^ r[i]);
        v[i] ^= t;
        r[i] ^= t;
      }
      for (var i = 0; i < p + 1; i++) {
        g[i] = _f3Freeze(g[i] + sign * f[i]);
      }
      for (var i = 0; i < p + 1; i++) {
        r[i] = _f3Freeze(r[i] + sign * v[i]);
      }
      for (var i = 0; i < p; i++) {
        g[i] = g[i + 1];
      }
      g[p] = 0;
    }
    final sign = f[0];
    final out = Int8List(p);
    for (var i = 0; i < p; i++) {
      out[i] = sign * v[p - 1 - i];
    }
    return (out, _nonzeroMask(delta) == 0);
  }

  /// h = f * g with f in Rq and g small, in Rq = Zq[x]/(x^p - x - 1).
  static Int16List _rqMultSmall(Int16List f, Int8List g) {
    final fg = Int32List(p + p - 1);
    for (var i = 0; i < p; i++) {
      final fi = f[i];
      for (var j = 0; j < p; j++) {
        fg[i + j] += fi * g[j];
      }
    }
    for (var i = p; i < p + p - 1; i++) {
      fg[i - p] += fg[i];
    }
    for (var i = p; i < p + p - 1; i++) {
      fg[i - p + 1] += fg[i];
    }
    final h = Int16List(p);
    for (var i = 0; i < p; i++) {
      h[i] = _fqFreeze(fg[i]);
    }
    return h;
  }

  static Int16List _rqMult3(Int16List f) {
    final h = Int16List(p);
    for (var i = 0; i < p; i++) {
      h[i] = _fqFreeze(3 * f[i]);
    }
    return h;
  }

  /// a^(q-2) mod q, by repeated multiplication as in the reference.
  static int _fqRecip(int a1) {
    var i = 1;
    var ai = a1;
    while (i < q - 2) {
      ai = _fqFreeze(a1 * ai);
      i += 1;
    }
    return ai;
  }

  /// Constant-time inverse of 3 * input in Rq; returns (out, ok).
  static (Int16List, bool) _rqRecip3(Int8List input) {
    final f = Int32List(p + 1);
    final g = Int32List(p + 1);
    final v = Int32List(p + 1);
    final r = Int32List(p + 1);
    r[0] = _fqRecip(3);
    f[0] = 1;
    f[p - 1] = -1;
    f[p] = -1;
    for (var i = 0; i < p; i++) {
      g[p - 1 - i] = input[i];
    }
    g[p] = 0;
    var delta = 1;
    for (var loop = 0; loop < 2 * p - 1; loop++) {
      for (var i = p; i > 0; i--) {
        v[i] = v[i - 1];
      }
      v[0] = 0;
      final swap = _negativeMask(-delta) & _nonzeroMask(g[0]);
      delta ^= swap & (delta ^ -delta);
      delta += 1;
      for (var i = 0; i < p + 1; i++) {
        var t = swap & (f[i] ^ g[i]);
        f[i] ^= t;
        g[i] ^= t;
        t = swap & (v[i] ^ r[i]);
        v[i] ^= t;
        r[i] ^= t;
      }
      final f0 = f[0];
      final g0 = g[0];
      for (var i = 0; i < p + 1; i++) {
        g[i] = _fqFreeze(f0 * g[i] - g0 * f[i]);
      }
      for (var i = 0; i < p + 1; i++) {
        r[i] = _fqFreeze(f0 * r[i] - g0 * v[i]);
      }
      for (var i = 0; i < p; i++) {
        g[i] = g[i + 1];
      }
      g[p] = 0;
    }
    final scale = _fqRecip(f[0]);
    final out = Int16List(p);
    for (var i = 0; i < p; i++) {
      out[i] = _fqFreeze(scale * v[p - 1 - i]);
    }
    return (out, _nonzeroMask(delta) == 0);
  }

  /// Round each coefficient to the nearest multiple of 3.
  static Int16List _round(Int16List a) {
    final out = Int16List(p);
    for (var i = 0; i < p; i++) {
      out[i] = a[i] - _f3Freeze(a[i]);
    }
    return out;
  }

  // ── Sorting network (djbsort int32 portable4) ──────────────────

  static void _sortInt32(Int32List x, int n) {
    if (n < 2) return;
    var top = 1;
    while (top < n - top) {
      top += top;
    }
    for (var pp = top; pp >= 1; pp >>= 1) {
      var i = 0;
      while (i + 2 * pp <= n) {
        for (var j = i; j < i + pp; j++) {
          _minmax(x[j], x[j + pp]);
          x[j] = _minmaxLo;
          x[j + pp] = _minmaxHi;
        }
        i += 2 * pp;
      }
      for (var j = i; j < n - pp; j++) {
        _minmax(x[j], x[j + pp]);
        x[j] = _minmaxLo;
        x[j + pp] = _minmaxHi;
      }
      i = 0;
      var j = 0;
      for (var qq = top; qq > pp; qq >>= 1) {
        var done = false;
        if (j != i) {
          for (;;) {
            if (j == n - qq) {
              done = true;
              break;
            }
            var a = x[j + pp];
            for (var rr = qq; rr > pp; rr >>= 1) {
              _minmax(a, x[j + rr]);
              a = _minmaxLo;
              x[j + rr] = _minmaxHi;
            }
            x[j + pp] = a;
            ++j;
            if (j == i + pp) {
              i += 2 * pp;
              break;
            }
          }
        }
        if (done) continue;
        while (i + pp <= n - qq) {
          for (j = i; j < i + pp; j++) {
            var a = x[j + pp];
            for (var rr = qq; rr > pp; rr >>= 1) {
              _minmax(a, x[j + rr]);
              a = _minmaxLo;
              x[j + rr] = _minmaxHi;
            }
            x[j + pp] = a;
          }
          i += 2 * pp;
        }
        // now i + pp > n - qq
        j = i;
        while (j < n - qq) {
          var a = x[j + pp];
          for (var rr = qq; rr > pp; rr >>= 1) {
            _minmax(a, x[j + rr]);
            a = _minmaxLo;
            x[j + rr] = _minmaxHi;
          }
          x[j + pp] = a;
          ++j;
        }
      }
    }
  }

  /// Sort unsigned 32-bit values through the signed network.
  static void _sortUint32(Uint32List x, int n) {
    final s = Int32List(n);
    for (var j = 0; j < n; j++) {
      s[j] = (x[j] ^ 0x80000000).toSigned(32);
    }
    _sortInt32(s, n);
    for (var j = 0; j < n; j++) {
      x[j] = (s[j] ^ 0x80000000) & 0xffffffff;
    }
  }

  /// A weight-w vector in {-1, 0, 1}^p from p random 32-bit words.
  static Int8List _shortFromList(Uint32List input) {
    final l = Uint32List(p);
    for (var i = 0; i < w; i++) {
      l[i] = input[i] & 0xfffffffe;
    }
    for (var i = w; i < p; i++) {
      l[i] = (input[i] & 0xfffffffd) | 1;
    }
    _sortUint32(l, p);
    final out = Int8List(p);
    for (var i = 0; i < p; i++) {
      out[i] = (l[i] & 3) - 1;
    }
    return out;
  }

  static Uint32List _randomWords(Uint8List Function(int) random) {
    final bytes = random(4 * p);
    final words = Uint32List(p);
    for (var i = 0; i < p; i++) {
      words[i] = bytes[4 * i] |
          (bytes[4 * i + 1] << 8) |
          (bytes[4 * i + 2] << 16) |
          (bytes[4 * i + 3] << 24);
    }
    return words;
  }

  static Int8List _shortRandom(Uint8List Function(int) random) =>
      _shortFromList(_randomWords(random));

  static Int8List _smallRandom(Uint8List Function(int) random) {
    final l = _randomWords(random);
    final out = Int8List(p);
    for (var i = 0; i < p; i++) {
      out[i] = (((l[i] & 0x3fffffff) * 3) >> 30) - 1;
    }
    return out;
  }

  // ── Encoding (the reference's radix Encode / Decode) ───────────

  /// Encode(out, R, M, len): appends to [out] at [pos], returns the new pos.
  static int _encode(Uint8List out, int pos, Uint16List rr, Uint16List mm, int len) {
    if (len == 1) {
      var r = rr[0];
      var m = mm[0];
      while (m > 1) {
        out[pos++] = r & 0xff;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      return pos;
    }
    final r2 = Uint16List((len + 1) ~/ 2);
    final m2 = Uint16List((len + 1) ~/ 2);
    var i = 0;
    for (; i < len - 1; i += 2) {
      final m0 = mm[i];
      var r = rr[i] + rr[i + 1] * m0;
      var m = mm[i + 1] * m0;
      while (m >= 16384) {
        out[pos++] = r & 0xff;
        r >>= 8;
        m = (m + 255) >> 8;
      }
      r2[i ~/ 2] = r;
      m2[i ~/ 2] = m;
    }
    if (i < len) {
      r2[i ~/ 2] = rr[i];
      m2[i ~/ 2] = mm[i];
    }
    return _encode(out, pos, r2, m2, (len + 1) ~/ 2);
  }

  /// Decode(out, S, M, len): reads [s] from [pos]; returns the new pos.
  static int _decode(Uint16List out, Uint8List s, int pos, Uint16List mm, int len) {
    if (len == 1) {
      if (mm[0] == 1) {
        out[0] = 0;
      } else if (mm[0] <= 256) {
        out[0] = _modUint14(s[pos], mm[0]);
        pos += 1;
      } else {
        out[0] = _modUint14(s[pos] + (s[pos + 1] << 8), mm[0]);
        pos += 2;
      }
      return pos;
    }
    final half = (len + 1) ~/ 2;
    final r2 = Uint16List(half);
    final m2 = Uint16List(half);
    final bottomr = Uint16List(len ~/ 2);
    final bottomt = Uint32List(len ~/ 2);
    var i = 0;
    for (; i < len - 1; i += 2) {
      final m = mm[i] * mm[i + 1];
      if (m > 256 * 16383) {
        bottomt[i ~/ 2] = 256 * 256;
        bottomr[i ~/ 2] = s[pos] + 256 * s[pos + 1];
        pos += 2;
        m2[i ~/ 2] = (((m + 255) >> 8) + 255) >> 8;
      } else if (m >= 16384) {
        bottomt[i ~/ 2] = 256;
        bottomr[i ~/ 2] = s[pos];
        pos += 1;
        m2[i ~/ 2] = (m + 255) >> 8;
      } else {
        bottomt[i ~/ 2] = 1;
        bottomr[i ~/ 2] = 0;
        m2[i ~/ 2] = m;
      }
    }
    if (i < len) m2[i ~/ 2] = mm[i];
    pos = _decode(r2, s, pos, m2, half);
    var o = 0;
    for (i = 0; i < len - 1; i += 2) {
      var r = bottomr[i ~/ 2];
      r += bottomt[i ~/ 2] * r2[i ~/ 2];
      final (r1, r0) = _divmodUint14(r, mm[i]);
      out[o++] = r0;
      out[o++] = _modUint14(r1, mm[i + 1]);
    }
    if (i < len) out[o++] = r2[i ~/ 2];
    return pos;
  }

  /// Quotient and remainder of x (< 2^32) by m (< 2^14), branch-free.
  static (int, int) _divmodUint14(int x, int m) {
    final v = 0x80000000 ~/ m;
    var qpart = (x * v) >> 31;
    x -= qpart * m;
    var quot = qpart;
    qpart = (x * v) >> 31;
    x -= qpart * m;
    quot += qpart;
    x -= m;
    quot += 1;
    final mask = _negativeMask(x);
    x += mask & m;
    quot += mask;
    return (quot, x);
  }

  static int _modUint14(int x, int m) => _divmodUint14(x, m).$2;

  static Uint8List _smallEncode(Int8List f) {
    final s = Uint8List(smallBytes);
    var k = 0;
    for (var i = 0; i < p ~/ 4; i++) {
      var x = 0;
      for (var j = 0; j < 4; j++) {
        x += (f[k++] + 1) << (2 * j);
      }
      s[i] = x & 0xff;
    }
    s[p ~/ 4] = (f[k] + 1) & 0xff;
    return s;
  }

  static Int8List _smallDecode(Uint8List s, int off) {
    final f = Int8List(p);
    var k = 0;
    for (var i = 0; i < p ~/ 4; i++) {
      final x = s[off + i];
      for (var j = 0; j < 4; j++) {
        f[k++] = ((x >> (2 * j)) & 3) - 1;
      }
    }
    f[k] = (s[off + p ~/ 4] & 3) - 1;
    return f;
  }

  static Uint8List _rqEncode(Int16List r) {
    final rr = Uint16List(p);
    final mm = Uint16List(p);
    for (var i = 0; i < p; i++) {
      rr[i] = r[i] + q12;
      mm[i] = q;
    }
    final s = Uint8List(rqBytes);
    final end = _encode(s, 0, rr, mm, p);
    assert(end == rqBytes);
    return s;
  }

  static Int16List _rqDecode(Uint8List s) {
    final rr = Uint16List(p);
    final mm = Uint16List(p);
    for (var i = 0; i < p; i++) {
      mm[i] = q;
    }
    _decode(rr, s, 0, mm, p);
    final r = Int16List(p);
    for (var i = 0; i < p; i++) {
      r[i] = rr[i] - q12;
    }
    return r;
  }

  static void _roundedEncode(Uint8List s, Int16List r) {
    final rr = Uint16List(p);
    final mm = Uint16List(p);
    for (var i = 0; i < p; i++) {
      rr[i] = ((r[i] + q12) * 10923) >> 15;
      mm[i] = (q + 2) ~/ 3;
    }
    final end = _encode(s, 0, rr, mm, p);
    assert(end == roundedBytes);
  }

  static Int16List _roundedDecode(Uint8List s) {
    final rr = Uint16List(p);
    final mm = Uint16List(p);
    for (var i = 0; i < p; i++) {
      mm[i] = (q + 2) ~/ 3;
    }
    _decode(rr, s, 0, mm, p);
    final r = Int16List(p);
    for (var i = 0; i < p; i++) {
      r[i] = rr[i] * 3 - q12;
    }
    return r;
  }

  // ── KEM building blocks ────────────────────────────────────────

  static void _zKeyGen(Uint8List pk, Uint8List sk, Uint8List Function(int) random) {
    Int8List g;
    Int8List ginv;
    for (;;) {
      g = _smallRandom(random);
      final (inv, ok) = _r3Recip(g);
      if (ok) {
        ginv = inv;
        break;
      }
    }
    final f = _shortRandom(random);
    final (finv, _) = _rqRecip3(f);
    final h = _rqMultSmall(finv, g);
    pk.setAll(0, _rqEncode(h));
    sk.setRange(0, smallBytes, _smallEncode(f));
    sk.setRange(smallBytes, 2 * smallBytes, _smallEncode(ginv));
  }

  static void _zEncrypt(Uint8List cOut, Int8List r, Uint8List pk) {
    final h = _rqDecode(pk);
    final c = _round(_rqMultSmall(h, r));
    _roundedEncode(cOut, c);
  }

  static Int8List _zDecrypt(Uint8List c, Uint8List sk) {
    final f = _smallDecode(sk, 0);
    final v = _smallDecode(sk, smallBytes);
    final cc = _roundedDecode(c);
    // Decrypt(r, c, f, ginv)
    final cf = _rqMultSmall(cc, f);
    final cf3 = _rqMult3(cf);
    final e = _r3FromRq(cf3);
    final ev = _r3Mult(e, v);
    final mask = _weightwMask(ev);
    final r = Int8List(p);
    for (var i = 0; i < w; i++) {
      r[i] = ((ev[i] ^ 1) & ~mask) ^ 1;
    }
    for (var i = w; i < p; i++) {
      r[i] = ev[i] & ~mask;
    }
    return r;
  }

  /// Hash_prefix: SHA-512(b || in), first 32 bytes.
  static Uint8List _hashPrefix(int b, Uint8List input) {
    final d = SHA512Digest();
    d.updateByte(b);
    d.update(input, 0, input.length);
    final full = Uint8List(64);
    d.doFinal(full, 0);
    return Uint8List.sublistView(full, 0, hashBytes);
  }

  static Uint8List _hashConfirm(Uint8List rEnc, Uint8List cache) {
    final x = Uint8List(2 * hashBytes);
    x.setRange(0, hashBytes, _hashPrefix(3, rEnc));
    x.setRange(hashBytes, 2 * hashBytes, cache);
    return _hashPrefix(2, x);
  }

  static Uint8List _hashSession(int b, Uint8List y, Uint8List z) {
    final x = Uint8List(hashBytes + ciphertextSize);
    x.setRange(0, hashBytes, _hashPrefix(3, y));
    x.setRange(hashBytes, x.length, z);
    return Uint8List.fromList(_hashPrefix(b, x));
  }

  static void _hide(Uint8List c, Uint8List rEnc, Int8List r, Uint8List pk,
      Uint8List cache) {
    rEnc.setAll(0, _smallEncode(r));
    _zEncrypt(c, r, pk);
    c.setRange(ciphertextSize - confirmBytes, ciphertextSize,
        _hashConfirm(rEnc, cache));
  }

  /// -1 when the ciphertexts differ, 0 when equal.
  static int _ciphertextsDiffMask(Uint8List c, Uint8List c2) {
    var differentbits = 0;
    for (var i = 0; i < ciphertextSize; i++) {
      differentbits |= c[i] ^ c2[i];
    }
    return _nonzeroMask(differentbits);
  }
}
