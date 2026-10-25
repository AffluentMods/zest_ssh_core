import 'dart:typed_data';

import 'package:meta/meta.dart';

final _byteMask = BigInt.from(0xff);
final _negativeFlag = BigInt.from(0x80);

/// Decode a big integer with arbitrary sign.
/// When:
/// sign == 0: Zero regardless of magnitude
/// sign < 0: Negative
/// sign > 0: Positive
@internal
BigInt decodeBigIntWithSign(int sign, List<int> magnitude) {
  if (sign == 0) {
    return BigInt.zero;
  }

  BigInt result;

  if (magnitude.length == 1) {
    result = BigInt.from(magnitude[0]);
  } else {
    result = BigInt.from(0);
    for (var i = 0; i < magnitude.length; i++) {
      var item = magnitude[magnitude.length - i - 1];
      result |= (BigInt.from(item) << (8 * i));
    }
  }

  if (result != BigInt.zero) {
    result = sign < 0
        ? result.toSigned(result.bitLength)
        : result.toUnsigned(result.bitLength);
  }
  return result;
}

/// Encode a BigInt into bytes using big-endian encoding.
/// It encodes the integer to a minimal twos-compliment integer as defined by
/// ASN.1
@internal
Uint8List encodeBigInt(BigInt? number) {
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }

  int needsPaddingByte;
  int rawSize;

  if (number! > BigInt.zero) {
    rawSize = (number.bitLength + 7) >> 3;
    needsPaddingByte =
        ((number >> (rawSize - 1) * 8) & _negativeFlag) == _negativeFlag
            ? 1
            : 0;
  } else {
    needsPaddingByte = 0;
    rawSize = (number.bitLength + 8) >> 3;
  }

  final size = rawSize + needsPaddingByte;
  var result = Uint8List(size);
  for (var i = 0; i < rawSize; i++) {
    result[size - i - 1] = (number! & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}

/// [base] to the power of [exponent], modulo [modulus], by squaring and
/// multiplying, with nothing of a big number but `*` and `%`.
///
/// This is what `BigInt.modPow` is for, and it is not used: in the Dart SDK
/// (3.10.8 on x64, as a script and compiled) it answers wrong for some
/// numbers. Not for numbers picked at random; but for any odd modulus of
/// 192 bits or more there are bases, which anybody can compute from the
/// modulus, whose powers it gets wrong, and the numbers of a key exchange
/// and the signature that is checked are the other side's to pick. `*` and
/// `%` were right for every number they were tried with.
///
/// The exponent must not be negative and the modulus must be positive, as
/// for `BigInt.modPow`. A group of 2048 bits to a power of 256 bits takes
/// under a millisecond this way on a desktop, and one of 8192 bits about
/// ten (measured; half as much again as `BigInt.modPow`). How long it takes
/// goes by the bits of the exponent, as it does for `BigInt.modPow`: an
/// exponent that is a secret is for one exchange and no more, which is how
/// a key exchange uses it.
@internal
BigInt modPowExact(BigInt base, BigInt exponent, BigInt modulus) {
  if (exponent.isNegative) {
    throw ArgumentError.value(exponent, 'exponent', 'must not be negative');
  }
  if (modulus <= BigInt.zero) {
    throw ArgumentError.value(modulus, 'modulus', 'must be positive');
  }
  var result = BigInt.one;
  // From the highest bit down: square, and multiply where the bit is set.
  // (There is one bit at the least, so what comes out is below the modulus.)
  final bits = exponent.toRadixString(2);
  for (var i = 0; i < bits.length; i++) {
    result = (result * result) % modulus;
    if (bits.codeUnitAt(i) == 0x31) result = (result * base) % modulus;
  }
  return result;
}

/// Encode as Big Endian unsigned byte array.
@internal
Uint8List encodeBigIntAsUnsigned(BigInt number) {
  if (number == BigInt.zero) {
    return Uint8List.fromList([0]);
  }
  var size = number.bitLength + (number.isNegative ? 8 : 7) >> 3;
  var result = Uint8List(size);
  for (var i = 0; i < size; i++) {
    result[size - i - 1] = (number & _byteMask).toInt();
    number = number >> 8;
  }
  return result;
}
