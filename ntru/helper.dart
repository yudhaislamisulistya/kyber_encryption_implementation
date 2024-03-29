// ignore_for_file: unnecessary_new, non_constant_identifier_names, prefer_conditional_assignment, avoid_function_literals_in_foreach_calls

import 'dart:math';
import 'dart:convert';
import 'polynomial.dart';

Polynomial mod2ToModPowerOfTwo(Polynomial a, Polynomial Fq, int mod) {
  int v = 2;
  while (v < mod) {
    v *= 2;
    Polynomial temp = Fq;
    temp = temp.multiplyInt(2).reduce(v);
    Fq = (a.multPolyModPowerOfTwo(Fq, mod)).multPolyModPowerOfTwo(Fq, mod);
    temp = temp.substractPoly(Fq, v);
    Fq = temp;
  }
  return Fq;
}

Polynomial inverseF2(Polynomial a) {
  List<int> coeffA = List.from(a.coefficients);
  coeffA.add(0); // padding
  a = new Polynomial(a.N + 1, coeffA);
  int N = a.N - 1;
  int k = 0;
  Polynomial b = Polynomial.fromDegree(N + 1, d: 0);
  Polynomial c = Polynomial.fromDegree(N + 1, d: 0, coeff: 0);
  Polynomial f = a;
  Polynomial g = new Polynomial.fromDegree(a.N, d: N);
  g.coefficients[0] = -1; // x^N - 1 what ? https://github.com/tbuktu/ntru/blob/78334321f544b9357e7417e935fb4b1a61264976/src/main/java/net/sf/ntru/polynomial/IntegerPolynomial.java#L410

  while (true) {
    while (f.coefficients[0] == 0) {
      /* f(x) = f(x) / x */
      for (int i = 1; i < f.N; i++) {
        f.coefficients[i - 1] = f.coefficients[i];
      }
      f.coefficients[f.N - 1] = 0;

      /* c(x) = c(x) * x */
      for (int i = c.N - 1; i > 0; i--) {
        c.coefficients[i] = c.coefficients[i - 1];
      }
      c.coefficients[0] = 0;

      k++;
      if (f.isZero()) throw new Exception('Not invertible 1');
    }
    if (f.isOne()) break;
    if (f.getDegree() < g.getDegree()) {
      // exchange f and g
      Polynomial temp = f;
      f = g;
      g = temp;
      // exchange b and c
      temp = b;
      b = c;
      c = temp;
    }
    f = f.addPolyModPowerOfTwo(g, 2);
    b = b.addPolyModPowerOfTwo(c, 2);
  }
  if (b.coefficients[N] != 0) {
    throw new Exception('Not invertible 2');
  }
  // Fq(x) = x^(N-k) * b(x)
  Polynomial Fq = Polynomial.fromDegree(N, d: 0, coeff: 0);
  int j = 0;
  k %= N;
  for (int i = N - 1; i >= 0; i--) {
    j = i - k;
    if (j < 0) j += N;
    Fq.coefficients[j] = b.coefficients[i];
  }
  return Fq;
}

Polynomial inverseFq(Polynomial a, int q) {
  Polynomial Fq = inverseF2(a);
  return mod2ToModPowerOfTwo(a, Fq, q);
}

Polynomial inverseF3(Polynomial a) {
  List<int> coeffA = List.from(a.coefficients);
  coeffA.add(0); // padding
  a = new Polynomial(a.N + 1, coeffA);
  int N = a.N - 1;
  int k = 0;
  Polynomial b = Polynomial.fromDegree(N + 1, d: 0);
  Polynomial c = Polynomial.fromDegree(N + 1, d: 0, coeff: 0);
  Polynomial f = a;
  Polynomial g = new Polynomial.fromDegree(a.N, d: N);
  g.coefficients[0] = -1; // x^N - 1

  while (true) {
    while (f.coefficients[0] == 0) {
      /* f(x) = f(x) / x */
      for (int i = 1; i < f.N; i++) {
        f.coefficients[i - 1] = f.coefficients[i];
      }
      f.coefficients[f.N - 1] = 0;

      /* c(x) = c(x) * x */
      for (int i = c.N - 1; i > 0; i--) {
        c.coefficients[i] = c.coefficients[i - 1];
      }
      c.coefficients[0] = 0;

      k++;
      if (f.isZero()) throw new Exception('Not invertible 3');
    }
    if (f.isOne()) break;
    if (f.getDegree() < g.getDegree()) {
      // exchange f and g
      Polynomial temp = f;
      f = g;
      g = temp;
      // exchange b and c
      temp = b;
      b = c;
      c = temp;
    }
    if (f.coefficients[0] == g.coefficients[0]) {
      f = f.substractPolyModInt(g, 3);
      b = b.substractPolyModInt(c, 3);
    } else {
      f = f.addPolyModInt(g, 3);
      b = b.addPolyModInt(c, 3);
    }
  }
  if (b.coefficients[N] != 0) {
    throw new Exception('Not invertible 4');
  }
  // Fp(x) = [+-] x^(N-k) * b(x)
  Polynomial Fp = Polynomial.fromDegree(N, d: 0, coeff: 0);
  int j = 0;
  k %= N;
  for (int i = N - 1; i >= 0; i--) {
    j = i - k;
    if (j < 0) j += N;
    Fp.coefficients[j] = (f.coefficients[0] * b.coefficients[i]) % 3;
  }
  return Fp;
}

Polynomial inverseFint(Polynomial a, int mod) {
  List<int> coeffA = List.from(a.coefficients);
  coeffA.add(0); // padding
  a = new Polynomial(a.N + 1, coeffA);
  int N = a.N - 1;
  int k = 0;
  Polynomial b = Polynomial.fromDegree(N + 1, d: 0);
  Polynomial c = Polynomial.fromDegree(N + 1, d: 0, coeff: 0);
  Polynomial f = a;
  Polynomial g = new Polynomial.fromDegree(a.N, d: N);
  g.coefficients[0] = -1; // x^N - 1

  while (true) {
    while (f.coefficients[0] == 0) {
      /* f(x) = f(x) / x */
      for (int i = 1; i < f.N; i++) {
        f.coefficients[i - 1] = f.coefficients[i];
      }
      f.coefficients[f.N - 1] = 0;

      /* c(x) = c(x) * x */
      for (int i = c.N - 1; i > 0; i--) {
        c.coefficients[i] = c.coefficients[i - 1];
      }
      c.coefficients[0] = 0;

      k++;
      if (f.isZero()) throw new Exception('Not invertible 3');
    }
    if (f.isOne()) break;
    if (f.getDegree() < g.getDegree()) {
      // exchange f and g
      Polynomial temp = f;
      f = g;
      g = temp;
      // exchange b and c
      temp = b;
      b = c;
      c = temp;
    }
    if (f.coefficients[0] == g.coefficients[0]) {
      f = f.substractPolyModInt(g, mod);
      b = b.substractPolyModInt(c, mod);
    } else {
      f = f.addPolyModInt(g, mod);
      b = b.addPolyModInt(c, mod);
    }
  }
  if (b.coefficients[N] != 0) {
    throw new Exception('Not invertible 4');
  }
  // Fp(x) = [+-] x^(N-k) * b(x)
  Polynomial Fp = Polynomial.fromDegree(N, d: 0, coeff: 0);
  int j = 0;
  k %= N;
  for (int i = N - 1; i >= 0; i--) {
    j = i - k;
    if (j < 0) j += N;
    Fp.coefficients[j] = (f.coefficients[0] * b.coefficients[i]) % mod;
  }
  return Fp;
}

List<int> randomCoefficients(int length, int d, int neg_ones_diff) {
  List<int> zeros = List.filled(length - 2 * d - neg_ones_diff, 0);
  List<int> ones = List.filled(d, 1);
  List<int> neg_ones = List.filled(d + neg_ones_diff, -1);
  List<int> result = List.from(zeros)
    ..addAll(ones)
    ..addAll(neg_ones);
  result.shuffle();
  return result;
}

List<int> randomBinaryCoefficients(int length, int d) {
  List<int> zeros = List.filled(length - d, 0);
  List<int> ones = List.filled(d, 1);
  List<int> result = List.from(zeros)..addAll(ones);
  result.shuffle();
  return result;
}

List<int> randomTrinaryCoefficients(int length, int d, int neg_ones_diff) {
  List<int> zeros = List.filled(length - 2 * d - neg_ones_diff, 0);
  List<int> ones = List.filled(d, 1);
  List<int> neg_ones = List.filled(d + neg_ones_diff, -1);
  List<int> result = List.from(zeros)
    ..addAll(ones)
    ..addAll(neg_ones);
  result.shuffle();
  return result;
}

Polynomial generateRandomPolynomial(int N, {List<int>? options}) {
  List<int> coeff = List.filled(N, 0);
  if (options == null) {
    options = [-1, 0, 1];
  }
  Random rand = new Random();
  for (int i = 0; i < N; i++) {
    coeff[i] = options[rand.nextInt(options.length)];
  }

  return new Polynomial(N, coeff);
}

Polynomial generateRandomBinaryPolynomialWithD(int N, int d) {
  List<int> coeff = randomBinaryCoefficients(N, (N / 3).floor());
  return new Polynomial(N, coeff);
}

Polynomial generateRandomTrinaryPolynomialWithD(int N, int d) {
  List<int> coeff = randomTrinaryCoefficients(N, (N / 3).floor(), -1);
  return new Polynomial(N, coeff);
}

bool comparePoly(Polynomial a, Polynomial b) {
  for (int i = 0; i < a.N; i++) {
    if (a.coefficients[i] != b.coefficients[i]) return false;
  }
  return true;
}

List<int> generateRandomInts(int n) {
  var random = Random.secure();
  var values = List<int>.generate(n, (i) => random.nextInt(256));
  return values;
}

String generateRandomBytes(int n) {
  var random = Random.secure();
  var values = List<int>.generate(n, (i) => random.nextInt(256));
  return base64.encode(values);
}

Polynomial listOfIntToPolynomial(List<int> ints, int N) {
  List<int> coeffs = new List.filled(N, 0);
  int idx = 0;
  ints.forEach((element) {
    List<int> tmp = element.toRadixString(2).padLeft(8, '0').split('').map((val) => int.parse(val)).toList();
    for (int i = 0; i < tmp.length; i++) {
      coeffs[idx + i] = tmp[i];
    }
    idx += tmp.length;
  });
  return new Polynomial(N, coeffs);
}

List<int> polynomialToListOfInt(Polynomial a, {int numChunks = 16}) {
  List<int> bytes = [];
  int currentByte = 0;
  int bitIndex = 0;
  int byteCount = 0;

  for (int i = 0; i < a.coefficients.length && byteCount < numChunks; i++) {
    int bit = a.coefficients[i];
    if (bit < 0 || bit > 1) {
      bit = 0;
    }

    currentByte = (currentByte << 1) | bit;
    bitIndex++;

    if (bitIndex == 8) {
      bytes.add(currentByte);
      currentByte = 0;
      bitIndex = 0;
      byteCount++;
    }
  }

  if (bitIndex != 0 && byteCount < numChunks) {
    bytes.add(currentByte << (8 - bitIndex));
  }

  return bytes;
}
