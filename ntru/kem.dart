// ignore_for_file: unnecessary_new, prefer_interpolation_to_compose_strings, avoid_print

import './ntru.dart';
import './polynomial.dart';
import './helper.dart';
import './hash.dart';
import 'dart:convert';

List<String> generateSecretKey(String selfPublicKeyString, String privF, String privFp, String receiverPublicKeyString) {
  NTRU ntru = NTRU();
  int N = ntru.N;

  ntru = NTRU.fromKeyPair(Polynomial.fromCommaSeparatedCoefficients(N, selfPublicKeyString).encodeCoefficientsToCommaSeparatedValue(), privF, privFp);

  Polynomial r = generateRandomPolynomial(N);
  List<int> key = generateRandomInts(32); // Ensures 256-bit key
  Polynomial msg = listOfIntToPolynomial(key, N);
  Polynomial receiverPublicKey = Polynomial.fromCommaSeparatedCoefficients(N, receiverPublicKeyString);
  Polynomial encrypted = r.multPolyMod2048(receiverPublicKey).addPolyMod2048(msg);

  String keySession = base64.encode(key);
  List<int> keySessionHash = sha256bytes(keySession);
  Polynomial encryptedHash = r.multPolyMod2048(receiverPublicKey).addPolyMod2048(listOfIntToPolynomial(keySessionHash, N));

  return [keySession, encrypted.encodeCoefficientsToCommaSeparatedValue(), encryptedHash.encodeCoefficientsToCommaSeparatedValue()];
}

String decryptSecretKey(String selfPublicKeyString, String privF, String privFp, String receiverPublicKeyString, String encryptedKey, String hash) {
  NTRU ntru = NTRU();
  int N = ntru.N;

  ntru = NTRU.fromKeyPair(Polynomial.fromCommaSeparatedCoefficients(N, selfPublicKeyString).encodeCoefficientsToCommaSeparatedValue(), privF, privFp);

  try {
    Polynomial encryptedKeyPoly = Polynomial.fromCommaSeparatedCoefficients(N, encryptedKey);
    Polynomial key = ntru.decrypt(encryptedKeyPoly);
    List<int> decodedKeySession = polynomialToListOfInt(key, numChunks: 32);
    String keySession = base64.encode(decodedKeySession);

    Polynomial polyHash = Polynomial.fromCommaSeparatedCoefficients(N, hash);
    List<int> hashResult = polynomialToListOfInt(ntru.decrypt(polyHash), numChunks: 32);
    List<int> hashCheck = sha256bytes(keySession);

    if (hashResult.length != hashCheck.length) {
      return "";
    }
    return keySession;
  } catch (e) {
    print("Error decrypting key session: $e");
    return "";
  }
}
