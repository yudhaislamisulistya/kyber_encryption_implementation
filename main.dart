import 'dart:convert';

import 'package:kyber/kyber.dart';
import 'package:encrypt/encrypt.dart';

void main() {
  try {
    // Mengukur performa untuk Kyber.k512()
    measurePerformance(Kyber.k512());

    // Mengukur performa untuk Kyber.k768()
    measurePerformance(Kyber.k768());

    // Mengukur performa untuk Kyber.k1024()
    measurePerformance(Kyber.k1024());
  } catch (e) {
    print(e);
  }
}

void measurePerformance(Kyber kyber) {
  var keyGenStopwatch = Stopwatch()..start();

  // Generate keys
  KyberGenerationResult keyPair = kyber.generateKeys();
  keyGenStopwatch.stop();

  var publicKey = keyPair.publicKey.bytes;

  var encryptStopwatch = Stopwatch()..start();
  // Encrypt
  KyberEncryptionResult encapsulated = kyber.encrypt(publicKey);
  var symmetricKey = encapsulated.sharedSecret.bytes;
  encryptStopwatch.stop();

  String symmetricKeyBase64 = base64Encode(symmetricKey);

  String data = "aA1&📙:)";

  var encryptAESStopwatch = Stopwatch()..start();
  print("symmetricKeyBase64 (${kyber.level}): $symmetricKeyBase64");
  // Encrypt using AES
  String encryptedData = encryptAES(symmetricKeyBase64, data);
  encryptAESStopwatch.stop();

  var decryptAESStopwatch = Stopwatch()..start();
  // Decrypt using AES
  String decryptedData = decryptAES(symmetricKeyBase64, encryptedData);
  decryptAESStopwatch.stop();

  var totalTime = keyGenStopwatch.elapsedMicroseconds + encryptStopwatch.elapsedMicroseconds + encryptAESStopwatch.elapsedMicroseconds + decryptAESStopwatch.elapsedMicroseconds;

  var totalMilliseconds = totalTime / 1000;

  String formattedKeyGen = '${(keyGenStopwatch.elapsedMicroseconds ~/ 60000).toString().padLeft(2, '0')}.${((keyGenStopwatch.elapsedMicroseconds % 60000) ~/ 1000).toString().padLeft(2, '0')}.${(keyGenStopwatch.elapsedMicroseconds % 1000).toString().padLeft(2, '0')} ms';
  var encryptTime = encryptAESStopwatch.elapsedMicroseconds;
  String formattedEncrypt = '${(encryptTime ~/ 60000).toString().padLeft(2, '0')}.${((encryptTime % 60000) ~/ 1000).toString().padLeft(2, '0')}.${(encryptTime % 1000).toString().padLeft(2, '0')} ms';
  String formattedDecrypt = '${(decryptAESStopwatch.elapsedMicroseconds ~/ 60000).toString().padLeft(2, '0')}.${((decryptAESStopwatch.elapsedMicroseconds % 60000) ~/ 1000).toString().padLeft(2, '0')}.${(decryptAESStopwatch.elapsedMicroseconds % 1000).toString().padLeft(2, '0')} ms';
  print("Encryption Data (${kyber.level}): $encryptedData");
  print("Key Generation (${kyber.level}): $formattedKeyGen");
  print("Encryption (${kyber.level}): $formattedEncrypt");
  print("Decryption (${kyber.level}): $formattedDecrypt");
  print("Decrypted Data (${kyber.level}): $decryptedData");
  print("");
}

// ignore_for_file: avoid_print

// Fixed IV for simplicity
const String fixedIV = "QUJDREVGR0hJSktMTU5PUA=="; // This is a 16-byte IV encoded in base64

// Encrypt Function
String encryptAES(String base64Key, String plaintext) {
  try {
    final key = Key.fromBase64(base64Key);
    final iv = IV.fromBase64(fixedIV);

    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: 'PKCS7'));
    final encrypted = encrypter.encrypt(plaintext, iv: iv);

    return encrypted.base64;
  } catch (e) {
    print(e);
    return "";
  }
}

// Decrypt Function
String decryptAES(String base64Key, String ciphertext) {
  try {
    final key = Key.fromBase64(base64Key);
    final iv = IV.fromBase64(fixedIV);

    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: 'PKCS7'));
    final decrypted = encrypter.decrypt(Encrypted.from64(ciphertext), iv: iv);

    return decrypted;
  } catch (e) {
    print(e);
    return "";
  }
}
