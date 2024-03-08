import 'dart:convert';

import 'kyber/aes.dart';
import 'kyber/kyber.dart';
import 'ntru/kem.dart';
import 'ntru/ntru.dart';
import 'ntru/polynomial.dart';

String selfPrivateKeyF = "";
String selfPrivateKeyFp = "";
String selfPublicKey = "";

void main() {
  try {
    measurePerformanceKyber(Kyber.k512(), "a");
    measurePerformanceKyber(Kyber.k768(), "a");
    measurePerformanceKyber(Kyber.k1024(), "a");
    measurePerformanceNTRU("a");
  } catch (e) {
    print(e);
  }
}

void measurePerformanceNTRU(String data) {
  // Generate keys
  // stopWatch for key generation
  var keyGenStopwatch = Stopwatch()..start();
  NTRU ntru = NTRU();
  List<Polynomial> privateKey = ntru.privateKey;

  selfPublicKey = ntru.publicKey.encodeCoefficientsToCommaSeparatedValue();
  selfPrivateKeyF = privateKey[0].encodeCoefficientsToCommaSeparatedValue();
  selfPrivateKeyFp = privateKey[1].encodeCoefficientsToCommaSeparatedValue();
  keyGenStopwatch.stop();

  // Encrypt
  var encryptStopwatchKem = Stopwatch()..start();
  List<String> kemResult = generateSecretKey(selfPublicKey, selfPrivateKeyF, selfPrivateKeyFp, selfPublicKey);
  encryptStopwatchKem.stop();

  String keySession = kemResult[0];

  var encryptStopwatchAES = Stopwatch()..start();
  String encryptedContent = encryptAES(keySession, data);
  encryptStopwatchAES.stop();

  // Decrypt
  var decryptStopwatchKem = Stopwatch()..start();
  try {
    decryptSecretKey(selfPublicKey, selfPrivateKeyF, selfPrivateKeyFp, selfPublicKey, kemResult[1], kemResult[2]);
  } catch (e) {
    print(e);
  }
  decryptStopwatchKem.stop();
  var decryptStopwatchAES = Stopwatch()..start();
  String decryptedContent = decryptAES(keySession, encryptedContent);
  decryptStopwatchAES.stop();

  String formattedKeyGen = '${(keyGenStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedEncryptKEM = '${(encryptStopwatchKem.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedEncryptAES = '${(encryptStopwatchAES.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedDecryptKEM = '${(decryptStopwatchKem.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedDecryptAES = '${(decryptStopwatchAES.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedEncryptAll = '${(encryptStopwatchKem.elapsedMicroseconds / 1000000 + encryptStopwatchAES.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedDecryptAll = '${(decryptStopwatchKem.elapsedMicroseconds / 1000000 + decryptStopwatchAES.elapsedMicroseconds / 1000000).toString()} detik';

  print("SymetricKeyBase64: $keySession");
  print("Encrypted Data NTRU: $encryptedContent");
  print("Key Generation NTRU: $formattedKeyGen");
  print("Encryption ALL NTRU: $formattedEncryptAll");
  print("Encryption KEM NTRU: $formattedEncryptKEM");
  print("Encryption AES NTRU: $formattedEncryptAES");
  print("Decryption ALL NTRU: $formattedDecryptAll");
  print("Decryption KEM NTRU: $formattedDecryptKEM");
  print("Decryption AES NTRU: $formattedDecryptAES");
  print("Decrypted Data NTRU: $decryptedContent");
}

void measurePerformanceKyber(Kyber kyber, String data) {
  var keyGenStopwatch = Stopwatch()..start();

  // Generate keys
  KyberGenerationResult keyPair = kyber.generateKeys();
  keyGenStopwatch.stop();

  var publicKey = keyPair.publicKey.bytes;

  var encryptsKEMStopwatch = Stopwatch()..start();
  // Encrypt
  KyberEncryptionResult encapsulated = kyber.encrypt(publicKey);
  var symmetricKey = encapsulated.sharedSecret.bytes;

  String symmetricKeyBase64 = base64Encode(symmetricKey);
  encryptsKEMStopwatch.stop();

  var encryptAESStopwatch = Stopwatch()..start();
  print("symmetricKeyBase64 (${kyber.level}): $symmetricKeyBase64");
  // Encrypt using AES
  String encryptedData = encryptAES(symmetricKeyBase64, data);
  encryptAESStopwatch.stop();

  var decryptAESStopwatch = Stopwatch()..start();
  // Decrypt using AES
  String decryptedData = decryptAES(symmetricKeyBase64, encryptedData);
  decryptAESStopwatch.stop();

  var decryptKEMStopwatch = Stopwatch()..start();
  kyber.encrypt(publicKey);
  decryptKEMStopwatch.stop();

  String formattedKeyGen = '${(keyGenStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedEncryptKEM = '${(encryptsKEMStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedEncryptAES = '${(encryptAESStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedDecryptAES = '${(decryptAESStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedDecryptKEM = '${(decryptKEMStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedEncrypt = '${(encryptsKEMStopwatch.elapsedMicroseconds / 1000000 + encryptAESStopwatch.elapsedMicroseconds / 1000000).toString()} detik';
  String formattedDecrypt = '${(decryptKEMStopwatch.elapsedMicroseconds / 1000000 + decryptAESStopwatch.elapsedMicroseconds / 1000000).toString()} detik';

  print("Encryption Data (${kyber.level}): $encryptedData");
  print("Key Generation (${kyber.level}): $formattedKeyGen");
  print("Encryption ALL (${kyber.level}): $formattedEncrypt");
  print("Encryption KEM (${kyber.level}): $formattedEncryptKEM");
  print("Encryption AES (${kyber.level}): $formattedEncryptAES");
  print("Decryption ALL (${kyber.level}): $formattedDecrypt");
  print("Decryption KEM (${kyber.level}): $formattedDecryptKEM");
  print("Decryption AES (${kyber.level}): $formattedDecryptAES");
  print("Decrypted Data (${kyber.level}): $decryptedData");
  print("");
}

// ignore_for_file: avoid_print


