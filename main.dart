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
  var encryptStopwatch = Stopwatch()..start();
  List<String> kemResult = generateSecretKey(selfPublicKey, selfPrivateKeyF, selfPrivateKeyFp, selfPublicKey);

  String keySession = kemResult[0];

  String encryptedContent = encryptAES(keySession, data);
  encryptStopwatch.stop();

  // Decrypt
  var decryptStopwatch = Stopwatch()..start();
  try {
    decryptSecretKey(selfPublicKey, selfPrivateKeyF, selfPrivateKeyFp, selfPublicKey, kemResult[1], kemResult[2]);
  } catch (e) {
    print(e);
  }
  String decryptedContent = decryptAES(keySession, encryptedContent);
  decryptStopwatch.stop();

  String formattedKeyGen = '${(keyGenStopwatch.elapsedMicroseconds ~/ 60000).toString().padLeft(2, '0')}.${((keyGenStopwatch.elapsedMicroseconds % 60000) ~/ 1000).toString().padLeft(2, '0')}.${(keyGenStopwatch.elapsedMicroseconds % 1000).toString().padLeft(2, '0')} ms';
  var encryptTime = encryptStopwatch.elapsedMicroseconds;
  String formattedEncrypt = '${(encryptTime ~/ 60000).toString().padLeft(2, '0')}.${((encryptTime % 60000) ~/ 1000).toString().padLeft(2, '0')}.${(encryptTime % 1000).toString().padLeft(2, '0')} ms';
  String formattedDecrypt = '${(decryptStopwatch.elapsedMicroseconds ~/ 60000).toString().padLeft(2, '0')}.${((decryptStopwatch.elapsedMicroseconds % 60000) ~/ 1000).toString().padLeft(2, '0')}.${(decryptStopwatch.elapsedMicroseconds % 1000).toString().padLeft(2, '0')} ms';

  print("SymetricKeyBase64: $keySession");
  print("Encrypted Data NTRU: $encryptedContent");
  print("Key Generation NTRU: $formattedKeyGen");
  print("Encryption NTRU: $formattedEncrypt");
  print("Decryption NTRU: $formattedDecrypt");
  print("Decrypted Data NTRU: $decryptedContent");
}

void measurePerformanceKyber(Kyber kyber, String data) {
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

  var encryptAESStopwatch = Stopwatch()..start();
  print("symmetricKeyBase64 (${kyber.level}): $symmetricKeyBase64");
  // Encrypt using AES
  String encryptedData = encryptAES(symmetricKeyBase64, data);
  encryptAESStopwatch.stop();

  var decryptAESStopwatch = Stopwatch()..start();
  // Decrypt using AES
  String decryptedData = decryptAES(symmetricKeyBase64, encryptedData);
  decryptAESStopwatch.stop();

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


