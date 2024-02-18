// ignore_for_file: avoid_print

import 'package:encrypt/encrypt.dart';

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
