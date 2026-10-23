import 'package:encrypt/encrypt.dart';

// Encrypter(AES(key, mode: AESMode.cbc)) was replaced by GCM.
Encrypter modern(Key key) => Encrypter(AES(key, mode: AESMode.gcm));
