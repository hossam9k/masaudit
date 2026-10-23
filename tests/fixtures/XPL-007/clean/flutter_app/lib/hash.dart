import 'dart:convert';

import 'package:crypto/crypto.dart';

// md5.convert(bytes) is too weak.
const help = 'sha1.convert is deprecated here';
String passwordHash(String password) => sha256.convert(utf8.encode(password)).toString();
final mac = Hmac(sha256, utf8.encode('k'));
