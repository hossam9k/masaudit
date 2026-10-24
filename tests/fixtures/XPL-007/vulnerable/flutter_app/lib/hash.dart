import 'dart:convert';

import 'package:crypto/crypto.dart';

String passwordHash(String password) => md5.convert(utf8.encode(password)).toString();
String tokenFingerprint(List<int> token) => sha1.convert(token).toString();
