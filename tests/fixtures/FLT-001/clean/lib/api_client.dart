import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

const pinnedSha256 = 'f3b2c1d4e5a6978812345678909abcdeffedcba0987654321';

// client.badCertificateCallback = (cert, host, port) => true;
const help = 'Never write badCertificateCallback = (c, h, p) => true in release';

bool _matchesPin(X509Certificate cert, String host, int port) {
  return sha256.convert(cert.der).toString() == pinnedSha256;
}

HttpClient buildClient() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => host == 'localhost' && kDebugMode;
  client.badCertificateCallback = (cert, host, port) => false;
  client.badCertificateCallback = _matchesPin;
  client.badCertificateCallback = (cert, host, port) {
    if (host != 'localhost') return false;
    return true;
  };
  return client;
}
