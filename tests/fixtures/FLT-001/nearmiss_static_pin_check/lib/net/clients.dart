// A static method and a closure variable that compare the certificate with a pin, so they don't trust everything.
import 'dart:io';

import 'package:crypto/crypto.dart';

class TlsPolicy {
  static const _pins = {'pinned-leaf-fingerprint'};

  static bool pinned(X509Certificate c, String h, int p) => _pins.contains(sha256.convert(c.der).toString());
}

final _localOnly = (X509Certificate c, String host, int p) => host == 'localhost';

HttpClient apiClient() {
  final client = HttpClient();
  client.badCertificateCallback = TlsPolicy.pinned;
  return client;
}

HttpClient devClient() {
  final client = HttpClient();
  client.badCertificateCallback = _localOnly;
  return client;
}
