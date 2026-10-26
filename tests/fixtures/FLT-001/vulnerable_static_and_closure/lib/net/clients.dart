// A static method on a policy class and a closure held in a variable, both trusting every certificate.
import 'dart:io';

class TlsPolicy {
  static bool acceptAll(X509Certificate c, String h, int p) => true;
}

final _trustAll = (c, h, p) => true;

HttpClient apiClient() {
  final client = HttpClient();
  client.badCertificateCallback = TlsPolicy.acceptAll;
  return client;
}

HttpClient uploadClient() {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 20);
  client.badCertificateCallback = _trustAll;
  return client;
}
