// The callback only returns true when the leaf certificate matches a pinned SHA-256 fingerprint.
import 'dart:io';

import 'package:crypto/crypto.dart';

const _pinnedFingerprint = 'replace-with-sha256-of-leaf-der';

bool _alwaysRetry(Object error) => true;

bool _matchesPin(X509Certificate cert, String host, int port) {
  if (host != 'api.acme.example') return false;
  final fingerprint = sha256.convert(cert.der).toString();
  return fingerprint == _pinnedFingerprint;
}

HttpClient pinnedClient() {
  final context = SecurityContext(withTrustedRoots: false);
  final client = HttpClient(context: context);
  client.badCertificateCallback = _matchesPin;
  client.badCertificateCallback = (cert, host, port) {
    final ok = _matchesPin(cert, host, port);
    return ok;
  };
  // client.badCertificateCallback = (cert, host, port) => true;
  return client;
}
