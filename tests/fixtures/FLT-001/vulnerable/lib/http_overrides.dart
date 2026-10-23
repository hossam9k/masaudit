import 'dart:io';

class DevHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

HttpClient legacyClient() {
  final client = HttpClient();
  client.badCertificateCallback = ((cert, host, port) {
    return true;
  });
  return client;
}

bool _acceptAny(X509Certificate cert, String host, int port) => true;

HttpClient referenceClient() => HttpClient()..badCertificateCallback = _acceptAny;
