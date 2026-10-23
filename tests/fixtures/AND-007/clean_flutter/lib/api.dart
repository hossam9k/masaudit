import 'dart:io';

import 'package:flutter/services.dart';

Future<HttpClient> pinnedClient() async {
  final ca = await rootBundle.load('assets/certs/acme_intermediate.pem');
  final context = SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(ca.buffer.asUint8List());
  return HttpClient(context: context);
}
