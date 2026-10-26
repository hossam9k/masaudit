// Dio 4 adapter hook, a multi-line arrow callback, and a block-bodied named function, all trusting every certificate.
import 'dart:io';

import 'package:dio/adapter.dart';
import 'package:dio/dio.dart';

bool _allowAll(X509Certificate cert, String host, int port) {
  return true;
}

Dio createDio(String baseUrl) {
  final dio = Dio(BaseOptions(baseUrl: baseUrl));
  (dio.httpClientAdapter as DefaultHttpClientAdapter).onHttpClientCreate = (HttpClient client) {
    client.badCertificateCallback =
        (X509Certificate cert, String host, int port) =>
            true;
    return client;
  };
  return dio;
}

HttpClient uploadClient() {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 20);
  client.badCertificateCallback = _allowAll;
  return client;
}
