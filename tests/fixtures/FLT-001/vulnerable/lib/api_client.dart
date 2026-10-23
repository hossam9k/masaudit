import 'dart:io';

import 'package:dio/dio.dart';
import 'package:dio/io.dart';

Dio buildDio() {
  final dio = Dio();
  dio.httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () {
      final client = HttpClient();
      client.badCertificateCallback = (cert, host, port) => true;
      return client;
    },
  );
  return dio;
}
