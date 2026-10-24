import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:pretty_dio_logger/pretty_dio_logger.dart';

Dio buildClient() {
  final dio = Dio();
  dio.interceptors.add(PrettyDioLogger(requestHeader: true, requestBody: true));
  dio.interceptors.add(LogInterceptor(requestBody: true, logPrint: (o) => debugPrint('$o')));
  dio.interceptors.add(LogInterceptor());
  if (kDebugMode) {
    dio.interceptors.add(PrettyDioLogger());
  }
  return dio;
}
