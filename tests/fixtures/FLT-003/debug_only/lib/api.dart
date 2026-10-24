import 'package:dio/dio.dart';
import 'package:pretty_dio_logger/pretty_dio_logger.dart';

Dio buildClient() {
  final dio = Dio();
  assert(() {
    dio.interceptors.add(PrettyDioLogger(requestHeader: true));
    return true;
  }());
  return dio;
}
