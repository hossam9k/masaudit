import 'package:dio/dio.dart';
import 'package:pretty_dio_logger/pretty_dio_logger.dart';

Dio buildClient() {
  final dio = Dio();
  // dio 5: the default logPrint only prints inside assert(), so release builds stay quiet.
  dio.interceptors.add(LogInterceptor());
  dio.interceptors.add(LogInterceptor(requestHeader: false, responseHeader: false, logPrint: print));
  dio.interceptors.add(PrettyDioLogger(responseBody: false));
  // dio.interceptors.add(PrettyDioLogger());
  return dio;
}
