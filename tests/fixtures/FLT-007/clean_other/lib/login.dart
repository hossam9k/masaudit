import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:local_auth/local_auth.dart';

Future<String> login(String url) => FlutterWebAuth2.authenticate(url: url, callbackUrlScheme: 'demo');

Future<bool> hasBiometrics() => LocalAuthentication().canCheckBiometrics;
