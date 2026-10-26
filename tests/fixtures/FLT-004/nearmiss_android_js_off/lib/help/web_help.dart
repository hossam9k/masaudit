// JavaScript unrestricted with file access turned off.
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

WebViewController webHelp() {
  final controller = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);
  (controller.platform as AndroidWebViewController).setAllowFileAccess(false);
  return controller;
}
