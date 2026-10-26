// File access on with JavaScript left disabled.
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

WebViewController offlineHelp() {
  final controller = WebViewController()..setJavaScriptMode(JavaScriptMode.disabled);
  (controller.platform as AndroidWebViewController).setAllowFileAccess(true);
  return controller;
}
