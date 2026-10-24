import 'package:flutter/foundation.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

Future<void> setUp(WebViewController controller) async {
  await InAppWebViewController.setWebContentsDebuggingEnabled(kDebugMode);
  final settings = InAppWebViewSettings(isInspectable: false);
  (controller.platform as WebKitWebViewController).setInspectable(kDebugMode);
  // AndroidWebViewController.enableDebugging(true);
}
