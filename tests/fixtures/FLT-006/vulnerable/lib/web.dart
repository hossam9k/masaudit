import 'package:flutter/foundation.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

Future<void> setUp(WebViewController controller) async {
  await InAppWebViewController.setWebContentsDebuggingEnabled(true);
  final settings = InAppWebViewSettings(isInspectable: true);
  AndroidWebViewController.enableDebugging(true);
  (controller.platform as WebKitWebViewController).setInspectable(true);
  if (kDebugMode) {
    await InAppWebViewController.setWebContentsDebuggingEnabled(true);
  }
}
