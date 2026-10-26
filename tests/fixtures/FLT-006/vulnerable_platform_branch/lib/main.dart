// Debugging enabled at startup behind a platform check (not a build-mode check), and in cascades and settings.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter_wkwebview/webview_flutter_wkwebview.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (Platform.isAndroid) {
    await InAppWebViewController.setWebContentsDebuggingEnabled(true);
  }
  runApp(const App());
}

final iosController = WebKitWebViewController(WebKitWebViewControllerCreationParams())
  ..setInspectable(true);

final settings = InAppWebViewSettings(
  javaScriptEnabled: true,
  isInspectable: true,
);
