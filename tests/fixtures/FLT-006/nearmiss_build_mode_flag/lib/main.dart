// Every debugging switch is tied to the build mode, so release builds pass false.
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';
import 'package:webview_flutter_wkwebview/webview_flutter_wkwebview.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await InAppWebViewController.setWebContentsDebuggingEnabled(!kReleaseMode);
  runApp(const App());
}

final iosController = WebKitWebViewController(WebKitWebViewControllerCreationParams())
  ..setInspectable(kDebugMode);

final settings = InAppWebViewSettings(
  javaScriptEnabled: true,
  isInspectable: kDebugMode,
);

const hint = 'call setWebContentsDebuggingEnabled(true) only in debug';
