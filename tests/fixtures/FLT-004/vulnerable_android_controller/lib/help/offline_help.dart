// webview_flutter's Android controller with file access on, and JavaScript unrestricted.
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

WebViewController offlineHelp() {
  final controller = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);
  if (controller.platform is AndroidWebViewController) {
    (controller.platform as AndroidWebViewController).setAllowFileAccess(true);
  }
  return controller;
}

Future<WebViewController> receiptViewer() async {
  final controller = WebViewController();
  await controller.setJavaScriptMode(JavaScriptMode.unrestricted);
  final android = controller.platform as AndroidWebViewController;
  await android
      .setAllowFileAccess(true);
  return controller;
}
