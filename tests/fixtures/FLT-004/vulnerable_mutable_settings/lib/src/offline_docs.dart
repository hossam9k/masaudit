// Settings built as an object then mutated, plus an InAppBrowser opening a bundled file.
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

InAppWebViewSettings offlineDocSettings() {
  final settings = InAppWebViewSettings();
  settings.allowFileAccess = true;
  settings.allowUniversalAccessFromFileURLs = true;
  settings.mixedContentMode = MixedContentMode.MIXED_CONTENT_ALWAYS_ALLOW;
  return settings;
}

Future<void> openReceipt(InAppBrowser browser, String path) async {
  await browser.openFile(
    assetFilePath: path,
    settings: InAppBrowserClassSettings(
      webViewSettings: InAppWebViewSettings(
        allowFileAccessFromFileURLs: true,
      ),
    ),
  );
}
