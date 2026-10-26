// A static local file viewer: file access on but JavaScript off, mixed content in compatibility mode.
import 'package:flutter/foundation.dart';
import 'package:flutter_inappwebview/flutter_inappwebview.dart';

const _note = 'Do not set allowUniversalAccessFromFileURLs: true here';

Widget termsViewer(String path) => InAppWebView(
      initialFile: path,
      initialSettings: InAppWebViewSettings(
        javaScriptEnabled: false,
        allowFileAccess: true,
        allowFileAccessFromFileURLs: kDebugMode,
        allowContentAccess: true,
        mixedContentMode: MixedContentMode.MIXED_CONTENT_COMPATIBILITY_MODE,
      ),
    );
