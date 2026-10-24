import 'package:flutter/services.dart';

Future<void> copyName(String displayName) => Clipboard.setData(ClipboardData(text: displayName));
Future<void> copyCode(String recoveryCode) async {
  await Clipboard.setData(ClipboardData(text: recoveryCode));
  Future.delayed(const Duration(seconds: 30), () => Clipboard.setData(const ClipboardData(text: '')));
}
