import 'dart:io';

Future<Process> play(String playerCmd, String filePath) => Process.start(playerCmd, [filePath]);
