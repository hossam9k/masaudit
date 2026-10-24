import 'dart:io';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;

void extract(Archive archive, String out) {
  for (final file in archive) {
    File(p.join(out, file.name)).writeAsBytesSync(file.content as List<int>);
  }
}
