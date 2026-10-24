import 'dart:io';
import 'package:archive/archive.dart';
import 'package:path/path.dart' as p;

void extract(Archive archive, String out) {
  for (final file in archive) {
    final target = p.normalize(p.join(out, file.name));
    if (!p.isWithin(out, target)) continue;
    File(target).writeAsBytesSync(file.content as List<int>);
  }
}
