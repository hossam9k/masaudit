import 'package:hive/hive.dart';

Future<void> save(String token) async {
  final box = await Hive.openBox('session');
  await box.put('access_token', token);
}
