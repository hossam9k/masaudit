import 'package:firebase_analytics/firebase_analytics.dart';

Future<void> identify(String email) => FirebaseAnalytics.instance.setUserId(id: email);
