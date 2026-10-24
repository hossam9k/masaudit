import 'package:local_auth/local_auth.dart';

final auth = LocalAuthentication();

Future<bool> unlockVault() => auth.authenticate(localizedReason: 'Unlock your vault');

Future<bool> confirmPayment() => LocalAuthentication().authenticate(localizedReason: 'Confirm payment');
