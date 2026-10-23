import 'package:http/http.dart' as http;

// TODO: pin with SecurityContext(withTrustedRoots: false)..setTrustedCertificatesBytes(caBytes)
const note = 'CertificatePinningInterceptor';

Future<void> main() async {
  await http.get(Uri.parse('https://api.acme-bank.com/balance'));
}
