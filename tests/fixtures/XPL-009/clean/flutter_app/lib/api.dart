const baseUrl = 'https://api.acme-bank.com/v1';
final balance = Uri.https('api.acme-bank.com', '/v1/balance');
final emulator = Uri.http('10.0.2.2:8080', '/v1/balance');
final local = 'http://localhost:8080';
// const old = 'http://api.acme-bank.com/v1';
String url(String host) => 'http://$host/v1';
