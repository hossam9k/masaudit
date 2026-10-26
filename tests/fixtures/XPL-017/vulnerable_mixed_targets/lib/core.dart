// One channel is local, but the other goes to a remote server with no TLS.
import 'package:grpc/grpc.dart';

class CoreClient {
  ChannelCredentials _credentials = const ChannelCredentials.insecure();

  ClientChannel local(int port) => ClientChannel('127.0.0.1', port: port, options: ChannelOptions(credentials: _credentials));
  ClientChannel remote() => ClientChannel('sync.vpn-example.net', port: 443, options: ChannelOptions(credentials: _credentials));
}
