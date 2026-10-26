// The app talks to its own core process over the loopback address; nothing leaves the device.
import 'package:grpc/grpc.dart';

class CoreClient {
  ChannelCredentials _credentials = const ChannelCredentials.insecure();

  ClientChannel open(int port) => ClientChannel('127.0.0.1', port: port, options: ChannelOptions(credentials: _credentials));
}
