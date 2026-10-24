import 'package:grpc/grpc.dart';

final channel = ClientChannel('api.demo-bank.com', port: 443,
    options: const ChannelOptions(credentials: ChannelCredentials.insecure()));
