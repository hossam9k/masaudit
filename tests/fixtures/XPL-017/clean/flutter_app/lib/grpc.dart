import 'package:grpc/grpc.dart';

final channel = ClientChannel('localhost', port: 50051,
    options: const ChannelOptions(credentials: ChannelCredentials.insecure()));
