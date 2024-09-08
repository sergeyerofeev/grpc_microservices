import 'dart:async';
import 'dart:developer';

import 'package:grpc/grpc.dart';

import 'data/grpc_interceptors.dart';
import 'domain/auth_rpc.dart';
import 'utils/env.dart' as env;
import 'utils/utils.dart' as utils;

Future<void> startServer() async {
  runZonedGuarded(() async {
    final authServer = Server.create(
      services: [AuthRpc()],
      interceptors: <Interceptor>[GrpcInterceptors.tokenInterceptors],
      codecRegistry: CodecRegistry(codecs: [GzipCodec()]),
    );
    await authServer.serve(port: env.authPort);
    log('Server listen port ${authServer.port}');
    // Иницилизируем подключение к БД и сразу закрываем соединение
    env.connection = await utils.createConnection();
    await env.connection.close();
  }, (error, stack) {
    log('Error', error: error);
  });
}
