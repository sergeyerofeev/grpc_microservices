import 'dart:async';

import 'package:auth/utils/env.dart' as env;
import 'package:grpc/grpc.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';

final _excludeMethods = ['SignIn', 'SignUp', 'RefreshToken'];

abstract class GrpcInterceptors {
  GrpcInterceptors._();

  static FutureOr<GrpcError?> tokenInterceptors(
    ServiceCall call,
    ServiceMethod serviceMethod,
  ) {
    try {
      if (_excludeMethods.contains(serviceMethod.name)) {
        return null;
      }
      final token = call.clientMetadata?['access_token'] ?? '';
      final jwtClaim = verifyJwtHS256Signature(token, env.jwtSk);
      jwtClaim.validate();
      return null;
    } catch (e) {
      if (e == JwtException.tokenExpired) {
        return GrpcError.custom(460, 'Пройдите повторную аутентификацию');
      }
      return GrpcError.unauthenticated('Пройдите повторную аутентификацию');
    }
  }
}
