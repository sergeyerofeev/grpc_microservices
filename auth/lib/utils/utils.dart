library;

import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';
import 'package:grpc/grpc.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';
import 'package:postgres/postgres.dart';
import 'package:process_run/shell_run.dart';

import 'env.dart' as env;
import '../generated/auth.pbgrpc.dart';

//------------------------------------------------------------------------------
// Проверяем переданную строку с именем пользователя
String isUsernameValid(String username) {
  // Проверяем имя пользователя на пустую строку
  if (username.isEmpty) {
    throw GrpcError.custom(452, 'Пожалуйста введите имя пользователя');
  }
  // Проверяем имя пользователя на допустимые символы
  if (!RegExp(r'^[А-ЯЁа-яёA-Za-z\d_-]+$').hasMatch(username)) {
    throw GrpcError.custom(452, 'Имя пользователя содержит недопустимые символы');
  }
  return username;
}

//------------------------------------------------------------------------------
// Проверяем переданную строку с email и шифруем её
String encryptEmail(String email) {
  final value = _isEmailValid(email);

  final key = Key.fromUtf8(env.dbSk);
  final iv = IV.fromLength(16);
  final encryptor = Encrypter(AES(key, mode: AESMode.ecb));

  return encryptor.encrypt(value, iv: iv).base64;
}

// Расшифровываем строку содержащую зашифрованный email
String decryptEmail(String encryptedEmail) {
  final key = Key.fromUtf8(env.dbSk);
  final iv = IV.fromLength(16);
  final encryptor = Encrypter(AES(key, mode: AESMode.ecb));

  return encryptor.decrypt64(encryptedEmail, iv: iv);
}

// Проверяем переданную строку с email
String _isEmailValid(String email) {
  // Проверяем email на пустую строку
  if (email.isEmpty) {
    throw GrpcError.custom(453, 'Пожалуйста введите email');
  }
  // Проверяем email на допустимые символы
  if (!RegExp(r'^[.\da-z_@-]+$').hasMatch(email)) {
    throw GrpcError.custom(453, 'Строка email содержит недопустимые символы');
  }
  // Проверяем корректный ли email
  if (!RegExp(
          r'^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$')
      .hasMatch(email)) {
    throw GrpcError.custom(453, 'Некорректный email');
  }
  return email;
}

//------------------------------------------------------------------------------
// Проверяем строку пароля и получаем hash, для усиления добавив jwtSk
String getHashPassword(String password) {
  final passValid = _isPasswordValid(password);
  final bytes = utf8.encode(passValid + env.jwtSk);
  return sha256.convert(bytes).toString();
}

// Проверяем переданную строку с паролем пользователя
String _isPasswordValid(String password) {
  // Проверяем пароль на пустую строку
  if (password.isEmpty) {
    throw GrpcError.custom(454, 'Пожалуйста введите пароль');
  }
  // Проверяем длину пароля, если менее 6 символов отправляем ошибку
  if (password.length < 6) {
    throw GrpcError.custom(454, 'Слишком короткий пароль');
  }
  // Проверяем password на допустимые символы
  if (!RegExp(r'^[А-ЯЁа-яёA-Za-z\d_-]+$').hasMatch(password)) {
    throw GrpcError.custom(454, 'Строка пароля содержит недопустимые символы');
  }
  return password;
}

//------------------------------------------------------------------------------
// Извлекаем id из метаданных запроса от клиента
int getIdFromMetadata(ServiceCall serviceCall) {
  final accessToken = serviceCall.clientMetadata?['access_token'] ?? '';
  return getIdFromToken(accessToken);
}

// Извлекаем id пользователя из строки token
int getIdFromToken(String token) {
  final jwtClaim = verifyJwtHS256Signature(token, env.jwtSk);
  final id = int.tryParse(jwtClaim['user_id']);
  if (id == null) {
    throw GrpcError.dataLoss('Ошибка при передаче данных');
  }
  return id;
}

//------------------------------------------------------------------------------
// Проверяем соединение с БД
Future<Connection> createConnection() async {
  late Connection connection;
  // Соединение с БД ещё не установлено, либо docker контейнер не запущен
  while (true) {
    try {
      connection = await Connection.open(
        env.endpoint,
        settings: ConnectionSettings(sslMode: SslMode.disable),
      );
      break;
    } on SocketException {
      // При неудачном подключения к БД, перезапустим docker контейнера с PostgreSQL
      await Shell().run('docker restart ${env.dbContainerName}');
      await Future.delayed(Duration(seconds: 5), () {});
    }
  }
  return connection;
}

//------------------------------------------------------------------------------
// На основе полученного из БД id пользователя создаём новые токены
Future<TokensDto> createTokens(int id) async {
  final accessTokenSet = JwtClaim(
    maxAge: Duration(hours: env.accessTokenLife),
    otherClaims: {'user_id': id.toString()},
  );
  final refreshTokenSet = JwtClaim(
    maxAge: Duration(hours: env.refreshTokenLife),
    otherClaims: {'user_id': id.toString()},
  );

  final tokensDto = TokensDto()
    ..accessToken = issueJwtHS256(accessTokenSet, env.jwtSk)
    ..refreshToken = issueJwtHS256(refreshTokenSet, env.jwtSk);

  return tokensDto;
}

//------------------------------------------------------------------------------