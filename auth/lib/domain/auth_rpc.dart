import 'package:grpc/grpc.dart';
import 'package:jaguar_jwt/jaguar_jwt.dart';
import 'package:postgres/postgres.dart';

import '../generated/auth.pbgrpc.dart';
import '../utils/env.dart' as env;
import '../utils/utils.dart' as utils;

class AuthRpc extends AuthRpcServiceBase {
  String query = '';
  Map<String, dynamic> parameters = {};

  //----------------------------------------------------------------------------
  // Регистрация пользователя
  @override
  Future<TokensDto> signUp(ServiceCall call, UserDto request) async {
    // Проверяем строку с username
    final username = utils.isUsernameValid(request.username);
    // Проверяем и шифруем строку с email
    final encryptedEmail = utils.encryptEmail(request.email);
    // Проверяем и шифруем строку с password
    final hashPassword = utils.getHashPassword(request.password);

    if (env.connection.isOpen == false) {
      // Соединение с БД ещё не установлено, либо docker контейнер не запущен
      env.connection = await utils.createConnection();
    }

    // Транзакция на проверку и сохранение данных пользователя
    int id = await env.connection.runTx<int>((connection) async {
      try {
        // Проверяем наличие пользователя с данным username в БД
        query = 'SELECT 1 FROM users WHERE username = @username FOR UPDATE';
        parameters = {'username': username};
        Result result = await connection.execute(Sql.named(query), parameters: parameters);

        if (result.isNotEmpty) {
          throw GrpcError.custom(452, 'Указанное имя уже используется');
        }

        // Проверяем на совпадение шифрованной стороки с email и данными в БД
        query = 'SELECT 1 FROM users WHERE email = @email FOR UPDATE';
        parameters = {'email': encryptedEmail};
        result = await connection.execute(Sql.named(query), parameters: parameters);

        if (result.isNotEmpty) {
          throw GrpcError.custom(453, 'Указанный email уже используется');
        }

        // Сохраняем нового пользователя в БД
        query = 'INSERT INTO users(username, email, upassword) VALUES (@username, @email, @password) RETURNING id';
        parameters = {'username': username, 'email': encryptedEmail, 'password': hashPassword};
        result = await connection.execute(Sql.named(query), parameters: parameters);

        if (result.affectedRows == 0) {
          throw GrpcError.custom(454, 'Ошибка при сохранении данных');
        }

        return result[0][0] as int;
      } on GrpcError {
        rethrow;
      } catch (e) {
        throw GrpcError.custom(455, 'Неизвестная ошибка при сохранении данных');
      }
    });

    // На основе полученного из БД id сохранённого пользователя, создаём токены
    final tokensDto = await utils.createTokens(id);

    // Сгенерированный refreshToken сохраняем в БД для данного пользователя
    query = 'UPDATE users SET utoken = @token WHERE id = @id';
    parameters = {'id': id, 'token': tokensDto.refreshToken};
    await env.connection.execute(Sql.named(query), parameters: parameters);
    // Закрываем соединение с БД
    await env.connection.close();

    return tokensDto;
  }

  //----------------------------------------------------------------------------
  // Вход при помощи email и password
  @override
  Future<TokensDto> signIn(ServiceCall call, UserDto request) async {
    // Проверяем и шифруем строку с email
    final encryptedEmail = utils.encryptEmail(request.email);
    // Проверяем и шифруем строку с password
    final hashPassword = utils.getHashPassword(request.password);

    if (env.connection.isOpen == false) {
      // Соединение с БД ещё не установлено, либо docker контейнер не запущен
      env.connection = await utils.createConnection();
    }

    query = 'SELECT id, email, upassword FROM users WHERE email = @email';
    parameters = {'email': encryptedEmail};
    Result result = await env.connection.execute(Sql.named(query), parameters: parameters);

    if (result.isEmpty) {
      throw GrpcError.custom(453, 'Указанный email не найден');
    }

    if (hashPassword != result[0][2]) {
      throw GrpcError.custom(454, 'Не верный пароль');
    }

    // На основании полученного из БД id пользователя, создаём токены
    final id = result[0][0] as int;
    final tokensDto = await utils.createTokens(id);

    // Сгенерированный refreshToken сохраняем в БД для данного пользователя
    query = 'UPDATE users SET utoken = @token WHERE id = @id';
    parameters = {'id': id, 'token': tokensDto.refreshToken};
    await env.connection.execute(Sql.named(query), parameters: parameters);
    // Закрываем соединение с БД
    await env.connection.close();

    return tokensDto;
  }

  //----------------------------------------------------------------------------
  // Обновляем данные пользователя
  @override
  Future<UserDto> updateUser(ServiceCall call, UserDto request) async {
    // Извлекаем id из переданного access_token
    final id = utils.getIdFromMetadata(call);

    // Если в request не указан столбец для обновления, присваиваем переменной null,
    // т.е. в запросе, благодаря функции COALESCE значение в столбце останется без изменения
    String? username = request.username.isEmpty ? null : utils.isUsernameValid(request.username);
    String? encryptedEmail = request.email.isEmpty ? null : utils.encryptEmail(request.email);
    String? hashPassword = request.password.isEmpty ? null : utils.getHashPassword(request.password);

    if (username == null && encryptedEmail == null && hashPassword == null) {
      throw GrpcError.custom(456, 'Не передано уникальных данных для обновления');
    }

    if (env.connection.isOpen == false) {
      // Соединение с БД ещё не установлено, либо docker контейнер не запущен
      env.connection = await utils.createConnection();
    }

    // Транзакция на проверку и обновления данных пользователя
    await env.connection.runTx((connection) async {
      try {
        if (username != null) {
          // Проверяем наличие пользователя с данным username в БД
          query = 'SELECT id FROM users WHERE username = @username FOR UPDATE';
          parameters = {'username': username};
          final result = await connection.execute(Sql.named(query), parameters: parameters);

          if (result.affectedRows == 1) {
            if (result[0][0] != id) {
              throw GrpcError.custom(452, 'Указанное имя уже используется');
            } else {
              // В запросе пользователь передал своё имя, ингорируем
              username = null;
            }
          }
        }
        if (encryptedEmail != null) {
          // Проверяем на совпадение шифрованной стороки с email и данными в БД
          query = 'SELECT id FROM users WHERE email = @email FOR UPDATE';
          parameters = {'email': encryptedEmail};
          final result = await connection.execute(Sql.named(query), parameters: parameters);

          if (result.affectedRows == 1) {
            if (result[0][0] != id) {
              throw GrpcError.custom(453, 'Указанный email уже используется');
            } else {
              // В запросе пользователь передал свой email, ингорируем
              encryptedEmail = null;
            }
          }
        }
        if (username == null && encryptedEmail == null && hashPassword == null) {
          throw GrpcError.custom(456, 'Не передано уникальных данных для обновления');
        }
        query = '''
                    UPDATE users SET 
                      username = COALESCE(@username, username),
                      email = COALESCE(@email, email),
                      upassword = COALESCE(@password, upassword)
                    WHERE id = @id
                ''';
        parameters = {'id': id, 'username': username, 'email': encryptedEmail, 'password': hashPassword};
        final result = await connection.execute(Sql.named(query), parameters: parameters);

        if (result.affectedRows == 0) {
          throw GrpcError.custom(454, 'Ошибка при сохранении данных');
        }
      } on GrpcError {
        rethrow;
      } catch (e) {
        throw GrpcError.custom(455, 'Неизвестная ошибка при обновлении данных');
      }
    });
    // Получим username обновлённого пользователя
    query = 'SELECT username FROM users WHERE id = @id';
    parameters = {'id': id};
    final result = await env.connection.execute(Sql.named(query), parameters: parameters);

    if (result.isEmpty) {
      throw GrpcError.notFound('Пользователь не найден');
    }

    // Закрываем соединение с БД
    await env.connection.close();

    return UserDto()
      ..id = id.toString()
      ..username = result[0][0] as String;
  }

  //----------------------------------------------------------------------------
  // Удаляем данные пользователя из БД
  @override
  Future<ResponseDto> deleteUser(ServiceCall call, RequestDto request) async {
    final id = utils.getIdFromMetadata(call);

    if (env.connection.isOpen == false) {
      // Соединение с БД ещё не установлено, либо docker контейнер не запущен
      env.connection = await utils.createConnection();
    }

    // Удаляем пользователя по id
    query = 'DELETE FROM users WHERE id = @id';
    parameters = {'id': id};
    final result = await env.connection.execute(Sql.named(query), parameters: parameters);

    if (result.affectedRows == 0) {
      throw GrpcError.notFound('Пользователь не найден');
    }
    return ResponseDto()..id = id.toString();
  }

  //----------------------------------------------------------------------------
  // Получение новой пары токенов, при истечении времени жизни access_token
  @override
  Future<TokensDto> refreshToken(ServiceCall call, TokensDto request) async {
    if (request.refreshToken.isEmpty) {
      throw GrpcError.custom(461, 'Ошибка при передаче данных');
    }
    // Получаем из запроса refresh_token
    final refreshToken = request.refreshToken;
    try {
      final jwtClaim = verifyJwtHS256Signature(refreshToken, env.jwtSk);
      // Проверяем время жизни refresh_token, если истекло, повторная аутентификация
      jwtClaim.validate();
    } catch (e) {
      throw GrpcError.unauthenticated('Пройдите повторную аутентификацию');
    }

    // refresh_token валидный, дальше необходимо сравнить его с token сохранённым в БД,
    // если разные refresh_token похищен
    final id = utils.getIdFromToken(request.refreshToken);

    if (env.connection.isOpen == false) {
      // Соединение с БД ещё не установлено, либо docker контейнер не запущен
      env.connection = await utils.createConnection();
    }

    query = 'SELECT utoken FROM users WHERE id = @id';
    parameters = {'id': id};
    Result result = await env.connection.execute(Sql.named(query), parameters: parameters);

    if (result.affectedRows == 0 || result[0][0] != refreshToken) {
      throw GrpcError.unauthenticated('Пройдите повторную аутентификацию');
    }

    final tokensDto = await utils.createTokens(id);

    // Сгенерированный refreshToken сохраняем в БД для данного пользователя
    query = 'UPDATE users SET utoken = @token WHERE id = @id';
    parameters = {'id': id, 'token': tokensDto.refreshToken};
    await env.connection.execute(Sql.named(query), parameters: parameters);

    // Закрываем соединение с БД
    await env.connection.close();

    return tokensDto;
  }
}
