//
//  Generated code. Do not modify.
//  source: auth.proto
//
// @dart = 2.12

// ignore_for_file: annotate_overrides, camel_case_types
// ignore_for_file: constant_identifier_names, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_final_fields
// ignore_for_file: unnecessary_import, unnecessary_this, unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

@$core.Deprecated('Use userDtoDescriptor instead')
const UserDto$json = {
  '1': 'UserDto',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '10': 'id'},
    {'1': 'username', '3': 2, '4': 1, '5': 9, '10': 'username'},
    {'1': 'email', '3': 3, '4': 1, '5': 9, '9': 0, '10': 'email'},
    {'1': 'password', '3': 4, '4': 1, '5': 9, '9': 1, '10': 'password'},
  ],
  '8': [
    {'1': 'optional_email'},
    {'1': 'optional_password'},
  ],
};

/// Descriptor for `UserDto`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List userDtoDescriptor = $convert.base64Decode(
    'CgdVc2VyRHRvEg4KAmlkGAEgASgJUgJpZBIaCgh1c2VybmFtZRgCIAEoCVIIdXNlcm5hbWUSFg'
    'oFZW1haWwYAyABKAlIAFIFZW1haWwSHAoIcGFzc3dvcmQYBCABKAlIAVIIcGFzc3dvcmRCEAoO'
    'b3B0aW9uYWxfZW1haWxCEwoRb3B0aW9uYWxfcGFzc3dvcmQ=');

@$core.Deprecated('Use tokensDtoDescriptor instead')
const TokensDto$json = {
  '1': 'TokensDto',
  '2': [
    {'1': 'access_token', '3': 1, '4': 1, '5': 9, '10': 'accessToken'},
    {'1': 'refresh_token', '3': 2, '4': 1, '5': 9, '10': 'refreshToken'},
  ],
};

/// Descriptor for `TokensDto`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List tokensDtoDescriptor = $convert.base64Decode(
    'CglUb2tlbnNEdG8SIQoMYWNjZXNzX3Rva2VuGAEgASgJUgthY2Nlc3NUb2tlbhIjCg1yZWZyZX'
    'NoX3Rva2VuGAIgASgJUgxyZWZyZXNoVG9rZW4=');

@$core.Deprecated('Use requestDtoDescriptor instead')
const RequestDto$json = {
  '1': 'RequestDto',
};

/// Descriptor for `RequestDto`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List requestDtoDescriptor = $convert.base64Decode(
    'CgpSZXF1ZXN0RHRv');

@$core.Deprecated('Use responseDtoDescriptor instead')
const ResponseDto$json = {
  '1': 'ResponseDto',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '10': 'id'},
  ],
};

/// Descriptor for `ResponseDto`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List responseDtoDescriptor = $convert.base64Decode(
    'CgtSZXNwb25zZUR0bxIOCgJpZBgBIAEoCVICaWQ=');

@$core.Deprecated('Use findDtoDescriptor instead')
const FindDto$json = {
  '1': 'FindDto',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
  ],
};

/// Descriptor for `FindDto`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List findDtoDescriptor = $convert.base64Decode(
    'CgdGaW5kRHRvEhAKA2tleRgBIAEoCVIDa2V5');

@$core.Deprecated('Use listUsersDtoDescriptor instead')
const ListUsersDto$json = {
  '1': 'ListUsersDto',
  '2': [
    {'1': 'users', '3': 1, '4': 3, '5': 11, '6': '.UserDto', '10': 'users'},
  ],
};

/// Descriptor for `ListUsersDto`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listUsersDtoDescriptor = $convert.base64Decode(
    'CgxMaXN0VXNlcnNEdG8SHgoFdXNlcnMYASADKAsyCC5Vc2VyRHRvUgV1c2Vycw==');

