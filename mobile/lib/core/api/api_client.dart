import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;
import 'package:http_parser/http_parser.dart';

import '../auth/token_store.dart';

/// Error returned by the API, carrying the stable server error code.
class ApiException implements Exception {
  ApiException(this.status, this.code, [this.message]);

  final int status;
  final String code;
  final String? message;

  bool get isNetwork => status == 0;
  bool get stepUpRequired => code == 'step_up_required';

  @override
  String toString() => 'ApiException($status, $code)';
}

typedef SessionExpiredCallback = void Function();

/// HTTP client with bearer authentication and single-flight token refresh.
///
/// Response bodies are never logged. Every response is treated as no-store.
class ApiClient {
  ApiClient({required this.baseUrl, required this.tokens, http.Client? httpClient})
      : _http = httpClient ?? http.Client();

  final String baseUrl;
  final TokenStore tokens;
  final http.Client _http;
  SessionExpiredCallback? onSessionExpired;
  Future<bool>? _refreshing;

  static const _timeout = Duration(seconds: 20);

  Uri _uri(String path, [Map<String, dynamic>? query]) {
    final base = Uri.parse('$baseUrl$path');
    if (query == null || query.isEmpty) return base;
    final params = <String, dynamic>{};
    query.forEach((k, v) {
      if (v == null) return;
      params[k] = v is List ? v.map((e) => e.toString()).toList() : v.toString();
    });
    return base.replace(queryParameters: params);
  }

  Future<dynamic> get(String path, {Map<String, dynamic>? query}) =>
      _send(() => http.Request('GET', _uri(path, query)));

  Future<dynamic> post(String path, {Object? body, Map<String, dynamic>? query}) =>
      _send(() => _json('POST', _uri(path, query), body));

  Future<dynamic> patch(String path, {Object? body}) => _send(() => _json('PATCH', _uri(path), body));

  Future<dynamic> delete(String path) => _send(() => http.Request('DELETE', _uri(path)));

  Future<Uint8List> getBytes(String path, {Map<String, dynamic>? query}) async {
    final resp = await _raw(() => http.Request('GET', _uri(path, query)));
    return resp.bodyBytes;
  }

  /// Multipart upload (documents). Field values are strings, the file is sent as bytes.
  Future<dynamic> postMultipart(String path, Map<String, String> fields, String fileField, String filename,
      List<int> bytes, String mimeType) async {
    http.BaseRequest build() {
      final req = http.MultipartRequest('POST', _uri(path));
      req.fields.addAll(fields);
      final parts = mimeType.split('/');
      req.files.add(http.MultipartFile.fromBytes(fileField, bytes,
          filename: filename, contentType: MediaType(parts.first, parts.last)));
      return req;
    }

    return _decode(await _rawBase(build));
  }

  /// Unauthenticated call (login, MFA, refresh).
  Future<dynamic> postPublic(String path, Object body) async {
    final resp = await _execute(_json('POST', _uri(path), body), authenticated: false);
    return _decode(resp);
  }

  http.Request _json(String method, Uri uri, Object? body) {
    final req = http.Request(method, uri);
    req.headers['Content-Type'] = 'application/json';
    if (body != null) req.body = jsonEncode(body);
    return req;
  }

  Future<dynamic> _send(http.Request Function() build) async => _decode(await _raw(build));

  Future<http.Response> _raw(http.Request Function() build) => _rawBase(build);

  Future<http.Response> _rawBase(http.BaseRequest Function() build) async {
    var resp = await _execute(build());
    if (resp.statusCode == 401) {
      final refreshed = await _refreshOnce();
      if (!refreshed) {
        onSessionExpired?.call();
        throw ApiException(401, 'session_expired');
      }
      resp = await _execute(build());
    }
    if (resp.statusCode >= 400) throw _error(resp);
    return resp;
  }

  Future<http.Response> _execute(http.BaseRequest req, {bool authenticated = true}) async {
    if (authenticated) {
      final access = await tokens.accessToken();
      if (access != null) req.headers['Authorization'] = 'Bearer $access';
    }
    req.headers['Accept'] = 'application/json';
    try {
      final streamed = await _http.send(req).timeout(_timeout);
      return await http.Response.fromStream(streamed);
    } on Exception {
      throw ApiException(0, 'network_unavailable');
    }
  }

  Future<bool> _refreshOnce() {
    return _refreshing ??= _doRefresh().whenComplete(() => _refreshing = null);
  }

  Future<bool> _doRefresh() async {
    final refresh = await tokens.refreshToken();
    if (refresh == null) return false;
    try {
      final resp = await _execute(_json('POST', _uri('/auth/refresh'), {'refresh_token': refresh}),
          authenticated: false);
      if (resp.statusCode != 200) {
        await tokens.clear();
        return false;
      }
      await tokens.saveFromJson(jsonDecode(resp.body) as Map<String, dynamic>);
      return true;
    } on ApiException {
      return false;
    }
  }

  dynamic _decode(http.Response resp) {
    if (resp.statusCode >= 400) throw _error(resp);
    if (resp.body.isEmpty) return null;
    return jsonDecode(utf8.decode(resp.bodyBytes));
  }

  ApiException _error(http.Response resp) {
    try {
      final body = jsonDecode(resp.body);
      if (body is Map && body['code'] is String) {
        return ApiException(resp.statusCode, body['code'] as String, body['message'] as String?);
      }
    } on FormatException {
      // fall through
    }
    return ApiException(resp.statusCode, 'http_${resp.statusCode}');
  }
}
