import '../security/secure_store.dart';

/// Tokens live only in the OS keystore, never in preferences or files.
/// The access token is also kept in memory to avoid keystore round-trips.
class TokenStore {
  TokenStore(this._store);

  final KeyValueStore _store;
  String? _access;
  static const _refreshKey = 'aic.refresh_token';
  static const _accessKey = 'aic.access_token';

  Future<String?> accessToken() async => _access ??= await _store.read(_accessKey);

  Future<String?> refreshToken() => _store.read(_refreshKey);

  Future<bool> hasSession() async => (await refreshToken()) != null;

  Future<void> saveFromJson(Map<String, dynamic> json) async {
    _access = json['access_token'] as String;
    await _store.write(_accessKey, _access!);
    await _store.write(_refreshKey, json['refresh_token'] as String);
  }

  Future<void> clear() async {
    _access = null;
    await _store.delete(_accessKey);
    await _store.delete(_refreshKey);
  }
}
