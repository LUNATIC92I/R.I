import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Thin wrapper over the OS keystore (Android Keystore / iOS Keychain).
///
/// iOS items are bound to this device and unavailable while it is locked,
/// and are excluded from backups. Android data is excluded from backups in
/// the manifest (`allowBackup=false`, data extraction rules).
abstract class KeyValueStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
  Future<void> deleteAll();
}

class SecureStore implements KeyValueStore {
  SecureStore()
      : _storage = const FlutterSecureStorage(
          aOptions: AndroidOptions(resetOnError: true),
          iOptions: IOSOptions(accessibility: KeychainAccessibility.unlocked_this_device, synchronizable: false),
        );

  final FlutterSecureStorage _storage;

  @override
  Future<String?> read(String key) => _storage.read(key: key);

  @override
  Future<void> write(String key, String value) => _storage.write(key: key, value: value);

  @override
  Future<void> delete(String key) => _storage.delete(key: key);

  @override
  Future<void> deleteAll() => _storage.deleteAll();
}

/// In-memory store used by tests.
class MemoryStore implements KeyValueStore {
  final Map<String, String> values = {};

  @override
  Future<String?> read(String key) async => values[key];

  @override
  Future<void> write(String key, String value) async => values[key] = value;

  @override
  Future<void> delete(String key) async => values.remove(key);

  @override
  Future<void> deleteAll() async => values.clear();
}
