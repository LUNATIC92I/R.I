import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:cryptography/cryptography.dart';

import '../security/secure_store.dart';

/// Encrypted, expiring local cache for offline packages and the sync queue.
///
/// Each entry is AES-256-GCM encrypted with a key held in the OS keystore.
/// Entries carry their expiry and are refused (and deleted) once expired.
/// Nothing is cached unless the server issued an explicit offline grant.
class EncryptedCache {
  EncryptedCache({required this.directory, required KeyValueStore keyStore}) : _keys = keyStore;

  final Directory directory;
  final KeyValueStore _keys;
  final _algo = AesGcm.with256bits();
  static const _keyName = 'aic.cache_key';

  Future<SecretKey> _key() async {
    final existing = await _keys.read(_keyName);
    if (existing != null) return SecretKey(base64Decode(existing));
    final rnd = Random.secure();
    final bytes = List<int>.generate(32, (_) => rnd.nextInt(256));
    await _keys.write(_keyName, base64Encode(bytes));
    return SecretKey(bytes);
  }

  File _file(String name) {
    if (!RegExp(r'^[A-Za-z0-9_\-]+$').hasMatch(name)) throw ArgumentError('invalid cache entry name');
    return File('${directory.path}/$name.bin');
  }

  Future<void> put(String name, Map<String, dynamic> value, {required DateTime expiresAt}) async {
    await directory.create(recursive: true);
    final payload = utf8.encode(jsonEncode({'expires_at': expiresAt.toUtc().toIso8601String(), 'value': value}));
    final box = await _algo.encrypt(payload, secretKey: await _key(), aad: utf8.encode(name));
    await _file(name).writeAsBytes(box.concatenation(), flush: true);
  }

  Future<Map<String, dynamic>?> get(String name, {DateTime? now}) async {
    final file = _file(name);
    if (!await file.exists()) return null;
    try {
      final box = SecretBox.fromConcatenation(await file.readAsBytes(),
          nonceLength: _algo.nonceLength, macLength: _algo.macAlgorithm.macLength);
      final clear = await _algo.decrypt(box, secretKey: await _key(), aad: utf8.encode(name));
      final data = jsonDecode(utf8.decode(clear)) as Map<String, dynamic>;
      final expires = DateTime.parse(data['expires_at'] as String);
      if ((now ?? DateTime.now().toUtc()).isAfter(expires)) {
        await file.delete();
        return null;
      }
      return Map<String, dynamic>.from(data['value'] as Map);
    } on Exception {
      // Corrupted or tampered entry: discard it.
      await file.delete();
      return null;
    }
  }

  Future<List<String>> names() async {
    if (!await directory.exists()) return [];
    return [
      for (final f in directory.listSync().whereType<File>())
        if (f.path.endsWith('.bin')) f.uri.pathSegments.last.replaceAll('.bin', ''),
    ];
  }

  Future<void> remove(String name) async {
    final f = _file(name);
    if (await f.exists()) await f.delete();
  }

  /// Deletes every entry and the encryption key (logout, revocation, wipe).
  Future<void> purgeAll() async {
    if (await directory.exists()) await directory.delete(recursive: true);
    await _keys.delete(_keyName);
  }
}
