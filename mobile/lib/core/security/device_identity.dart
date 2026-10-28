import 'dart:io';
import 'dart:math';

import 'secure_store.dart';

/// Stable, random installation identifier (not a hardware identifier).
class DeviceIdentity {
  DeviceIdentity(this._store);

  final KeyValueStore _store;
  static const _key = 'aic.install_id';

  Future<String> installId() async {
    final existing = await _store.read(_key);
    if (existing != null) return existing;
    final rnd = Random.secure();
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    final id = List.generate(32, (_) => alphabet[rnd.nextInt(alphabet.length)]).join();
    await _store.write(_key, id);
    return id;
  }

  String get platform => Platform.isIOS ? 'ios' : (Platform.isAndroid ? 'android' : 'test');

  /// Best-effort heuristics. They can be bypassed and are reported to the
  /// server as signals only; they are not presented as reliable detection.
  Map<String, Object> integritySignals() {
    var suspicious = false;
    if (Platform.isAndroid) {
      for (final path in const ['/system/xbin/su', '/system/bin/su', '/sbin/su', '/system/app/Superuser.apk']) {
        if (File(path).existsSync()) suspicious = true;
      }
    } else if (Platform.isIOS) {
      for (final path in const ['/Applications/Cydia.app', '/bin/bash', '/usr/sbin/sshd', '/etc/apt']) {
        if (File(path).existsSync()) suspicious = true;
      }
    }
    return {'heuristic_root_or_jailbreak': suspicious, 'method': 'file_heuristics_v1'};
  }
}
