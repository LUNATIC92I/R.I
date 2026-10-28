import 'dart:math';

import '../api/api_client.dart';
import 'encrypted_cache.dart';

/// Offline packages (read) and queued operations (write) for authorised cases.
class OfflineService {
  OfflineService(this.api, this.cache);

  final ApiClient api;
  final EncryptedCache cache;
  static const _queue = 'sync_queue';

  String _entry(String caseId) => 'case_${caseId.replaceAll('-', '')}';

  Future<DateTime> download(String caseId) async {
    final pkg = Map<String, dynamic>.from(await api.post('/sync/offline-package/$caseId') as Map);
    final expires = DateTime.parse(pkg['expires_at'] as String);
    await cache.put(_entry(caseId), pkg, expiresAt: expires);
    return expires;
  }

  Future<Map<String, dynamic>?> cached(String caseId) => cache.get(_entry(caseId));

  /// Removes any cached package whose grant the server no longer lists.
  Future<void> reconcileGrants() async {
    final grants = (await api.get('/sync/grants') as List).cast<Map>();
    final valid = {for (final g in grants) _entry(g['case_id'] as String)};
    for (final name in await cache.names()) {
      if (name.startsWith('case_') && !valid.contains(name)) await cache.remove(name);
    }
  }

  Future<List<Map<String, dynamic>>> pending() async {
    final q = await cache.get(_queue);
    return [for (final op in (q?['ops'] as List? ?? const [])) Map<String, dynamic>.from(op as Map)];
  }

  /// Only operations the server accepts offline can be queued.
  Future<void> enqueue(String opType, String caseId, Map<String, dynamic> payload, {int? baseVersion}) async {
    const allowed = {'add_statement', 'add_event', 'update_case_summary'};
    if (!allowed.contains(opType)) throw ArgumentError('operation not allowed offline');
    final ops = await pending();
    final rnd = Random.secure();
    ops.add({
      'client_op_id': 'op-${DateTime.now().microsecondsSinceEpoch}-${rnd.nextInt(1 << 32)}',
      'op_type': opType,
      'case_id': caseId,
      'base_version': baseVersion,
      'payload': payload,
      'queued_at': DateTime.now().toUtc().toIso8601String(),
    });
    await cache.put(_queue, {'ops': ops}, expiresAt: DateTime.now().toUtc().add(const Duration(days: 3)));
  }

  /// Pushes the queue; the server re-checks permissions and versions.
  Future<List<Map<String, dynamic>>> flush() async {
    final ops = await pending();
    if (ops.isEmpty) return [];
    final resp = Map<String, dynamic>.from(await api.post('/sync/push', body: {'operations': ops}) as Map);
    await cache.remove(_queue);
    return [for (final r in resp['results'] as List) Map<String, dynamic>.from(r as Map)];
  }
}
