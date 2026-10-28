import 'package:flutter/material.dart';

import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../widgets/common.dart';
import '../cases/case_forms.dart';

class AdminScreen extends StatelessWidget {
  const AdminScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    return DefaultTabController(
      length: 4,
      child: Scaffold(
        appBar: AppBar(
          title: Text(t.administration),
          bottom: TabBar(isScrollable: true, tabAlignment: TabAlignment.start, tabs: [
            Tab(text: t.users),
            Tab(text: t.rolesPermissions),
            Tab(text: t.devices),
            Tab(text: t.recovery),
          ]),
        ),
        body: const TabBarView(children: [_Users(), _Roles(), _AdminDevices(), _Recovery()]),
      ),
    );
  }
}

class _Users extends StatelessWidget {
  const _Users();

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return AsyncView<List>(
      load: () async => await s.api.get('/admin/users') as List,
      builder: (context, users, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        NoticeBox(t.adminSeparationNotice),
        for (final u in users.cast<Map>())
          Card(
            child: ListTile(
              title: Text('${u['display_name']}'),
              subtitle: Text('${u['username']}  ·  ${u['professional_id']}\n'
                  '${(u['roles'] as List).map((r) => r['code']).join(', ')}  ·  ${t.clearance} ${u['clearance_rank']}'
                  '${u['is_active'] == true ? '' : '  ·  ${t.disabled}'}'),
              isThreeLine: true,
              trailing: PopupMenuButton<String>(
                onSelected: (action) async {
                  try {
                    switch (action) {
                      case 'unlock':
                        await s.api.post('/admin/users/${u['id']}/unlock');
                      case 'revoke':
                        await s.api.post('/admin/users/${u['id']}/revoke-sessions');
                      case 'disable':
                        await withStepUp(context, () => s.api.patch('/admin/users/${u['id']}', body: {'is_active': false}));
                      case 'enable':
                        await withStepUp(context, () => s.api.patch('/admin/users/${u['id']}', body: {'is_active': true}));
                    }
                    if (context.mounted) toast(context, t.done);
                    reload();
                  } catch (e) {
                    if (context.mounted) toast(context, errorMessage(context, e));
                  }
                },
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'unlock', child: Text(t.unlockAccount)),
                  PopupMenuItem(value: 'revoke', child: Text(t.revokeAllSessions)),
                  PopupMenuItem(value: u['is_active'] == true ? 'disable' : 'enable',
                      child: Text(u['is_active'] == true ? t.disableAccount : t.enableAccount)),
                ],
              ),
            ),
          ),
      ]),
    );
  }
}

class _Roles extends StatelessWidget {
  const _Roles();

  @override
  Widget build(BuildContext context) {
    final s = AppServices.of(context);
    final lang = Localizations.localeOf(context).languageCode;
    return AsyncView<List>(
      load: () async => await s.api.get('/admin/roles') as List,
      builder: (context, roles, _) => ListView(padding: const EdgeInsets.all(12), children: [
        for (final r in roles.cast<Map>())
          Card(
            child: ExpansionTile(
              title: Text('${r[lang == 'fr' ? 'name_fr' : 'name_en']}'),
              subtitle: Text('${r['code']}  ·  scope: ${r['case_scope']}'),
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                  child: Wrap(spacing: 6, runSpacing: 6, children: [
                    for (final p in (r['permissions'] as List)) Tag('$p'),
                  ]),
                ),
              ],
            ),
          ),
      ]),
    );
  }
}

class _AdminDevices extends StatelessWidget {
  const _AdminDevices();

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    if (!s.auth.me!.can('device:revoke_any')) return MessageState(icon: Icons.block, text: t.errorForbidden);
    return AsyncView<List>(
      load: () async => await s.api.get('/admin/devices') as List,
      builder: (context, devices, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        for (final d in devices.cast<Map>())
          Card(
            child: ListTile(
              title: Text('${d['label']}'),
              subtitle: Text('${'${d['user_id']}'.substring(0, 8)}  ·  ${t.deviceStatus(d['status'] as String)}'
                  '${(d['integrity_report'] as Map?)?['heuristic_root_or_jailbreak'] == true ? '  ·  ${t.integritySignal}' : ''}'),
              trailing: d['status'] == 'active'
                  ? PopupMenuButton<String>(
                      onSelected: (status) async {
                        final reason = await askText(context, t.justification);
                        if (reason == null) return;
                        try {
                          await s.api.post('/admin/devices/${d['id']}/revoke', body: {'status': status, 'reason': reason, 'wipe': true});
                          reload();
                        } catch (e) {
                          if (context.mounted) toast(context, errorMessage(context, e));
                        }
                      },
                      itemBuilder: (_) => [
                        for (final st in ['lost', 'stolen', 'revoked']) PopupMenuItem(value: st, child: Text(t.deviceStatus(st))),
                      ],
                    )
                  : null,
            ),
          ),
      ]),
    );
  }
}

class _Recovery extends StatelessWidget {
  const _Recovery();

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return AsyncView<List>(
      load: () async => await s.api.get('/admin/recovery') as List,
      builder: (context, items, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        NoticeBox(t.recoveryProcedureNotice),
        if (items.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
        for (final r in items.cast<Map>())
          Card(
            child: ListTile(
              title: Text('${r['identity_check_reference']}'),
              subtitle: Text('${t.status} : ${r['status']}'),
              trailing: r['status'] == 'pending' && s.auth.me!.can('recovery:approve')
                  ? TextButton(
                      onPressed: () async {
                        try {
                          final res = await withStepUp(context, () => s.api.post('/admin/recovery/${r['id']}/approve'));
                          if (res == null || !context.mounted) return;
                          await showDialog<void>(
                            context: context,
                            builder: (c) => AlertDialog(
                              title: Text(t.recoveryCode),
                              content: SelectableText('${(res as Map)['recovery_code']}\n\n${res['instruction']}'),
                              actions: [TextButton(onPressed: () => Navigator.pop(c), child: Text(t.close))],
                            ),
                          );
                          reload();
                        } catch (e) {
                          if (context.mounted) toast(context, errorMessage(context, e));
                        }
                      },
                      child: Text(t.approve),
                    )
                  : null,
            ),
          ),
      ]),
    );
  }
}

class AuditScreen extends StatelessWidget {
  const AuditScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(
        title: Text(t.auditLog),
        actions: [
          IconButton(
            tooltip: t.verifyIntegrity,
            icon: const Icon(Icons.verified_user_outlined),
            onPressed: () async {
              try {
                final r = Map<String, dynamic>.from(await s.api.get('/audit/verify') as Map);
                if (context.mounted) {
                  toast(context, r['valid'] == true ? t.chainValid(r['checked'] as int) : t.chainBroken('${r['first_broken_seq']}'));
                }
              } catch (e) {
                if (context.mounted) toast(context, errorMessage(context, e));
              }
            },
          ),
        ],
      ),
      body: AsyncView<List>(
        load: () async => await s.api.get('/audit', query: {'limit': 200}) as List,
        isEmpty: (l) => l.isEmpty,
        builder: (context, rows, _) => ListView.separated(
          itemCount: rows.length,
          separatorBuilder: (_, _) => const Divider(),
          itemBuilder: (context, i) {
            final r = rows[i] as Map;
            final color = switch (r['outcome']) {
              'denied' => AicColors.warning,
              'failure' => AicColors.danger,
              _ => AicColors.silverMuted,
            };
            return ListTile(
              dense: true,
              leading: Text('#${r['seq']}', style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
              title: Text('${r['action']}'),
              subtitle: Text('${r['actor']}  ·  ${fmtDate(DateTime.tryParse('${r['occurred_at']}')?.toLocal())}  ·  ${r['ip_address'] ?? ''}'),
              trailing: Tag('${r['outcome']}', color: color),
            );
          },
        ),
      ),
    );
  }
}
