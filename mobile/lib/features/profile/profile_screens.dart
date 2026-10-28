import 'package:flutter/material.dart';

import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../widgets/common.dart';
import '../cases/case_forms.dart';

class ProfileScreen extends StatelessWidget {
  const ProfileScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    return Scaffold(
      appBar: AppBar(title: Text(t.profile)),
      body: AsyncView<List>(
        load: () async => await s.api.get('/me/sessions') as List,
        builder: (context, sessions, reload) => ListView(padding: const EdgeInsets.all(12), children: [
          Card(
            child: ListTile(
              title: Text(me.displayName),
              subtitle: Text('${me.username}\n${me.professionalId}  ·  ${me.roleLabel(Localizations.localeOf(context).languageCode)}\n'
                  '${t.clearance} : ${s.auth.markings[me.clearanceRank] ?? me.clearanceRank}'),
              isThreeLine: true,
            ),
          ),
          SectionTitle(t.language),
          SegmentedButton<String>(
            segments: [
              ButtonSegment(value: 'fr', label: Text(t.french)),
              ButtonSegment(value: 'en', label: Text(t.english)),
            ],
            selected: {Localizations.localeOf(context).languageCode},
            onSelectionChanged: (v) async {
              s.locale.value = Locale(v.first);
              try {
                await s.api.patch('/me/locale?locale=${v.first}');
              } catch (_) {
                // Preference is kept locally even if the server is unreachable.
              }
            },
          ),
          SectionTitle(t.sessions),
          for (final x in sessions.cast<Map>())
            Card(
              child: ListTile(
                leading: Icon(x['revoked_at'] == null ? Icons.lock_open : Icons.lock, size: 20),
                title: Text(x['user_agent'] as String? ?? t.unknownClient, maxLines: 1, overflow: TextOverflow.ellipsis),
                subtitle: Text('${t.openedOn} ${fmtDate(DateTime.tryParse('${x['created_at']}')?.toLocal())}\n'
                    '${x['revoked_at'] != null ? '${t.revoked} (${x['revoked_reason']})' : '${t.lastUsed} ${fmtDate(DateTime.tryParse('${x['last_used_at']}')?.toLocal())}'}'),
                isThreeLine: true,
                trailing: x['revoked_at'] == null
                    ? IconButton(
                        tooltip: t.revoke,
                        icon: const Icon(Icons.logout),
                        onPressed: () async {
                          if (!await confirm(context, t.revoke, t.revokeSessionConfirm)) return;
                          try {
                            await s.api.delete('/me/sessions/${x['id']}');
                            reload();
                          } catch (e) {
                            if (context.mounted) toast(context, errorMessage(context, e));
                          }
                        },
                      )
                    : null,
              ),
            ),
        ]),
      ),
    );
  }
}

class DevicesScreen extends StatelessWidget {
  const DevicesScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.devices)),
      body: AsyncView<List>(
        load: () async => await s.api.get('/me/devices') as List,
        builder: (context, devices, reload) => ListView(padding: const EdgeInsets.all(12), children: [
          NoticeBox(t.lostDeviceNotice),
          for (final d in devices.cast<Map>())
            Card(
              child: ListTile(
                leading: Icon(d['platform'] == 'ios' ? Icons.phone_iphone : Icons.phone_android),
                title: Text(d['label'] as String),
                subtitle: Text('${t.deviceStatus(d['status'] as String)}  ·  ${t.registeredOn} '
                    '${fmtDay(DateTime.tryParse('${d['created_at']}'))}'),
                trailing: d['status'] == 'active'
                    ? TextButton(
                        onPressed: () async {
                          final reason = await askText(context, t.reportLost);
                          if (reason == null || !context.mounted) return;
                          try {
                            await s.api.post('/me/devices/${d['id']}/report-lost',
                                body: {'status': 'lost', 'reason': reason, 'wipe': true});
                            if (context.mounted) toast(context, t.deviceRevokedDone);
                            reload();
                            await s.auth.checkDeviceStatus();
                          } catch (e) {
                            if (context.mounted) toast(context, errorMessage(context, e));
                          }
                        },
                        child: Text(t.reportLost, style: const TextStyle(color: AicColors.danger)),
                      )
                    : null,
              ),
            ),
        ]),
      ),
    );
  }
}

class SecuritySettingsScreen extends StatefulWidget {
  const SecuritySettingsScreen({super.key});

  @override
  State<SecuritySettingsScreen> createState() => _SecuritySettingsScreenState();
}

class _SecuritySettingsScreenState extends State<SecuritySettingsScreen> {
  int _pending = 0;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    AppServices.of(context).offline.pending().then((p) {
      if (mounted) setState(() => _pending = p.length);
    });
  }

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.securitySettings)),
      body: ListView(padding: const EdgeInsets.all(12), children: [
        ListTile(
          leading: const Icon(Icons.fingerprint),
          title: Text(t.biometricLock),
          subtitle: Text(t.biometricLockDetail(s.auth.lockAfter.inMinutes)),
        ),
        ListTile(
          leading: const Icon(Icons.visibility_off_outlined),
          title: Text(t.screenProtection),
          subtitle: Text(t.screenProtectionDetail),
        ),
        ListTile(
          leading: const Icon(Icons.notifications_off_outlined),
          title: Text(t.genericNotifications),
          subtitle: Text(t.genericNotificationsDetail),
        ),
        if (s.auth.deviceRiskSignal) NoticeBox(t.deviceRiskWarning),
        const Divider(),
        SectionTitle(t.offlineData),
        ListTile(
          leading: const Icon(Icons.sync),
          title: Text(t.syncNow),
          subtitle: Text(t.pendingOperations(_pending)),
          onTap: () async {
            try {
              final results = await s.offline.flush();
              await s.offline.reconcileGrants();
              final conflicts = results.where((r) => r['result'] != 'applied').length;
              if (context.mounted) toast(context, t.syncResult(results.length, conflicts));
              final p = await s.offline.pending();
              if (mounted) setState(() => _pending = p.length);
            } catch (e) {
              if (context.mounted) toast(context, errorMessage(context, e));
            }
          },
        ),
        ListTile(
          leading: const Icon(Icons.delete_sweep_outlined, color: AicColors.danger),
          title: Text(t.purgeLocalData),
          subtitle: Text(t.purgeLocalDataDetail),
          onTap: () async {
            if (!await confirm(context, t.purgeLocalData, t.purgeLocalDataDetail)) return;
            await s.offline.cache.purgeAll();
            if (context.mounted) toast(context, t.done);
            if (mounted) setState(() => _pending = 0);
          },
        ),
      ]),
    );
  }
}
