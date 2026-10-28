import 'package:flutter/material.dart';

import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../models/models.dart';
import '../../widgets/charts.dart';
import '../../widgets/common.dart';
import '../cases/case_detail_screen.dart';

class DashboardScreen extends StatelessWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final api = AppServices.of(context).api;
    return Scaffold(
      appBar: AppBar(title: Text(t.dashboard)),
      body: AsyncView<Map<String, dynamic>>(
        load: () async => Map<String, dynamic>.from(await api.get('/dashboard') as Map),
        builder: (context, d, reload) => ListView(padding: const EdgeInsets.all(16), children: [
          NoticeBox(d['scope_notice'] as String),
          Wrap(spacing: 10, runSpacing: 10, children: [
            _Metric(label: t.activeCases, value: '${d['active_cases'] ?? 0}'),
            _Metric(label: t.alertsToVerify, value: '${d['alerts_to_verify'] ?? 0}'),
            if (d.containsKey('reports_pending_validation'))
              _Metric(label: t.reportsPending, value: '${d['reports_pending_validation']}'),
            _Metric(label: t.recentActivity, value: '${d['recent_activity'] ?? 0}'),
          ]),
          SectionTitle(t.reviewDueSoon),
          ..._list(d['review_due_soon'], t.emptyList, (m) => ListTile(
                dense: true,
                title: Text(m['title'] as String),
                subtitle: Text('${m['reference']}  ·  ${m['review_date']}'),
                onTap: () => Navigator.push(context,
                    MaterialPageRoute(builder: (_) => CaseDetailScreen(caseId: m['id'] as String))),
              )),
          SectionTitle(t.recentEvents),
          ..._list(d['recent_events'], t.emptyList, (m) => ListTile(
                dense: true,
                leading: const Icon(Icons.event_note, size: 18),
                title: Text(m['title'] as String),
                subtitle: Text(fmtDate(DateTime.tryParse('${m['occurred_at']}')?.toLocal())),
              )),
          if (d['threat_category_trend'] is Map && (d['threat_category_trend'] as Map).isNotEmpty) ...[
            SectionTitle(t.threatTrend),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: StackedBarChart(data: Map<String, dynamic>.from(d['threat_category_trend'] as Map)),
              ),
            ),
          ],
          if (d['source_quality'] is Map) ...[
            SectionTitle(t.sourceQuality),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: _SourceQuality(Map<String, dynamic>.from(d['source_quality'] as Map)),
              ),
            ),
          ],
          if (d['services'] is Map) ...[
            SectionTitle(t.servicesStatus),
            Card(
              child: Column(children: [
                for (final e in (d['services'] as Map).entries)
                  ListTile(dense: true, title: Text('${e.key}'), trailing: Tag('${e.value}')),
              ]),
            ),
          ],
        ]),
      ),
    );
  }

  List<Widget> _list(Object? raw, String empty, Widget Function(Map m) build) {
    final items = (raw as List?) ?? const [];
    if (items.isEmpty) {
      return [Padding(padding: const EdgeInsets.all(8), child: Text(empty, style: const TextStyle(color: AicColors.silverMuted)))];
    }
    return [Card(child: Column(children: [for (final i in items) build(i as Map)]))];
  }
}

class _Metric extends StatelessWidget {
  const _Metric({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => SizedBox(
        width: 160,
        child: Card(
          child: Padding(
            padding: const EdgeInsets.all(14),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(value, style: Theme.of(context).textTheme.headlineSmall),
              const SizedBox(height: 4),
              Text(label, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
            ]),
          ),
        ),
      );
}

class _SourceQuality extends StatelessWidget {
  const _SourceQuality(this.q);

  final Map<String, dynamic> q;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final rel = Map<String, dynamic>.from(q['reliability_distribution'] as Map? ?? {});
    final fresh = Map<String, dynamic>.from(q['indicator_freshness'] as Map? ?? {});
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(t.reliabilityDistribution, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
      const SizedBox(height: 6),
      HorizontalBars(values: {for (final k in ['A', 'B', 'C', 'D', 'E', 'F']) k: (rel[k] as num? ?? 0).toDouble()}),
      const SizedBox(height: 12),
      Text(t.indicatorFreshness, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
      const SizedBox(height: 6),
      HorizontalBars(values: {for (final e in fresh.entries) e.key: (e.value as num).toDouble()}),
      const SizedBox(height: 8),
      Text(t.osintLast30(q['osint_items_last_30_days'] as int? ?? 0), style: const TextStyle(fontSize: 12)),
    ]);
  }
}

class AlertsScreen extends StatelessWidget {
  const AlertsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.alertCenter)),
      body: AsyncView<List<AlertItem>>(
        load: () async => [for (final a in await s.api.get('/alerts') as List) AlertItem(Map<String, dynamic>.from(a as Map))],
        isEmpty: (l) => l.isEmpty,
        emptyText: t.noAlerts,
        builder: (context, alerts, reload) => ListView(padding: const EdgeInsets.all(12), children: [
          NoticeBox(t.alertNotice),
          for (final a in alerts)
            Card(
              child: ListTile(
                leading: Icon(Icons.flag_outlined, color: _severityColor(a.severity)),
                title: Text(a.title),
                subtitle: Text('${fmtDate(a.createdAt)}  ·  ${t.alertStatus(a.status)}'),
                onTap: () async {
                  final changed = await showModalBottomSheet<bool>(
                    context: context,
                    isScrollControlled: true,
                    builder: (_) => _AlertReview(alert: a),
                  );
                  if (changed == true) reload();
                },
              ),
            ),
        ]),
      ),
    );
  }

  Color _severityColor(String s) => s == 'high' ? AicColors.danger : (s == 'medium' ? AicColors.warning : AicColors.silverMuted);
}

class _AlertReview extends StatefulWidget {
  const _AlertReview({required this.alert});

  final AlertItem alert;

  @override
  State<_AlertReview> createState() => _AlertReviewState();
}

class _AlertReviewState extends State<_AlertReview> {
  final _note = TextEditingController();

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final a = widget.alert;
    Future<void> decide(String status) async {
      if (_note.text.trim().length < 3) {
        toast(context, t.noteRequired);
        return;
      }
      try {
        await s.api.post('/alerts/${a.id}/review', body: {'status': status, 'note': _note.text.trim()});
        if (context.mounted) Navigator.pop(context, true);
      } catch (e) {
        if (context.mounted) toast(context, errorMessage(context, e));
      }
    }

    return Padding(
      padding: EdgeInsets.fromLTRB(16, 16, 16, MediaQuery.of(context).viewInsets.bottom + 16),
      child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(a.title, style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        Text(a.detail),
        NoticeBox(a.notice),
        if (s.auth.me!.can('alert:review')) ...[
          TextField(controller: _note, maxLines: 3, decoration: InputDecoration(labelText: t.reviewNote)),
          const SizedBox(height: 12),
          Wrap(spacing: 8, children: [
            OutlinedButton(onPressed: () => decide('under_review'), child: Text(t.alertStatus('under_review'))),
            OutlinedButton(onPressed: () => decide('dismissed'), child: Text(t.alertStatus('dismissed'))),
            FilledButton(onPressed: () => decide('escalated'), child: Text(t.alertStatus('escalated'))),
          ]),
        ],
      ]),
    );
  }
}

class NotificationsScreen extends StatelessWidget {
  const NotificationsScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final api = AppServices.of(context).api;
    return Scaffold(
      appBar: AppBar(title: Text(t.notifications)),
      body: AsyncView<List>(
        load: () async => await api.get('/me/notifications') as List,
        isEmpty: (l) => l.isEmpty,
        builder: (context, items, reload) => ListView(children: [
          for (final n in items.cast<Map>())
            ListTile(
              leading: Icon(n['read_at'] == null ? Icons.circle : Icons.circle_outlined, size: 10),
              title: Text(t.notificationText(n['category'] as String)),
              subtitle: Text(fmtDate(DateTime.tryParse(n['created_at'] as String)?.toLocal())),
              onTap: () async {
                await api.post('/me/notifications/${n['id']}/read');
                reload();
              },
            ),
        ]),
      ),
    );
  }
}
