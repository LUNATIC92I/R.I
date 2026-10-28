import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart';

import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../models/models.dart';
import '../../widgets/common.dart';
import '../cases/case_detail_screen.dart';
import '../cases/case_forms.dart';
import '../cases/case_list_screen.dart';
import 'report_screens.dart';

enum CaseModule { osint, cyber, graph, reports }

/// Picks an authorised case, then opens the requested module for it.
class CasePickerScreen extends StatelessWidget {
  const CasePickerScreen({super.key, required this.target});

  final CaseModule target;

  @override
  Widget build(BuildContext context) {
    return CaseListScreen(onPick: (c) {
      final Widget screen = switch (target) {
        CaseModule.osint => OsintScreen(caseId: c.id, reference: c.reference),
        CaseModule.cyber => CyberScreen(caseId: c.id, reference: c.reference),
        CaseModule.graph => GraphScreen(caseId: c.id, reference: c.reference),
        CaseModule.reports => ReportsListScreen(caseId: c.id, reference: c.reference),
      };
      Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => screen));
    });
  }
}

class SearchScreen extends StatefulWidget {
  const SearchScreen({super.key});

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  final _q = TextEditingController();
  Future<Map>? _future;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final api = AppServices.of(context).api;
    return Scaffold(
      appBar: AppBar(title: Text(t.search)),
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.all(12),
          child: TextField(
            controller: _q,
            textInputAction: TextInputAction.search,
            decoration: InputDecoration(labelText: t.searchHint, prefixIcon: const Icon(Icons.search)),
            onSubmitted: (v) {
              if (v.trim().length < 2) return;
              setState(() => _future = api.get('/search', query: {'q': v.trim()}).then((r) => r as Map));
            },
          ),
        ),
        Padding(padding: const EdgeInsets.symmetric(horizontal: 12), child: NoticeBox(t.searchScopeNotice)),
        Expanded(
          child: _future == null
              ? const SizedBox.shrink()
              : FutureBuilder<Map>(
                  future: _future,
                  builder: (context, snap) {
                    if (snap.connectionState != ConnectionState.done) {
                      return const Center(child: CircularProgressIndicator(strokeWidth: 2));
                    }
                    if (snap.hasError) return MessageState(icon: Icons.error_outline, text: errorMessage(context, snap.error!));
                    final results = (snap.data!['results'] as List).cast<Map>();
                    if (results.isEmpty) return MessageState(icon: Icons.search_off, text: t.noResults);
                    return ListView(children: [
                      for (final r in results)
                        ListTile(
                          leading: Tag(t.resultType(r['type'] as String)),
                          title: Text(r['title'] as String, maxLines: 2, overflow: TextOverflow.ellipsis),
                          onTap: () => Navigator.push(context,
                              MaterialPageRoute(builder: (_) => CaseDetailScreen(caseId: r['case_id'] as String))),
                        ),
                    ]);
                  },
                ),
        ),
      ]),
    );
  }
}

class OsintScreen extends StatelessWidget {
  const OsintScreen({super.key, required this.caseId, required this.reference});

  final String caseId;
  final String reference;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(title: Text('${t.osint} · $reference')),
      body: AsyncView<List>(
        load: () async => await s.api.get('/cases/$caseId/osint') as List,
        builder: (context, items, reload) => ListView(padding: const EdgeInsets.all(12), children: [
          NoticeBox(t.osintNotice),
          if (s.auth.me!.can('osint:write'))
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
                icon: const Icon(Icons.add),
                label: Text(t.addOsint),
                onPressed: () async {
                  final r = await Navigator.push<bool>(
                      context, MaterialPageRoute(builder: (_) => OsintFormScreen(caseId: caseId, previous: items.cast<Map>())));
                  if (r == true) reload();
                },
              ),
            ),
          if (items.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
          for (final o in items.cast<Map>())
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Expanded(child: Text(o['title'] as String, style: Theme.of(context).textTheme.titleMedium)),
                    Tag('${t.reliability} ${o['reliability']}'),
                  ]),
                  const SizedBox(height: 4),
                  Text('${o['source_name']}${o['author'] != null ? ' · ${o['author']}' : ''}'),
                  if (o['url'] != null) SelectableText(o['url'] as String, style: const TextStyle(fontSize: 12)),
                  const SizedBox(height: 6),
                  Text('${t.publishedOn} ${fmtDay(DateTime.tryParse('${o['published_at']}'))}  ·  '
                      '${t.collectedOn} ${fmtDay(DateTime.tryParse('${o['collected_at']}'))}  ·  '
                      '${t.eventDate} ${fmtDay(DateTime.tryParse('${o['event_date']}'))}',
                      style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
                  for (final v in (o['verified_points'] as List)) Text('✓  $v'),
                  for (final v in (o['unverified_points'] as List)) Text('?  $v'),
                  if (o['content_sha256'] != null)
                    Text('SHA-256 ${(o['content_sha256'] as String).substring(0, 16)}…',
                        style: const TextStyle(fontSize: 11, fontFamily: 'monospace', color: AicColors.silverMuted)),
                ]),
              ),
            ),
        ]),
      ),
    );
  }
}

class OsintFormScreen extends StatefulWidget {
  const OsintFormScreen({super.key, required this.caseId, required this.previous});

  final String caseId;
  final List<Map> previous;

  @override
  State<OsintFormScreen> createState() => _OsintFormScreenState();
}

class _OsintFormScreenState extends State<OsintFormScreen> {
  final _source = TextEditingController();
  final _url = TextEditingController();
  final _title = TextEditingController();
  final _author = TextEditingController();
  final _context = TextEditingController();
  final _content = TextEditingController();
  final _verified = TextEditingController();
  final _unverified = TextEditingController();
  String _reliability = 'F';
  DateTime? _published;
  DateTime? _eventDate;
  String? _previous;

  List<String> _lines(TextEditingController c) => c.text.split('\n').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    Widget dateTile(String label, DateTime? value, ValueChanged<DateTime> set) => ListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(label),
          subtitle: Text(value == null ? '…' : fmtDay(value)),
          trailing: const Icon(Icons.calendar_today),
          onTap: () async {
            final d = await showDatePicker(context: context, initialDate: DateTime.now(), firstDate: DateTime(1990), lastDate: DateTime.now());
            if (d != null) setState(() => set(d));
          },
        );
    return Scaffold(
      appBar: AppBar(title: Text(t.addOsint)),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        NoticeBox(t.osintLegalNotice),
        TextField(controller: _source, decoration: InputDecoration(labelText: t.sourceName)),
        const SizedBox(height: 8),
        TextField(controller: _url, keyboardType: TextInputType.url, decoration: InputDecoration(labelText: t.url)),
        const SizedBox(height: 8),
        TextField(controller: _title, decoration: InputDecoration(labelText: t.title)),
        const SizedBox(height: 8),
        TextField(controller: _author, decoration: InputDecoration(labelText: t.author)),
        dateTile(t.publishedOn, _published, (d) => _published = d),
        dateTile(t.eventDate, _eventDate, (d) => _eventDate = d),
        TextField(controller: _context, maxLines: 2, decoration: InputDecoration(labelText: t.publicationContext)),
        const SizedBox(height: 8),
        TextField(controller: _content, maxLines: 6, decoration: InputDecoration(labelText: t.archivedContent)),
        const SizedBox(height: 8),
        TextField(controller: _verified, maxLines: 3, decoration: InputDecoration(labelText: t.verifiedPoints, helperText: t.onePerLine)),
        TextField(controller: _unverified, maxLines: 3, decoration: InputDecoration(labelText: t.unverifiedPoints, helperText: t.onePerLine)),
        DropdownButtonFormField<String>(
          initialValue: _reliability,
          decoration: InputDecoration(labelText: t.reliability),
          items: [for (final r in ['A', 'B', 'C', 'D', 'E', 'F']) DropdownMenuItem(value: r, child: Text(t.reliabilityLabel(r)))],
          onChanged: (v) => setState(() => _reliability = v!),
        ),
        DropdownButtonFormField<String?>(
          initialValue: _previous,
          isExpanded: true,
          decoration: InputDecoration(labelText: t.previousVersion),
          items: [
            DropdownMenuItem<String?>(value: null, child: Text(t.none)),
            for (final p in widget.previous) DropdownMenuItem(value: p['id'] as String, child: Text(p['title'] as String)),
          ],
          onChanged: (v) => setState(() => _previous = v),
        ),
        const SizedBox(height: 16),
        FilledButton(
          onPressed: () async {
            try {
              final r = Map<String, dynamic>.from(await s.api.post('/cases/${widget.caseId}/osint', body: {
                'source_name': _source.text.trim(),
                'title': _title.text.trim(),
                if (_url.text.trim().isNotEmpty) 'url': _url.text.trim(),
                if (_author.text.trim().isNotEmpty) 'author': _author.text.trim(),
                if (_published != null) 'published_at': _published!.toUtc().toIso8601String(),
                if (_eventDate != null) 'event_date': _eventDate!.toUtc().toIso8601String(),
                'publication_context': _context.text.trim(),
                'content': _content.text,
                'verified_points': _lines(_verified),
                'unverified_points': _lines(_unverified),
                'reliability': _reliability,
                'previous_version_id': _previous,
              }) as Map);
              if (!context.mounted) return;
              final dups = r['possible_duplicates'] as List;
              if (dups.isNotEmpty) toast(context, t.duplicatesFound(dups.length));
              Navigator.pop(context, true);
            } catch (e) {
              if (context.mounted) toast(context, errorMessage(context, e));
            }
          },
          child: Text(t.save),
        ),
      ]),
    );
  }
}

class CyberScreen extends StatelessWidget {
  const CyberScreen({super.key, required this.caseId, required this.reference});

  final String caseId;
  final String reference;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    return Scaffold(
      appBar: AppBar(title: Text('${t.cyber} · $reference')),
      body: AsyncView<List>(
        load: () async => await s.api.get('/cases/$caseId/indicators') as List,
        builder: (context, items, reload) => ListView(padding: const EdgeInsets.all(12), children: [
          NoticeBox(t.cyberNotice),
          if (me.can('cyber:write'))
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
                icon: const Icon(Icons.add),
                label: Text(t.addIndicator),
                onPressed: () async {
                  if (await _addIndicator(context)) reload();
                },
              ),
            ),
          if (items.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
          for (final i in items.cast<Map>())
            Card(
              child: ListTile(
                title: Text('${i['value']}', style: const TextStyle(fontFamily: 'monospace', fontSize: 13)),
                subtitle: Text('${i['type']}  ·  ${t.freshness(i['freshness'] as String)}  ·  ${t.verdict(i['verdict'] as String)}\n'
                    '${t.firstSeen} ${fmtDay(DateTime.tryParse('${i['first_seen']}'))}  ·  '
                    '${t.lastSeen} ${fmtDay(DateTime.tryParse('${i['last_seen']}'))}\n${i['provenance']}'),
                isThreeLine: true,
                trailing: PopupMenuButton<String>(
                  onSelected: (action) async {
                    try {
                      if (action == 'enrich') {
                        await s.api.post('/cases/$caseId/indicators/${i['id']}/enrich');
                      } else {
                        final j = await askText(context, t.justification, minLength: 10);
                        if (j == null) return;
                        await s.api.post('/cases/$caseId/indicators/${i['id']}/verdict',
                            body: {'verdict': action, 'justification': j});
                      }
                      reload();
                    } catch (e) {
                      if (context.mounted) toast(context, errorMessage(context, e));
                    }
                  },
                  itemBuilder: (_) => [
                    if (me.can('cyber:write')) PopupMenuItem(value: 'enrich', child: Text(t.enrich)),
                    if (me.can('cyber:verdict'))
                      for (final v in ['suspicious', 'malicious_confirmed', 'benign', 'false_positive'])
                        PopupMenuItem(value: v, child: Text(t.verdict(v))),
                  ],
                ),
              ),
            ),
        ]),
      ),
    );
  }

  Future<bool> _addIndicator(BuildContext context) async {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final value = TextEditingController();
    final provenance = TextEditingController();
    final contextCtrl = TextEditingController();
    var type = 'domain';
    var sources = 1;
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => StatefulBuilder(
        builder: (c, setState) => AlertDialog(
          title: Text(t.addIndicator),
          content: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              DropdownButtonFormField<String>(
                initialValue: type,
                items: [
                  for (final x in ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email'])
                    DropdownMenuItem(value: x, child: Text(x)),
                ],
                onChanged: (v) => setState(() => type = v!),
              ),
              TextField(controller: value, decoration: InputDecoration(labelText: t.value)),
              TextField(controller: provenance, decoration: InputDecoration(labelText: t.provenance)),
              TextField(controller: contextCtrl, decoration: InputDecoration(labelText: t.context)),
              DropdownButtonFormField<int>(
                initialValue: sources,
                decoration: InputDecoration(labelText: t.independentSources),
                items: [for (var n = 1; n <= 5; n++) DropdownMenuItem(value: n, child: Text('$n'))],
                onChanged: (v) => setState(() => sources = v!),
              ),
            ]),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: Text(t.cancel)),
            FilledButton(
              onPressed: () async {
                try {
                  await s.api.post('/cases/$caseId/indicators', body: {
                    'type': type,
                    'value': value.text.trim(),
                    'provenance': provenance.text.trim(),
                    'context': contextCtrl.text.trim(),
                    'first_seen': DateTime.now().toUtc().toIso8601String(),
                    'independent_source_count': sources,
                  });
                  if (c.mounted) Navigator.pop(c, true);
                } catch (e) {
                  if (c.mounted) toast(c, errorMessage(c, e));
                }
              },
              child: Text(t.save),
            ),
          ],
        ),
      ),
    );
    return ok ?? false;
  }
}

class TimelineScreen extends StatelessWidget {
  const TimelineScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final api = AppServices.of(context).api;
    return Scaffold(
      appBar: AppBar(title: Text(t.timeline)),
      body: AsyncView<List<dynamic>>(
        load: () async {
          final timeline = await api.get('/analysis/timeline') as List;
          final corr = Map<String, dynamic>.from(await api.get('/analysis/correlations') as Map);
          return [timeline, corr];
        },
        builder: (context, data, _) {
          final events = [for (final e in data[0] as List) EventItem(Map<String, dynamic>.from(e as Map))];
          final corr = data[1] as Map<String, dynamic>;
          return ListView(padding: const EdgeInsets.all(12), children: [
            SectionTitle(t.chronology),
            if (events.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
            for (final e in events) EventTile(e: e),
            SectionTitle(t.contradictions),
            for (final c in (corr['contradictions'] as List).cast<Map>())
              Card(child: ListTile(leading: const Icon(Icons.compare_arrows), title: Text('${c['detail']}'), subtitle: Text('${c['type']}'))),
            SectionTitle(t.coOccurrences),
            NoticeBox(corr['notice'] as String),
            for (final c in (corr['co_occurrences'] as List).cast<Map>())
              Card(
                child: ListTile(
                  leading: const Icon(Icons.link),
                  title: Text((c['basis'] as List).join(', ')),
                  subtitle: Text('${t.confidence} ${t.confidenceLabel(c['confidence'] as String)}'
                      '${c['cross_case'] == true ? '  ·  ${t.crossCase}' : ''}'),
                ),
              ),
          ]);
        },
      ),
    );
  }
}

class MapScreen extends StatefulWidget {
  const MapScreen({super.key});

  @override
  State<MapScreen> createState() => _MapScreenState();
}

class _MapScreenState extends State<MapScreen> {
  Map<String, dynamic>? _selected;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(t.map)),
      body: AsyncView<Map>(
        load: () async => await s.api.get('/analysis/map') as Map,
        builder: (context, geo, _) {
          final features = (geo['features'] as List).cast<Map>();
          final points = [
            for (final f in features)
              (
                LatLng(((f['geometry'] as Map)['coordinates'] as List)[1] as double,
                    ((f['geometry'] as Map)['coordinates'] as List)[0] as double),
                Map<String, dynamic>.from(f['properties'] as Map),
              ),
          ];
          final center = points.isEmpty
              ? const LatLng(2, 20)
              : LatLng(points.map((p) => p.$1.latitude).reduce((a, b) => a + b) / points.length,
                  points.map((p) => p.$1.longitude).reduce((a, b) => a + b) / points.length);
          return Column(children: [
            NoticeBox((geo['meta'] as Map)['notice'] as String),
            if (s.config.mapTileUrl.isEmpty) NoticeBox(t.noTileServer),
            Expanded(
              child: FlutterMap(
                options: MapOptions(initialCenter: center, initialZoom: points.isEmpty ? 3 : 6),
                children: [
                  if (s.config.mapTileUrl.isNotEmpty)
                    TileLayer(urlTemplate: s.config.mapTileUrl, userAgentPackageName: 'org.aic.core.aic_mobile'),
                  CircleLayer(circles: [
                    for (final p in points)
                      if (p.$2['accuracy_m'] != null)
                        CircleMarker(
                          point: p.$1,
                          radius: (p.$2['accuracy_m'] as num).toDouble(),
                          useRadiusInMeter: true,
                          color: s.config.accentColor.withValues(alpha: 0.12),
                          borderColor: s.config.accentColor.withValues(alpha: 0.5),
                          borderStrokeWidth: 1,
                        ),
                  ]),
                  MarkerLayer(markers: [
                    for (final p in points)
                      Marker(
                        point: p.$1,
                        width: 28,
                        height: 28,
                        child: GestureDetector(
                          onTap: () => setState(() => _selected = p.$2),
                          child: Semantics(
                            label: p.$2['title'] as String,
                            child: Icon(
                              p.$2['kind'] == 'reference_site' ? Icons.apartment : _precisionIcon(p.$2['precision'] as String),
                              color: p.$2['kind'] == 'reference_site' ? AicColors.silver : s.config.accentColor,
                            ),
                          ),
                        ),
                      ),
                  ]),
                ],
              ),
            ),
            _Legend(selected: _selected),
          ]);
        },
      ),
    );
  }

  IconData _precisionIcon(String p) => switch (p) {
        'exact' => Icons.place,
        'approximate' => Icons.adjust,
        _ => Icons.blur_circular,
      };
}

class _Legend extends StatelessWidget {
  const _Legend({required this.selected});

  final Map<String, dynamic>? selected;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final sel = selected;
    return Container(
      width: double.infinity,
      color: AicColors.surface,
      padding: const EdgeInsets.all(12),
      child: sel == null
          ? Wrap(spacing: 16, children: [
              Row(mainAxisSize: MainAxisSize.min, children: [const Icon(Icons.place, size: 16), Text(' ${t.locationPrecision('exact')}')]),
              Row(mainAxisSize: MainAxisSize.min, children: [const Icon(Icons.adjust, size: 16), Text(' ${t.locationPrecision('approximate')}')]),
              Row(mainAxisSize: MainAxisSize.min, children: [const Icon(Icons.blur_circular, size: 16), Text(' ${t.locationPrecision('region')}')]),
              Row(mainAxisSize: MainAxisSize.min, children: [const Icon(Icons.apartment, size: 16), Text(' ${t.referenceSite}')]),
            ])
          : Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
              Text(sel['title'] as String, style: Theme.of(context).textTheme.titleMedium),
              Text('${t.locationPrecision(sel['precision'] as String? ?? 'unknown')}'
                  '${sel['accuracy_m'] != null ? ' (± ${(sel['accuracy_m'] as num).round()} m)' : ''}'),
              if (sel['provenance'] != null) Text('${t.locationProvenance} : ${sel['provenance']}'),
              if (sel['occurred_at'] != null) Text(fmtDate(DateTime.tryParse(sel['occurred_at'] as String)?.toLocal())),
            ]),
    );
  }
}

class GraphScreen extends StatelessWidget {
  const GraphScreen({super.key, required this.caseId, required this.reference});

  final String caseId;
  final String reference;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final api = AppServices.of(context).api;
    return Scaffold(
      appBar: AppBar(title: Text('${t.graph} · $reference')),
      body: AsyncView<Map>(
        load: () async => await api.get('/cases/$caseId/graph') as Map,
        isEmpty: (g) => (g['nodes'] as List).isEmpty,
        builder: (context, g, _) {
          final nodes = (g['nodes'] as List).cast<Map>();
          final edges = (g['edges'] as List).cast<Map>();
          return ListView(padding: const EdgeInsets.all(12), children: [
            NoticeBox(g['notice'] as String),
            SizedBox(
              height: 320,
              child: InteractiveViewer(
                minScale: 0.5,
                maxScale: 3,
                child: CustomPaint(painter: _GraphPainter(nodes, edges), size: const Size(double.infinity, 320)),
              ),
            ),
            SectionTitle(t.documentedRelations),
            for (final e in edges)
              Card(
                child: ListTile(
                  title: Text('${_label(nodes, e['from'])}  →  ${_label(nodes, e['to'])}'),
                  subtitle: Text('${e['type']}  ·  ${t.confidence} ${t.confidenceLabel(e['confidence'] as String)}\n'
                      '${t.basis} : ${e['basis']}${e['source_id'] == null ? '  ·  ${t.noSource}' : ''}'),
                  isThreeLine: true,
                ),
              ),
          ]);
        },
      ),
    );
  }

  String _label(List<Map> nodes, Object? id) =>
      nodes.firstWhere((n) => n['id'] == id, orElse: () => {'label': '?'})['label'] as String;
}

/// Circular layout: deterministic and readable for the small graphs of a case.
class _GraphPainter extends CustomPainter {
  _GraphPainter(this.nodes, this.edges);

  final List<Map> nodes;
  final List<Map> edges;

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = math.min(size.width, size.height) / 2 - 40;
    final pos = <Object?, Offset>{};
    for (var i = 0; i < nodes.length; i++) {
      final a = 2 * math.pi * i / nodes.length - math.pi / 2;
      pos[nodes[i]['id']] = center + Offset(math.cos(a) * radius, math.sin(a) * radius);
    }
    for (final e in edges) {
      final p1 = pos[e['from']], p2 = pos[e['to']];
      if (p1 == null || p2 == null) continue;
      final w = switch (e['confidence']) { 'high' => 2.5, 'moderate' => 1.6, _ => 1.0 };
      final paint = Paint()
        ..color = AicColors.silverMuted
        ..strokeWidth = w;
      canvas.drawLine(p1, p2, paint);
    }
    for (final n in nodes) {
      final p = pos[n['id']]!;
      canvas.drawCircle(p, 7, Paint()..color = AicColors.nightBlue);
      canvas.drawCircle(p, 7, Paint()..color = AicColors.silver..style = PaintingStyle.stroke..strokeWidth = 1.5);
      final tp = TextPainter(
        text: TextSpan(text: n['label'] as String, style: const TextStyle(color: AicColors.silver, fontSize: 11)),
        textDirection: TextDirection.ltr,
        maxLines: 1,
        ellipsis: '…',
      )..layout(maxWidth: 110);
      tp.paint(canvas, p + Offset(-tp.width / 2, 10));
    }
  }

  @override
  bool shouldRepaint(covariant _GraphPainter old) => old.nodes != nodes || old.edges != edges;
}
