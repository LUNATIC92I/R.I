import 'dart:io';

import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../models/models.dart';
import '../../widgets/common.dart';
import '../cases/case_forms.dart';

const reportTypes = [
  'intelligence_note',
  'daily_summary',
  'situation_report',
  'threat_assessment',
  'incident_report',
  'analytical_chronology',
  'strategic_watch_note',
  'executive_briefing',
  'case_closure_report',
];

class ReportsListScreen extends StatelessWidget {
  const ReportsListScreen({super.key, required this.caseId, required this.reference});

  final String caseId;
  final String reference;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    return Scaffold(
      appBar: AppBar(title: Text('${t.reports} · $reference')),
      body: _ReportList(caseId: caseId, canCreate: true),
    );
  }
}

class CaseReportsTab extends StatelessWidget {
  const CaseReportsTab({super.key, required this.c});

  final CaseDetail c;

  @override
  Widget build(BuildContext context) => _ReportList(caseId: c.id, canCreate: c.status == 'open');
}

class _ReportList extends StatelessWidget {
  const _ReportList({required this.caseId, required this.canCreate});

  final String caseId;
  final bool canCreate;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return AsyncView<List<ReportItem>>(
      load: () async => [for (final r in await s.api.get('/cases/$caseId/reports') as List) ReportItem(Map<String, dynamic>.from(r as Map))],
      builder: (context, reports, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        if (canCreate && s.auth.me!.can('report:write'))
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.note_add_outlined),
              label: Text(t.newReport),
              onPressed: () async {
                final created = await _create(context);
                if (created != null && context.mounted) {
                  await Navigator.push(context, MaterialPageRoute(builder: (_) => ReportEditorScreen(caseId: caseId, report: created)));
                  reload();
                }
              },
            ),
          ),
        if (reports.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
        for (final r in reports)
          Card(
            child: ListTile(
              title: Text(r.title),
              subtitle: Text('${r.reference}  ·  ${t.reportType(r.reportType)}'),
              trailing: Tag(t.reportStatus(r.status)),
              onTap: () async {
                await Navigator.push(context, MaterialPageRoute(builder: (_) => ReportEditorScreen(caseId: caseId, report: r)));
                reload();
              },
            ),
          ),
      ]),
    );
  }

  Future<ReportItem?> _create(BuildContext context) async {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    var type = reportTypes.first;
    final title = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => StatefulBuilder(
        builder: (c, setState) => AlertDialog(
          title: Text(t.newReport),
          content: Column(mainAxisSize: MainAxisSize.min, children: [
            DropdownButtonFormField<String>(
              initialValue: type,
              isExpanded: true,
              items: [for (final r in reportTypes) DropdownMenuItem(value: r, child: Text(t.reportType(r)))],
              onChanged: (v) => setState(() => type = v!),
            ),
            TextField(controller: title, decoration: InputDecoration(labelText: t.title)),
            const SizedBox(height: 8),
            Text(t.prefillNotice, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
          ]),
          actions: [
            TextButton(onPressed: () => Navigator.pop(c, false), child: Text(t.cancel)),
            FilledButton(onPressed: () => Navigator.pop(c, true), child: Text(t.create)),
          ],
        ),
      ),
    );
    if (ok != true || !context.mounted) return null;
    try {
      return ReportItem(Map<String, dynamic>.from(await s.api.post('/cases/$caseId/reports',
          body: {'report_type': type, 'title': title.text.trim().isEmpty ? t.reportType(type) : title.text.trim()}) as Map));
    } catch (e) {
      if (context.mounted) toast(context, errorMessage(context, e));
      return null;
    }
  }
}

class ReportEditorScreen extends StatefulWidget {
  const ReportEditorScreen({super.key, required this.caseId, required this.report});

  final String caseId;
  final ReportItem report;

  @override
  State<ReportEditorScreen> createState() => _ReportEditorScreenState();
}

class _ReportEditorScreenState extends State<ReportEditorScreen> {
  late ReportItem _r = widget.report;
  late final _title = TextEditingController(text: _r.title);
  late final _summary = TextEditingController(text: _r.summary);
  late final _analysis = TextEditingController(text: _r.analysis);
  late final _uncertainties = TextEditingController(text: _r.uncertainties);
  late final _recommendations = TextEditingController(text: _r.recommendations);

  String get _base => '/cases/${widget.caseId}/reports/${_r.id}';

  void _set(Object json) => setState(() => _r = ReportItem(Map<String, dynamic>.from(json as Map)));

  Future<void> _run(Future<void> Function() action) async {
    try {
      await action();
      if (mounted) toast(context, AppLocalizations.of(context).saved);
    } catch (e) {
      if (mounted) toast(context, errorMessage(context, e));
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    final editable = {'draft', 'rejected'}.contains(_r.status) && _r.authorId == me.id;
    Widget field(String label, TextEditingController c, int lines) => Padding(
          padding: const EdgeInsets.only(bottom: 12),
          child: TextField(controller: c, readOnly: !editable, maxLines: lines, decoration: InputDecoration(labelText: label)),
        );
    return Scaffold(
      appBar: AppBar(title: Text(_r.reference)),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        Wrap(spacing: 6, children: [Tag(t.reportType(_r.reportType)), Tag(t.reportStatus(_r.status))]),
        const SizedBox(height: 12),
        field(t.title, _title, 1),
        field(t.summaryLabel, _summary, 4),
        field(t.analysisLabel, _analysis, 10),
        field(t.uncertainties, _uncertainties, 4),
        field(t.recommendations, _recommendations, 4),
        Text(t.sourcesReferenced(_r.sourceIds.length), style: const TextStyle(color: AicColors.silverMuted)),
        NoticeBox(t.humanValidationNotice),
        Wrap(spacing: 8, runSpacing: 8, children: [
          if (editable) ...[
            OutlinedButton(
              onPressed: () => _run(() async => _set(await s.api.patch(_base, body: {
                    'version': _r.version,
                    'title': _title.text.trim(),
                    'summary': _summary.text,
                    'analysis': _analysis.text,
                    'uncertainties': _uncertainties.text,
                    'recommendations': _recommendations.text,
                  }))),
              child: Text(t.save),
            ),
            if (me.can('assistant:use'))
              OutlinedButton.icon(
                icon: const Icon(Icons.auto_fix_high_outlined),
                label: Text(t.assistantVerification),
                onPressed: () => _assistant(context),
              ),
            FilledButton(
              onPressed: () => _run(() async => _set(await s.api.post('$_base/submit'))),
              child: Text(t.submitForValidation),
            ),
          ],
          if (_r.status == 'submitted' && me.can('report:validate') && _r.authorId != me.id) ...[
            FilledButton(
              onPressed: () => _run(() async => _set(await s.api.post('$_base/decision', body: {'decision': 'approved'}))),
              child: Text(t.approve),
            ),
            OutlinedButton(
              onPressed: () async {
                final comment = await askText(context, t.rejectionReason);
                if (comment == null) return;
                await _run(() async => _set(await s.api.post('$_base/decision', body: {'decision': 'rejected', 'comment': comment})));
              },
              child: Text(t.reject),
            ),
          ],
          if ({'approved', 'disseminated'}.contains(_r.status) && me.can('report:export')) ...[
            OutlinedButton.icon(icon: const Icon(Icons.picture_as_pdf_outlined), label: const Text('PDF'), onPressed: () => _export(context, 'pdf')),
            OutlinedButton.icon(icon: const Icon(Icons.article_outlined), label: const Text('DOCX'), onPressed: () => _export(context, 'docx')),
          ],
        ]),
      ]),
    );
  }

  Future<void> _assistant(BuildContext context) async {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    try {
      final res = Map<String, dynamic>.from(
          await s.api.post('/cases/${widget.caseId}/assistant', body: {'task': 'verification_questions'}) as Map);
      final gaps = Map<String, dynamic>.from(await s.api.post('/cases/${widget.caseId}/assistant', body: {'task': 'gaps'}) as Map);
      if (!context.mounted) return;
      await showModalBottomSheet<void>(
        context: context,
        isScrollControlled: true,
        builder: (_) => DraggableScrollableSheet(
          expand: false,
          builder: (c, controller) => ListView(controller: controller, padding: const EdgeInsets.all(16), children: [
            Text(t.assistantVerification, style: Theme.of(context).textTheme.titleMedium),
            NoticeBox(res['notice'] as String),
            SectionTitle(t.verificationQuestions),
            for (final q in (res['items'] as List).cast<Map>()) ListTile(dense: true, title: Text('${q['question']}'), subtitle: Text('ref ${'${q['about']}'.substring(0, 8)}')),
            SectionTitle(t.informationGaps),
            for (final g in (gaps['items'] as List).cast<Map>()) ListTile(dense: true, title: Text('${g['detail']}')),
          ]),
        ),
      );
    } catch (e) {
      if (context.mounted) toast(context, errorMessage(context, e));
    }
  }

  Future<void> _export(BuildContext context, String fmt) async {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    try {
      final bytes = await withStepUp(context, () => s.api.getBytes('$_base/export', query: {'fmt': fmt}));
      if (bytes == null) return;
      final dir = Directory('${(await getApplicationSupportDirectory()).path}/aic_cache/exports');
      await dir.create(recursive: true);
      await File('${dir.path}/${_r.reference}.$fmt').writeAsBytes(bytes, flush: true);
      if (context.mounted) toast(context, t.downloadedPrivately(bytes.length));
      final fresh = await s.api.get(_base);
      _set(fresh as Object);
    } catch (e) {
      if (context.mounted) toast(context, errorMessage(context, e));
    }
  }
}
