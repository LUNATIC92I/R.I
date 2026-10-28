import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

import '../../core/api/api_client.dart';
import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../models/models.dart';
import '../../widgets/common.dart';
import '../analysis/report_screens.dart';
import 'case_forms.dart';

class CaseDetailScreen extends StatefulWidget {
  const CaseDetailScreen({super.key, required this.caseId});

  final String caseId;

  @override
  State<CaseDetailScreen> createState() => _CaseDetailScreenState();
}

class _CaseDetailScreenState extends State<CaseDetailScreen> {
  CaseDetail? _case;
  Object? _error;
  bool _fromOfflineCache = false;

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    if (_case == null && _error == null) _load();
  }

  Future<void> _load() async {
    final s = AppServices.of(context);
    try {
      final c = CaseDetail(Map<String, dynamic>.from(await s.api.get('/cases/${widget.caseId}') as Map));
      setState(() {
        _case = c;
        _error = null;
        _fromOfflineCache = false;
      });
    } on ApiException catch (e) {
      if (e.isNetwork) {
        final pkg = await s.offline.cached(widget.caseId);
        if (pkg != null) {
          setState(() {
            _case = CaseDetail(Map<String, dynamic>.from(pkg['case'] as Map));
            _fromOfflineCache = true;
          });
          return;
        }
      }
      setState(() => _error = e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    if (_error != null) {
      return Scaffold(
        appBar: AppBar(),
        body: MessageState(
            icon: Icons.error_outline,
            text: errorMessage(context, _error!),
            action: TextButton(onPressed: _load, child: Text(t.retry))),
      );
    }
    final c = _case;
    if (c == null) return const Scaffold(body: Center(child: CircularProgressIndicator(strokeWidth: 2)));
    final tabs = [t.overview, t.analyticalItems, t.sources, t.timeline, t.documents, t.assessments, t.reports, t.members];
    return DefaultTabController(
      length: tabs.length,
      child: Scaffold(
        appBar: AppBar(
          title: Text(c.reference),
          bottom: TabBar(isScrollable: true, tabAlignment: TabAlignment.start, tabs: [for (final x in tabs) Tab(text: x)]),
        ),
        body: Column(children: [
          ClassificationBanner(rank: c.classificationRank),
          if (_fromOfflineCache) NoticeBox(t.offlineCopyNotice),
          Expanded(
            child: TabBarView(children: [
              _Overview(c: c, onChanged: _load),
              _Statements(c: c, offline: _fromOfflineCache),
              _Sources(c: c),
              _Events(c: c, offline: _fromOfflineCache),
              _Documents(c: c),
              _Assessments(c: c),
              CaseReportsTab(c: c),
              _Members(c: c),
            ]),
          ),
        ]),
      ),
    );
  }
}

class _Field extends StatelessWidget {
  const _Field(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
          const SizedBox(height: 2),
          SelectableText(value.isEmpty ? '…' : value),
        ]),
      );
}

class _Overview extends StatelessWidget {
  const _Overview({required this.c, required this.onChanged});

  final CaseDetail c;
  final VoidCallback onChanged;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    Future<void> status(String action) async {
      final reason = await askText(context, t.justification);
      if (reason == null || !context.mounted) return;
      try {
        await withStepUp(context, () => s.api.post('/cases/${c.id}/status', body: {'action': action, 'justification': reason}));
        if (context.mounted) toast(context, t.saved);
        if (action == 'approve_deletion' && context.mounted) {
          Navigator.pop(context);
        } else {
          onChanged();
        }
      } catch (e) {
        if (context.mounted) toast(context, errorMessage(context, e));
      }
    }

    return ListView(padding: const EdgeInsets.all(16), children: [
      Text(c.title, style: Theme.of(context).textTheme.titleLarge),
      const SizedBox(height: 8),
      Wrap(spacing: 6, runSpacing: 4, children: [
        Tag(t.categoryLabel(c.category)),
        Tag(t.caseStatus(c.status)),
        Tag(t.priorityLabel(c.priority)),
        Tag('${t.confidence} : ${t.confidenceLabel(c.confidence)}'),
      ]),
      _Field(t.jurisdiction, '${c.jurisdiction} (${c.countryCode})'),
      _Field(t.executiveSummary, c.executiveSummary),
      _Field(t.analysisContext, c.analysisContext),
      _Field(t.legalBasis, c.legalBasis),
      _Field(t.authorisedFollowUp, c.authorisedFollowUp),
      _Field(t.reviewDate, fmtDay(c.reviewDate)),
      _Field(t.lastUpdate, fmtDate(c.updatedAt)),
      const SizedBox(height: 12),
      if (me.can('case:update') && c.status == 'open')
        OutlinedButton.icon(
          icon: const Icon(Icons.edit_outlined),
          label: Text(t.editSummary),
          onPressed: () async {
            final text = await askText(context, t.executiveSummary, initial: c.executiveSummary, minLength: 0, lines: 6);
            if (text == null || !context.mounted) return;
            try {
              await s.api.patch('/cases/${c.id}', body: {'version': c.version, 'executive_summary': text});
              onChanged();
            } on ApiException catch (e) {
              if (e.isNetwork) {
                await s.offline.enqueue('update_case_summary', c.id, {'executive_summary': text}, baseVersion: c.version);
                if (context.mounted) toast(context, t.offlineQueued);
              } else if (context.mounted) {
                toast(context, errorMessage(context, e));
              }
            }
          },
        ),
      if (c.offlineAllowed)
        OutlinedButton.icon(
          icon: const Icon(Icons.download_for_offline_outlined),
          label: Text(t.downloadOffline),
          onPressed: () async {
            try {
              final exp = await s.offline.download(c.id);
              if (context.mounted) toast(context, t.offlineExpires(fmtDate(exp.toLocal())));
            } catch (e) {
              if (context.mounted) toast(context, errorMessage(context, e));
            }
          },
        ),
      if (me.can('case:offline_authorize'))
        SwitchListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(t.offlineAuthorised),
          subtitle: Text(t.offlinePolicyHelp),
          value: c.offlineAllowed,
          onChanged: (v) async {
            try {
              await s.api.post('/cases/${c.id}/offline', query: {'allowed': v});
              onChanged();
            } catch (e) {
              if (context.mounted) toast(context, errorMessage(context, e));
            }
          },
        ),
      const Divider(),
      SectionTitle(t.lifecycle),
      Wrap(spacing: 8, runSpacing: 8, children: [
        if (c.status == 'open' && me.can('case:update'))
          OutlinedButton(onPressed: () => status('submit_review'), child: Text(t.submitReview)),
        if ({'open', 'under_review'}.contains(c.status) && me.can('case:close'))
          OutlinedButton(onPressed: () => status('close'), child: Text(t.closeCase)),
        if (c.status == 'closed' && me.can('case:close'))
          OutlinedButton(onPressed: () => status('reopen'), child: Text(t.reopenCase)),
        if (c.status == 'closed' && me.can('case:archive'))
          OutlinedButton(onPressed: () => status('archive'), child: Text(t.archiveCase)),
        if ({'closed', 'archived'}.contains(c.status) && me.can('case:delete_request'))
          OutlinedButton(onPressed: () => status('request_deletion'), child: Text(t.requestDeletion)),
        if (c.status == 'pending_deletion' && me.can('case:delete_approve'))
          FilledButton(
            style: FilledButton.styleFrom(backgroundColor: AicColors.danger),
            onPressed: () async {
              if (await confirm(context, t.approveDeletion, t.approveDeletionConfirm)) await status('approve_deletion');
            },
            child: Text(t.approveDeletion),
          ),
      ]),
      const SizedBox(height: 8),
      TextButton.icon(
        icon: const Icon(Icons.history),
        label: Text(t.history),
        onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => CaseHistoryScreen(caseId: c.id))),
      ),
    ]);
  }
}

class CaseHistoryScreen extends StatelessWidget {
  const CaseHistoryScreen({super.key, required this.caseId});

  final String caseId;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final api = AppServices.of(context).api;
    return Scaffold(
      appBar: AppBar(title: Text(t.history)),
      body: AsyncView<List>(
        load: () async => await api.get('/cases/$caseId/history') as List,
        isEmpty: (l) => l.isEmpty,
        builder: (context, rows, _) => ListView(children: [
          for (final r in rows.cast<Map>())
            ListTile(
              dense: true,
              title: Text('${r['action']}'),
              subtitle: Text('${r['actor']}  ·  ${fmtDate(DateTime.tryParse('${r['at']}')?.toLocal())}'),
              trailing: Tag('${r['outcome']}'),
            ),
        ]),
      ),
    );
  }
}

class _Statements extends StatelessWidget {
  const _Statements({required this.c, required this.offline});

  final CaseDetail c;
  final bool offline;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    Future<List<Statement>> load() async {
      final raw = offline
          ? ((await s.offline.cached(c.id))?['statements'] as List? ?? const [])
          : await s.api.get('/cases/${c.id}/statements') as List;
      return [for (final x in raw) Statement(Map<String, dynamic>.from(x as Map))];
    }

    return AsyncView<List<Statement>>(
      load: load,
      builder: (context, items, reload) {
        const order = ['confirmed_fact', 'unverified_information', 'claim', 'working_hypothesis', 'alternative_hypothesis'];
        return ListView(padding: const EdgeInsets.all(12), children: [
          NoticeBox(t.epistemicNotice),
          if (me.can('statement:write') && c.status == 'open')
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton.icon(
                icon: const Icon(Icons.add),
                label: Text(t.addStatement),
                onPressed: () async {
                  final added = await showStatementForm(context, c.id);
                  if (added) reload();
                },
              ),
            ),
          for (final kind in order) ...[
            SectionTitle('${t.statementKind(kind)} (${items.where((i) => i.kind == kind).length})'),
            for (final st in items.where((i) => i.kind == kind))
              Card(
                child: ListTile(
                  title: Text(st.text),
                  subtitle: Text([
                    '${t.credibility} ${st.credibility}',
                    if (st.sourceId == null) t.noSource else t.sourceLinked,
                    if (st.verifiedBy != null) t.verifiedByHuman,
                  ].join('  ·  ')),
                  trailing: kind != 'confirmed_fact' && me.can('statement:verify') && st.createdBy != me.id
                      ? IconButton(
                          tooltip: t.verifyFact,
                          icon: const Icon(Icons.verified_outlined),
                          onPressed: () async {
                            if (await showVerifyForm(context, c.id, st)) reload();
                          },
                        )
                      : null,
                ),
              ),
          ],
        ]);
      },
    );
  }
}

class _Sources extends StatelessWidget {
  const _Sources({required this.c});

  final CaseDetail c;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return AsyncView<List<SourceItem>>(
      load: () async => [for (final x in await s.api.get('/cases/${c.id}/sources') as List) SourceItem(Map<String, dynamic>.from(x as Map))],
      builder: (context, items, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        if (s.auth.me!.can('statement:write') && c.status == 'open')
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.add),
              label: Text(t.addSource),
              onPressed: () async {
                if (await showSourceForm(context, c.id)) reload();
              },
            ),
          ),
        if (items.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
        for (final src in items)
          Card(
            child: ListTile(
              leading: CircleAvatar(radius: 14, child: Text(src.reliability, style: const TextStyle(fontSize: 12))),
              title: Text(src.title),
              subtitle: Text([
                t.sourceKind(src.kind),
                '${t.publishedOn} ${fmtDay(src.publishedAt)}',
                '${t.collectedOn} ${fmtDay(src.collectedAt)}',
                if (src.url != null) src.url!,
              ].join('\n')),
              isThreeLine: true,
            ),
          ),
      ]),
    );
  }
}

class _Events extends StatelessWidget {
  const _Events({required this.c, required this.offline});

  final CaseDetail c;
  final bool offline;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return AsyncView<List<EventItem>>(
      load: () async {
        final raw = offline
            ? ((await s.offline.cached(c.id))?['events'] as List? ?? const [])
            : await s.api.get('/cases/${c.id}/events') as List;
        return [for (final x in raw) EventItem(Map<String, dynamic>.from(x as Map))];
      },
      builder: (context, items, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        if (s.auth.me!.can('statement:write') && c.status == 'open')
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.add),
              label: Text(t.addEvent),
              onPressed: () async {
                if (await showEventForm(context, c.id)) reload();
              },
            ),
          ),
        if (items.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
        for (final e in items) EventTile(e: e),
      ]),
    );
  }
}

class EventTile extends StatelessWidget {
  const EventTile({super.key, required this.e});

  final EventItem e;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    return Card(
      child: ListTile(
        leading: const Icon(Icons.radio_button_checked, size: 16),
        title: Text(e.title),
        subtitle: Text([
          e.occurredAt == null ? t.undated : '${fmtDate(e.occurredAt)} (${t.datePrecision(e.datePrecision)})',
          if (e.locationLabel != null) e.locationLabel!,
          t.locationPrecision(e.locationPrecision),
        ].join('  ·  ')),
      ),
    );
  }
}

class _Documents extends StatelessWidget {
  const _Documents({required this.c});

  final CaseDetail c;

  static const _mime = {
    'pdf': 'application/pdf',
    'txt': 'text/plain',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  };

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    return AsyncView<List>(
      load: () async => await s.api.get('/cases/${c.id}/documents') as List,
      builder: (context, docs, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        if (me.can('document:upload') && c.status == 'open')
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.upload_file),
              label: Text(t.attachDocument),
              onPressed: () async {
                final file = await FilePicker.pickFile(type: FileType.custom, allowedExtensions: _mime.keys.toList());
                if (file == null || !context.mounted) return;
                final ext = (file.extension ?? '').toLowerCase().replaceAll('.', '');
                try {
                  await s.api.postMultipart('/cases/${c.id}/documents',
                      {'title': file.name, 'classification_rank': '${c.classificationRank}'},
                      'file', file.name, await file.readAsBytes(), _mime[ext] ?? 'application/octet-stream');
                  reload();
                } catch (e) {
                  if (context.mounted) toast(context, errorMessage(context, e));
                }
              },
            ),
          ),
        if (docs.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
        for (final d in docs.cast<Map>())
          Card(
            child: ListTile(
              leading: const Icon(Icons.insert_drive_file_outlined),
              title: Text(d['title'] as String),
              subtitle: Text('${t.version} ${d['current_version']}  ·  ${s.auth.markings[d['classification_rank']] ?? ''}'),
              trailing: me.can('document:download') && d['download_allowed'] == true
                  ? IconButton(
                      tooltip: t.download,
                      icon: const Icon(Icons.download_outlined),
                      onPressed: () => _download(context, d),
                    )
                  : null,
            ),
          ),
      ]),
    );
  }

  Future<void> _download(BuildContext context, Map d) async {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    try {
      final bytes = await withStepUp(context, () => s.api.getBytes('/cases/${c.id}/documents/${d['id']}/content'));
      if (bytes == null || !context.mounted) return;
      // Saved inside the encrypted-at-rest app sandbox and purged at sign-out.
      final dir = Directory('${(await getApplicationSupportDirectory()).path}/aic_cache/exports');
      await dir.create(recursive: true);
      final file = File('${dir.path}/${d['id']}');
      await file.writeAsBytes(bytes, flush: true);
      if (context.mounted) toast(context, t.downloadedPrivately(bytes.length));
    } catch (e) {
      if (context.mounted) toast(context, errorMessage(context, e));
    }
  }
}

class _Assessments extends StatelessWidget {
  const _Assessments({required this.c});

  final CaseDetail c;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final me = s.auth.me!;
    return AsyncView<List>(
      load: () async => await s.api.get('/cases/${c.id}/assessments') as List,
      builder: (context, items, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        if (me.can('assessment:write') && c.status == 'open')
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.add),
              label: Text(t.newAssessment),
              onPressed: () async {
                if (await showAssessmentForm(context, c.id, c.category)) reload();
              },
            ),
          ),
        if (items.isEmpty) MessageState(icon: Icons.inbox_outlined, text: t.emptyList),
        for (final a in items.cast<Map>()) AssessmentCard(a: Map<String, dynamic>.from(a), caseId: c.id, onChanged: reload),
      ]),
    );
  }
}

class AssessmentCard extends StatelessWidget {
  const AssessmentCard({super.key, required this.a, required this.caseId, required this.onChanged});

  final Map<String, dynamic> a;
  final String caseId;
  final VoidCallback onChanged;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    List<String> list(String k) => (a[k] as List).map((e) => '$e').toList();
    Widget block(String title, List<String> items) => items.isEmpty
        ? const SizedBox.shrink()
        : Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(title, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
              for (final i in items) Text('•  $i'),
            ]),
          );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Expanded(child: Text(a['threat'] as String, style: Theme.of(context).textTheme.titleMedium)),
            Tag(t.assessmentLevel(a['level'] as String),
                color: a['level'] == 'confirmed_threat' ? AicColors.danger : AicColors.silverMuted),
          ]),
          const SizedBox(height: 6),
          Text('${t.reliability} ${a['source_reliability']}  ·  ${t.credibility} ${a['information_credibility']}  ·  '
              '${t.uncertainty} ${t.uncertaintyLabel(a['uncertainty'] as String)}'),
          block(t.observedFacts, list('observed_facts')),
          block(t.alternativeHypotheses, list('alternative_hypotheses')),
          block(t.contradictingElements, list('contradicting_elements')),
          block(t.recommendedVerifications, list('recommended_verifications')),
          if ((a['possible_consequences'] as String).isNotEmpty) block(t.possibleConsequences, [a['possible_consequences'] as String]),
          const SizedBox(height: 8),
          Text('${t.analyst} ${a['analyst_professional_id']}  ·  ${t.lastAssessed} '
              '${fmtDate(DateTime.tryParse(a['last_assessed_at'] as String)?.toLocal())}',
              style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
          NoticeBox(a['disclaimer'] as String),
          if (a['level'] != 'confirmed_threat' && s.auth.me!.can('assessment:confirm') && a['analyst_id'] != s.auth.me!.id)
            OutlinedButton(
              onPressed: () async {
                final j = await askText(context, t.justification, minLength: 10);
                if (j == null || !context.mounted) return;
                try {
                  await withStepUp(context, () => s.api.post('/cases/$caseId/assessments/${a['id']}/confirm',
                      body: {'justification': j}));
                  onChanged();
                } catch (e) {
                  if (context.mounted) toast(context, errorMessage(context, e));
                }
              },
              child: Text(t.confirmThreat),
            ),
        ]),
      ),
    );
  }
}

class _Members extends StatelessWidget {
  const _Members({required this.c});

  final CaseDetail c;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final canManage = s.auth.me!.can('case:manage_members');
    return AsyncView<List>(
      load: () async => await s.api.get('/cases/${c.id}/members') as List,
      builder: (context, members, reload) => ListView(padding: const EdgeInsets.all(12), children: [
        NoticeBox(t.needToKnowNotice),
        if (canManage)
          Align(
            alignment: Alignment.centerRight,
            child: FilledButton.icon(
              icon: const Icon(Icons.person_add_alt),
              label: Text(t.grantAccess),
              onPressed: () async {
                if (await showMemberForm(context, c.id)) reload();
              },
            ),
          ),
        for (final m in members.cast<Map>())
          Card(
            child: ListTile(
              title: Text('${m['user_id']}'.substring(0, 8)),
              subtitle: Text('${t.accessLevel(m['access'] as String)}  ·  ${m['justification']}'
                  '${m['expires_at'] != null ? '  ·  ${t.until} ${fmtDay(DateTime.tryParse('${m['expires_at']}'))}' : ''}'),
              trailing: canManage
                  ? IconButton(
                      tooltip: t.revoke,
                      icon: const Icon(Icons.remove_circle_outline),
                      onPressed: () async {
                        try {
                          await s.api.delete('/cases/${c.id}/members/${m['user_id']}');
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
    );
  }
}
