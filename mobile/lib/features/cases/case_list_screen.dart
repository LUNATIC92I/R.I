import 'package:flutter/material.dart';

import '../../core/services.dart';
import '../../core/theme.dart';
import '../../l10n/app_localizations.dart';
import '../../models/models.dart';
import '../../widgets/common.dart';
import 'case_detail_screen.dart';
import 'case_form_screen.dart';

const caseCategories = [
  'terrorism_organised_violence',
  'organised_crime',
  'illicit_trafficking',
  'critical_infrastructure',
  'cyber_threat_public_institutions',
  'foreign_interference',
  'physical_threat_sensitive_sites',
  'security_crisis_destabilisation',
  'administrative_inquiry',
  'other',
];

class CaseListScreen extends StatefulWidget {
  const CaseListScreen({super.key, this.onPick});

  /// When set, tapping a case returns it instead of opening it.
  final void Function(CaseSummary)? onPick;

  @override
  State<CaseListScreen> createState() => _CaseListScreenState();
}

class _CaseListScreenState extends State<CaseListScreen> {
  String? _status = 'open';
  String? _category;
  String? _priority;
  final _q = TextEditingController();
  Key _listKey = UniqueKey();

  void _refresh() => setState(() => _listKey = UniqueKey());

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(widget.onPick == null ? t.cases : t.pickCase)),
      floatingActionButton: widget.onPick == null && s.auth.me!.can('case:create')
          ? FloatingActionButton.extended(
              icon: const Icon(Icons.add),
              label: Text(t.newCase),
              onPressed: () async {
                final created = await Navigator.push<bool>(
                    context, MaterialPageRoute(builder: (_) => const CaseFormScreen()));
                if (created == true) _refresh();
              },
            )
          : null,
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
          child: TextField(
            controller: _q,
            decoration: InputDecoration(labelText: t.filterTitle, prefixIcon: const Icon(Icons.filter_list)),
            onSubmitted: (_) => _refresh(),
          ),
        ),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
          child: Row(children: [
            _drop<String>(t.status, _status, ['open', 'under_review', 'closed', 'archived'], t.caseStatus,
                (v) => setState(() {
                      _status = v;
                      _listKey = UniqueKey();
                    })),
            const SizedBox(width: 8),
            _drop<String>(t.category, _category, caseCategories, t.categoryLabel, (v) => setState(() {
                  _category = v;
                  _listKey = UniqueKey();
                })),
            const SizedBox(width: 8),
            _drop<String>(t.priority, _priority, ['low', 'medium', 'high', 'critical'], t.priorityLabel,
                (v) => setState(() {
                      _priority = v;
                      _listKey = UniqueKey();
                    })),
          ]),
        ),
        Expanded(
          child: AsyncView<List<CaseSummary>>(
            key: _listKey,
            load: () async => [
              for (final c in await s.api.get('/cases', query: {
                'status': _status,
                'category': _category,
                'priority': _priority,
                'q': _q.text.trim().isEmpty ? null : _q.text.trim(),
              }) as List)
                CaseSummary(Map<String, dynamic>.from(c as Map)),
            ],
            isEmpty: (l) => l.isEmpty,
            emptyText: t.noCases,
            builder: (context, cases, _) => ListView.builder(
              padding: const EdgeInsets.all(12),
              itemCount: cases.length,
              itemBuilder: (context, i) => CaseTile(
                c: cases[i],
                onTap: () {
                  if (widget.onPick != null) {
                    widget.onPick!(cases[i]);
                  } else {
                    Navigator.push(context, MaterialPageRoute(builder: (_) => CaseDetailScreen(caseId: cases[i].id)))
                        .then((_) => _refresh());
                  }
                },
              ),
            ),
          ),
        ),
      ]),
    );
  }

  Widget _drop<T>(String label, T? value, List<T> options, String Function(String) text, ValueChanged<T?> onChanged) {
    return DropdownButton<T?>(
      value: value,
      hint: Text(label),
      underline: const SizedBox.shrink(),
      items: [
        DropdownMenuItem<T?>(value: null, child: Text('$label : ${AppLocalizations.of(context).all}')),
        for (final o in options) DropdownMenuItem<T?>(value: o, child: Text(text('$o'))),
      ],
      onChanged: onChanged,
    );
  }
}

class CaseTile extends StatelessWidget {
  const CaseTile({super.key, required this.c, required this.onTap});

  final CaseSummary c;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final due = c.reviewDate.isBefore(DateTime.now().add(const Duration(days: 14)));
    return Card(
      child: InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.all(14),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Text(c.reference, style: const TextStyle(fontSize: 12, color: AicColors.silverMuted)),
              const Spacer(),
              Tag(t.priorityLabel(c.priority),
                  color: c.priority == 'critical' || c.priority == 'high' ? AicColors.warning : null),
            ]),
            const SizedBox(height: 6),
            Text(c.title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 6),
            Wrap(spacing: 6, runSpacing: 4, children: [
              Tag(t.categoryLabel(c.category)),
              Tag(t.caseStatus(c.status)),
              Tag(AppServices.of(context).auth.markings[c.classificationRank] ?? t.classificationLevel(c.classificationRank)),
              if (due) Tag(t.reviewOn(fmtDay(c.reviewDate)), color: AicColors.warning),
            ]),
          ]),
        ),
      ),
    );
  }
}
