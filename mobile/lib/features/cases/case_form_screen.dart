import 'package:flutter/material.dart';

import '../../core/services.dart';
import '../../l10n/app_localizations.dart';
import '../../widgets/common.dart';
import 'case_list_screen.dart';

class CaseFormScreen extends StatefulWidget {
  const CaseFormScreen({super.key});

  @override
  State<CaseFormScreen> createState() => _CaseFormScreenState();
}

class _CaseFormScreenState extends State<CaseFormScreen> {
  final _form = GlobalKey<FormState>();
  final _title = TextEditingController();
  final _jurisdiction = TextEditingController();
  final _legal = TextEditingController();
  final _summary = TextEditingController();
  final _context = TextEditingController();
  final _followUp = TextEditingController();
  String _category = caseCategories.first;
  String _priority = 'medium';
  int _classification = 1;
  String? _retention;
  DateTime _review = DateTime.now().add(const Duration(days: 90));
  bool _busy = false;

  @override
  Widget build(BuildContext context) {
    final t = AppLocalizations.of(context);
    final s = AppServices.of(context);
    final ranks = s.auth.markings.keys.where((r) => r <= s.auth.me!.clearanceRank).toList()..sort();
    String? required(String? v) => (v == null || v.trim().length < 3) ? t.fieldRequired : null;
    return Scaffold(
      appBar: AppBar(title: Text(t.newCase)),
      body: FutureBuilder<List>(
        future: s.api.get('/admin/retention-rules').then((v) => v as List),
        builder: (context, snap) {
          final rules = (snap.data ?? const []).cast<Map>();
          _retention ??= rules.isNotEmpty ? rules.first['code'] as String : null;
          return Form(
            key: _form,
            child: ListView(padding: const EdgeInsets.all(16), children: [
              TextFormField(controller: _title, validator: required, decoration: InputDecoration(labelText: t.caseTitle)),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                initialValue: _category,
                decoration: InputDecoration(labelText: t.category),
                items: [for (final c in caseCategories) DropdownMenuItem(value: c, child: Text(t.categoryLabel(c)))],
                onChanged: (v) => setState(() => _category = v!),
              ),
              const SizedBox(height: 12),
              NoticeBox(t.categoryNotice),
              TextFormField(controller: _jurisdiction, validator: required,
                  decoration: InputDecoration(labelText: t.jurisdiction)),
              const SizedBox(height: 12),
              TextFormField(controller: _legal, validator: required, maxLines: 2,
                  decoration: InputDecoration(labelText: t.legalBasis, helperText: t.legalBasisHelp)),
              const SizedBox(height: 12),
              Row(children: [
                Expanded(
                  child: DropdownButtonFormField<int>(
                    initialValue: ranks.contains(_classification) ? _classification : (ranks.isEmpty ? null : ranks.first),
                    decoration: InputDecoration(labelText: t.classification),
                    items: [for (final r in ranks) DropdownMenuItem(value: r, child: Text(s.auth.markings[r]!))],
                    onChanged: (v) => setState(() => _classification = v!),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: DropdownButtonFormField<String>(
                    initialValue: _priority,
                    decoration: InputDecoration(labelText: t.priority),
                    items: [
                      for (final p in ['low', 'medium', 'high', 'critical'])
                        DropdownMenuItem(value: p, child: Text(t.priorityLabel(p))),
                    ],
                    onChanged: (v) => setState(() => _priority = v!),
                  ),
                ),
              ]),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                initialValue: _retention,
                decoration: InputDecoration(labelText: t.retentionRule),
                items: [
                  for (final r in rules)
                    DropdownMenuItem(value: r['code'] as String, child: Text('${r['code']} (${r['retention_days']} j)')),
                ],
                onChanged: (v) => setState(() => _retention = v),
              ),
              const SizedBox(height: 12),
              ListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(t.reviewDate),
                subtitle: Text(fmtDay(_review)),
                trailing: const Icon(Icons.calendar_today),
                onTap: () async {
                  final d = await showDatePicker(
                    context: context,
                    initialDate: _review,
                    firstDate: DateTime.now().add(const Duration(days: 1)),
                    lastDate: DateTime.now().add(const Duration(days: 3650)),
                  );
                  if (d != null) setState(() => _review = d);
                },
              ),
              TextFormField(controller: _summary, maxLines: 4, decoration: InputDecoration(labelText: t.executiveSummary)),
              const SizedBox(height: 12),
              TextFormField(controller: _context, maxLines: 4, decoration: InputDecoration(labelText: t.analysisContext)),
              const SizedBox(height: 12),
              TextFormField(controller: _followUp, maxLines: 3,
                  decoration: InputDecoration(labelText: t.authorisedFollowUp, helperText: t.authorisedFollowUpHelp)),
              const SizedBox(height: 20),
              FilledButton(
                onPressed: _busy || _retention == null
                    ? null
                    : () async {
                        if (!_form.currentState!.validate()) return;
                        setState(() => _busy = true);
                        try {
                          await s.api.post('/cases', body: {
                            'title': _title.text.trim(),
                            'category': _category,
                            'country_code': s.config.countryCode,
                            'jurisdiction': _jurisdiction.text.trim(),
                            'classification_rank': _classification,
                            'priority': _priority,
                            'executive_summary': _summary.text.trim(),
                            'analysis_context': _context.text.trim(),
                            'legal_basis': _legal.text.trim(),
                            'authorised_follow_up': _followUp.text.trim(),
                            'review_date': fmtDay(_review),
                            'retention_rule_code': _retention,
                          });
                          if (context.mounted) {
                            toast(context, t.caseCreated);
                            Navigator.pop(context, true);
                          }
                        } catch (e) {
                          if (context.mounted) toast(context, errorMessage(context, e));
                        } finally {
                          if (mounted) setState(() => _busy = false);
                        }
                      },
                child: Padding(padding: const EdgeInsets.all(12), child: Text(t.create)),
              ),
            ]),
          );
        },
      ),
    );
  }
}
