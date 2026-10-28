import 'package:flutter/material.dart';

import '../../core/api/api_client.dart';
import '../../core/services.dart';
import '../../l10n/app_localizations.dart';
import '../../models/models.dart';
import '../../widgets/common.dart';

Future<String?> askText(BuildContext context, String label, {String initial = '', int minLength = 3, int lines = 3}) {
  final t = AppLocalizations.of(context);
  final ctrl = TextEditingController(text: initial);
  return showDialog<String>(
    context: context,
    builder: (c) => AlertDialog(
      title: Text(label),
      content: TextField(controller: ctrl, maxLines: lines, autofocus: true),
      actions: [
        TextButton(onPressed: () => Navigator.pop(c), child: Text(t.cancel)),
        FilledButton(
          onPressed: () {
            if (ctrl.text.trim().length < minLength) {
              toast(c, t.fieldRequired);
              return;
            }
            Navigator.pop(c, ctrl.text.trim());
          },
          child: Text(t.confirm),
        ),
      ],
    ),
  );
}

/// Bottom-sheet form scaffold with a submit action and error reporting.
Future<bool> _sheet(BuildContext context, String title, List<Widget> Function(StateSetter) fields,
    Future<void> Function() submit) async {
  final t = AppLocalizations.of(context);
  final ok = await showModalBottomSheet<bool>(
    context: context,
    isScrollControlled: true,
    builder: (c) => StatefulBuilder(
      builder: (c, setState) => Padding(
        padding: EdgeInsets.fromLTRB(16, 16, 16, MediaQuery.of(c).viewInsets.bottom + 16),
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Text(title, style: Theme.of(c).textTheme.titleMedium),
            const SizedBox(height: 12),
            ...fields(setState),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: () async {
                try {
                  await submit();
                  if (c.mounted) Navigator.pop(c, true);
                } catch (e) {
                  if (c.mounted) toast(c, errorMessage(c, e));
                }
              },
              child: Text(t.save),
            ),
          ]),
        ),
      ),
    ),
  );
  return ok ?? false;
}

Future<List<SourceItem>> _sources(BuildContext context, String caseId) async {
  final api = AppServices.of(context).api;
  try {
    return [for (final x in await api.get('/cases/$caseId/sources') as List) SourceItem(Map<String, dynamic>.from(x as Map))];
  } on ApiException {
    return [];
  }
}

Future<bool> showStatementForm(BuildContext context, String caseId) async {
  final t = AppLocalizations.of(context);
  final s = AppServices.of(context);
  final sources = await _sources(context, caseId);
  if (!context.mounted) return false;
  final text = TextEditingController();
  var kind = 'unverified_information';
  var credibility = 6;
  String? sourceId;
  return _sheet(context, t.addStatement, (setState) => [
        DropdownButtonFormField<String>(
          initialValue: kind,
          decoration: InputDecoration(labelText: t.kind),
          items: [
            for (final k in ['unverified_information', 'claim', 'working_hypothesis', 'alternative_hypothesis'])
              DropdownMenuItem(value: k, child: Text(t.statementKind(k))),
          ],
          onChanged: (v) => setState(() => kind = v!),
        ),
        const SizedBox(height: 8),
        TextField(controller: text, maxLines: 4, decoration: InputDecoration(labelText: t.content)),
        const SizedBox(height: 8),
        DropdownButtonFormField<String?>(
          initialValue: sourceId,
          decoration: InputDecoration(labelText: t.source),
          items: [
            DropdownMenuItem<String?>(value: null, child: Text(t.noSource)),
            for (final src in sources) DropdownMenuItem(value: src.id, child: Text('${src.reliability} · ${src.title}')),
          ],
          onChanged: (v) => setState(() => sourceId = v),
        ),
        const SizedBox(height: 8),
        DropdownButtonFormField<int>(
          initialValue: credibility,
          decoration: InputDecoration(labelText: t.credibility),
          items: [for (var i = 1; i <= 6; i++) DropdownMenuItem(value: i, child: Text(t.credibilityLabel('$i')))],
          onChanged: (v) => setState(() => credibility = v!),
        ),
      ], () async {
    final payload = {'kind': kind, 'text': text.text.trim(), 'credibility': credibility, 'source_id': sourceId};
    try {
      await s.api.post('/cases/$caseId/statements', body: payload);
    } on ApiException catch (e) {
      if (!e.isNetwork) rethrow;
      await s.offline.enqueue('add_statement', caseId, payload);
      if (context.mounted) toast(context, t.offlineQueued);
    }
  });
}

Future<bool> showVerifyForm(BuildContext context, String caseId, Statement st) async {
  final t = AppLocalizations.of(context);
  final s = AppServices.of(context);
  final sources = await _sources(context, caseId);
  if (!context.mounted) return false;
  if (sources.isEmpty) {
    toast(context, t.verifyNeedsSource);
    return false;
  }
  var sourceId = st.sourceId ?? sources.first.id;
  var credibility = 2;
  return _sheet(context, t.verifyFact, (setState) => [
        Text(st.text),
        NoticeBox(t.verifyNotice),
        DropdownButtonFormField<String>(
          initialValue: sourceId,
          decoration: InputDecoration(labelText: t.source),
          items: [for (final src in sources) DropdownMenuItem(value: src.id, child: Text('${src.reliability} · ${src.title}'))],
          onChanged: (v) => setState(() => sourceId = v!),
        ),
        const SizedBox(height: 8),
        DropdownButtonFormField<int>(
          initialValue: credibility,
          decoration: InputDecoration(labelText: t.credibility),
          items: [for (var i = 1; i <= 6; i++) DropdownMenuItem(value: i, child: Text(t.credibilityLabel('$i')))],
          onChanged: (v) => setState(() => credibility = v!),
        ),
      ], () async {
    await s.api.post('/cases/$caseId/statements/${st.id}/verify',
        body: {'version': st.version, 'source_id': sourceId, 'credibility': credibility});
  });
}

Future<bool> showSourceForm(BuildContext context, String caseId) {
  final t = AppLocalizations.of(context);
  final s = AppServices.of(context);
  final title = TextEditingController();
  final url = TextEditingController();
  final legal = TextEditingController();
  final protectedRef = TextEditingController();
  var kind = 'official_report';
  var reliability = 'F';
  return _sheet(context, t.addSource, (setState) => [
        DropdownButtonFormField<String>(
          initialValue: kind,
          decoration: InputDecoration(labelText: t.kind),
          items: [
            for (final k in ['open_source', 'institutional_system', 'official_report', 'human_protected', 'technical', 'other'])
              DropdownMenuItem(value: k, child: Text(t.sourceKind(k))),
          ],
          onChanged: (v) => setState(() => kind = v!),
        ),
        const SizedBox(height: 8),
        TextField(controller: title, decoration: InputDecoration(labelText: t.title)),
        const SizedBox(height: 8),
        if (kind == 'human_protected') ...[
          NoticeBox(t.protectedSourceNotice),
          TextField(controller: protectedRef, decoration: InputDecoration(labelText: t.protectedReference)),
        ] else
          TextField(controller: url, keyboardType: TextInputType.url, decoration: InputDecoration(labelText: t.url)),
        const SizedBox(height: 8),
        DropdownButtonFormField<String>(
          initialValue: reliability,
          decoration: InputDecoration(labelText: t.reliability),
          items: [for (final r in ['A', 'B', 'C', 'D', 'E', 'F']) DropdownMenuItem(value: r, child: Text(t.reliabilityLabel(r)))],
          onChanged: (v) => setState(() => reliability = v!),
        ),
        const SizedBox(height: 8),
        TextField(controller: legal, decoration: InputDecoration(labelText: t.legalBasis)),
      ], () async {
    await s.api.post('/cases/$caseId/sources', body: {
      'kind': kind,
      'title': title.text.trim(),
      'reliability': reliability,
      'legal_basis': legal.text.trim(),
      if (url.text.trim().isNotEmpty) 'url': url.text.trim(),
      if (protectedRef.text.trim().isNotEmpty) 'protected_reference': protectedRef.text.trim(),
    });
  });
}

Future<bool> showEventForm(BuildContext context, String caseId) {
  final t = AppLocalizations.of(context);
  final s = AppServices.of(context);
  final title = TextEditingController();
  final description = TextEditingController();
  final place = TextEditingController();
  final lat = TextEditingController();
  final lon = TextEditingController();
  final accuracy = TextEditingController();
  final provenance = TextEditingController();
  var precision = 'unknown';
  DateTime? when;
  return _sheet(context, t.addEvent, (setState) => [
        TextField(controller: title, decoration: InputDecoration(labelText: t.title)),
        const SizedBox(height: 8),
        TextField(controller: description, maxLines: 3, decoration: InputDecoration(labelText: t.description)),
        ListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(t.eventDate),
          subtitle: Text(when == null ? t.undated : fmtDay(when)),
          trailing: const Icon(Icons.calendar_today),
          onTap: () async {
            final d = await showDatePicker(
                context: context, initialDate: DateTime.now(), firstDate: DateTime(1990), lastDate: DateTime(2100));
            if (d != null) setState(() => when = d);
          },
        ),
        TextField(controller: place, decoration: InputDecoration(labelText: t.locationLabel)),
        const SizedBox(height: 8),
        DropdownButtonFormField<String>(
          initialValue: precision,
          decoration: InputDecoration(labelText: t.locationPrecisionTitle),
          items: [
            for (final p in ['exact', 'approximate', 'region', 'unknown'])
              DropdownMenuItem(value: p, child: Text(t.locationPrecision(p))),
          ],
          onChanged: (v) => setState(() => precision = v!),
        ),
        if (precision != 'unknown') ...[
          Row(children: [
            Expanded(child: TextField(controller: lat, keyboardType: const TextInputType.numberWithOptions(decimal: true, signed: true), decoration: InputDecoration(labelText: t.latitude))),
            const SizedBox(width: 8),
            Expanded(child: TextField(controller: lon, keyboardType: const TextInputType.numberWithOptions(decimal: true, signed: true), decoration: InputDecoration(labelText: t.longitude))),
          ]),
          TextField(controller: accuracy, keyboardType: TextInputType.number, decoration: InputDecoration(labelText: t.accuracyMeters)),
          TextField(controller: provenance, decoration: InputDecoration(labelText: t.locationProvenance)),
        ],
      ], () async {
    final payload = <String, dynamic>{
      'title': title.text.trim(),
      'description': description.text.trim(),
      'date_precision': when == null ? 'unknown' : 'day',
      if (when != null) 'occurred_at': when!.toUtc().toIso8601String(),
      if (place.text.trim().isNotEmpty) 'location_label': place.text.trim(),
      'location_precision': precision,
      if (precision != 'unknown') 'latitude': double.tryParse(lat.text.replaceAll(',', '.')),
      if (precision != 'unknown') 'longitude': double.tryParse(lon.text.replaceAll(',', '.')),
      if (accuracy.text.isNotEmpty) 'location_accuracy_m': double.tryParse(accuracy.text),
      if (provenance.text.trim().isNotEmpty) 'location_provenance': provenance.text.trim(),
    };
    try {
      await s.api.post('/cases/$caseId/events', body: payload);
    } on ApiException catch (e) {
      if (!e.isNetwork) rethrow;
      await s.offline.enqueue('add_event', caseId, payload);
      if (context.mounted) toast(context, t.offlineQueued);
    }
  });
}

Future<bool> showAssessmentForm(BuildContext context, String caseId, String category) async {
  final t = AppLocalizations.of(context);
  final s = AppServices.of(context);
  final sources = await _sources(context, caseId);
  if (!context.mounted) return false;
  final threat = TextEditingController();
  final facts = TextEditingController();
  final alternatives = TextEditingController();
  final contradictions = TextEditingController();
  final consequences = TextEditingController();
  final verifications = TextEditingController();
  var level = 'signal';
  var uncertainty = 'high';
  final selected = <String>{};
  List<String> lines(TextEditingController c) =>
      c.text.split('\n').map((e) => e.trim()).where((e) => e.isNotEmpty).toList();
  return _sheet(context, t.newAssessment, (setState) => [
        TextField(controller: threat, decoration: InputDecoration(labelText: t.threatStudied)),
        const SizedBox(height: 8),
        DropdownButtonFormField<String>(
          initialValue: level,
          decoration: InputDecoration(labelText: t.assessmentLevelTitle),
          items: [
            for (final l in ['signal', 'anomaly', 'actionable_intelligence'])
              DropdownMenuItem(value: l, child: Text(t.assessmentLevel(l))),
          ],
          onChanged: (v) => setState(() => level = v!),
        ),
        NoticeBox(t.levelNotice),
        TextField(controller: facts, maxLines: 3, decoration: InputDecoration(labelText: t.observedFacts, helperText: t.onePerLine)),
        const SizedBox(height: 8),
        Text(t.sources),
        for (final src in sources)
          CheckboxListTile(
            dense: true,
            value: selected.contains(src.id),
            title: Text('${src.reliability} · ${src.title}'),
            onChanged: (v) => setState(() => v == true ? selected.add(src.id) : selected.remove(src.id)),
          ),
        TextField(controller: alternatives, maxLines: 3,
            decoration: InputDecoration(labelText: t.alternativeHypotheses, helperText: t.onePerLine)),
        TextField(controller: contradictions, maxLines: 2,
            decoration: InputDecoration(labelText: t.contradictingElements, helperText: t.onePerLine)),
        TextField(controller: consequences, maxLines: 2, decoration: InputDecoration(labelText: t.possibleConsequences)),
        TextField(controller: verifications, maxLines: 2,
            decoration: InputDecoration(labelText: t.recommendedVerifications, helperText: t.onePerLine)),
        DropdownButtonFormField<String>(
          initialValue: uncertainty,
          decoration: InputDecoration(labelText: t.uncertainty),
          items: [
            for (final u in ['low', 'moderate', 'high', 'very_high'])
              DropdownMenuItem(value: u, child: Text(t.uncertaintyLabel(u))),
          ],
          onChanged: (v) => setState(() => uncertainty = v!),
        ),
      ], () async {
    final chosen = sources.where((x) => selected.contains(x.id)).toList();
    const order = 'ABCDEF';
    final best = chosen.isEmpty ? 'F' : chosen.map((x) => x.reliability).reduce((a, b) => order.indexOf(a) < order.indexOf(b) ? a : b);
    await s.api.post('/cases/$caseId/assessments', body: {
      'threat': threat.text.trim(),
      'category': category,
      'level': level,
      'observed_facts': lines(facts),
      'source_ids': selected.toList(),
      'source_reliability': best,
      'alternative_hypotheses': lines(alternatives),
      'contradicting_elements': lines(contradictions),
      'possible_consequences': consequences.text.trim(),
      'uncertainty': uncertainty,
      'recommended_verifications': lines(verifications),
    });
  });
}

Future<bool> showMemberForm(BuildContext context, String caseId) async {
  final t = AppLocalizations.of(context);
  final s = AppServices.of(context);
  List<Map> people;
  try {
    people = (await s.api.get('/admin/directory') as List).cast<Map>();
  } catch (e) {
    if (context.mounted) toast(context, errorMessage(context, e));
    return false;
  }
  if (!context.mounted) return false;
  final justification = TextEditingController();
  String? userId;
  var access = 'read';
  DateTime? until;
  return _sheet(context, t.grantAccess, (setState) => [
        DropdownButtonFormField<String>(
          initialValue: userId,
          isExpanded: true,
          decoration: InputDecoration(labelText: t.colleague),
          items: [
            for (final p in people)
              DropdownMenuItem(value: p['id'] as String, child: Text('${p['display_name']} (${p['professional_id']})')),
          ],
          onChanged: (v) => setState(() => userId = v),
        ),
        DropdownButtonFormField<String>(
          initialValue: access,
          decoration: InputDecoration(labelText: t.accessLevelTitle),
          items: [for (final a in ['read', 'write']) DropdownMenuItem(value: a, child: Text(t.accessLevel(a)))],
          onChanged: (v) => setState(() => access = v!),
        ),
        TextField(controller: justification, decoration: InputDecoration(labelText: t.justification)),
        ListTile(
          contentPadding: EdgeInsets.zero,
          title: Text(t.until),
          subtitle: Text(until == null ? t.noExpiry : fmtDay(until)),
          onTap: () async {
            final d = await showDatePicker(context: context, initialDate: DateTime.now().add(const Duration(days: 30)),
                firstDate: DateTime.now(), lastDate: DateTime.now().add(const Duration(days: 3650)));
            if (d != null) setState(() => until = d);
          },
        ),
      ], () async {
    await s.api.post('/cases/$caseId/members', body: {
      'user_id': userId,
      'access': access,
      'justification': justification.text.trim(),
      if (until != null) 'expires_at': until!.toUtc().toIso8601String(),
    });
  });
}
