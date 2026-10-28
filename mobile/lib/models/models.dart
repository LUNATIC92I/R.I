/// Typed views over API payloads. Unknown fields are ignored.
library;

DateTime? _date(Object? v) => v == null ? null : DateTime.tryParse(v as String)?.toLocal();

class Me {
  Me(this.json)
      : id = json['id'] as String,
        username = json['username'] as String,
        displayName = json['display_name'] as String,
        professionalId = json['professional_id'] as String,
        clearanceRank = json['clearance_rank'] as int,
        permissions = {...(json['permissions'] as List).cast<String>()},
        roles = [for (final r in json['roles'] as List) Map<String, dynamic>.from(r as Map)];

  final Map<String, dynamic> json;
  final String id;
  final String username;
  final String displayName;
  final String professionalId;
  final int clearanceRank;
  final Set<String> permissions;
  final List<Map<String, dynamic>> roles;

  bool can(String permission) => permissions.contains(permission);
  String roleLabel(String lang) => roles.map((r) => r[lang == 'fr' ? 'name_fr' : 'name_en']).join(', ');
}

class CaseSummary {
  CaseSummary(Map<String, dynamic> j)
      : id = j['id'] as String,
        reference = j['reference'] as String,
        title = j['title'] as String,
        category = j['category'] as String,
        priority = j['priority'] as String,
        status = j['status'] as String,
        classificationRank = j['classification_rank'] as int,
        reviewDate = DateTime.parse(j['review_date'] as String),
        updatedAt = _date(j['updated_at']);

  final String id;
  final String reference;
  final String title;
  final String category;
  final String priority;
  final String status;
  final int classificationRank;
  final DateTime reviewDate;
  final DateTime? updatedAt;
}

class CaseDetail extends CaseSummary {
  CaseDetail(super.j)
      : jurisdiction = j['jurisdiction'] as String,
        countryCode = j['country_code'] as String,
        executiveSummary = j['executive_summary'] as String,
        analysisContext = j['analysis_context'] as String,
        confidence = j['confidence_assessment'] as String,
        legalBasis = j['legal_basis'] as String,
        authorisedFollowUp = j['authorised_follow_up'] as String,
        offlineAllowed = j['offline_allowed'] as bool,
        version = j['version'] as int,
        raw = j;

  final String jurisdiction;
  final String countryCode;
  final String executiveSummary;
  final String analysisContext;
  final String confidence;
  final String legalBasis;
  final String authorisedFollowUp;
  final bool offlineAllowed;
  final int version;
  final Map<String, dynamic> raw;
}

class Statement {
  Statement(Map<String, dynamic> j)
      : id = j['id'] as String,
        kind = j['kind'] as String,
        text = j['text'] as String,
        credibility = j['credibility'] as int,
        sourceId = j['source_id'] as String?,
        verifiedBy = j['verified_by'] as String?,
        version = j['version'] as int,
        createdBy = j['created_by'] as String;

  final String id;
  final String kind;
  final String text;
  final int credibility;
  final String? sourceId;
  final String? verifiedBy;
  final int version;
  final String createdBy;
}

class SourceItem {
  SourceItem(Map<String, dynamic> j)
      : id = j['id'] as String,
        kind = j['kind'] as String,
        title = j['title'] as String,
        reliability = j['reliability'] as String,
        url = j['url'] as String?,
        publishedAt = _date(j['published_at']),
        collectedAt = _date(j['collected_at'])!;

  final String id;
  final String kind;
  final String title;
  final String reliability;
  final String? url;
  final DateTime? publishedAt;
  final DateTime collectedAt;
}

class EventItem {
  EventItem(Map<String, dynamic> j)
      : id = j['id'] as String,
        caseId = j['case_id'] as String,
        title = j['title'] as String,
        category = (j['category'] ?? 'other') as String,
        occurredAt = _date(j['occurred_at']),
        datePrecision = (j['date_precision'] ?? 'unknown') as String,
        locationLabel = j['location_label'] as String?,
        latitude = (j['latitude'] as num?)?.toDouble(),
        longitude = (j['longitude'] as num?)?.toDouble(),
        locationPrecision = (j['location_precision'] ?? 'unknown') as String,
        accuracyM = (j['location_accuracy_m'] as num?)?.toDouble();

  final String id;
  final String caseId;
  final String title;
  final String category;
  final DateTime? occurredAt;
  final String datePrecision;
  final String? locationLabel;
  final double? latitude;
  final double? longitude;
  final String locationPrecision;
  final double? accuracyM;
}

class AlertItem {
  AlertItem(Map<String, dynamic> j)
      : id = j['id'] as String,
        caseId = j['case_id'] as String?,
        kind = j['kind'] as String,
        title = j['title'] as String,
        detail = j['detail'] as String,
        severity = j['severity'] as String,
        status = j['status'] as String,
        origin = j['origin'] as String,
        notice = j['notice'] as String,
        createdAt = _date(j['created_at'])!;

  final String id;
  final String? caseId;
  final String kind;
  final String title;
  final String detail;
  final String severity;
  final String status;
  final String origin;
  final String notice;
  final DateTime createdAt;
}

class ReportItem {
  ReportItem(Map<String, dynamic> j)
      : id = j['id'] as String,
        caseId = j['case_id'] as String,
        reference = j['reference'] as String,
        reportType = j['report_type'] as String,
        title = j['title'] as String,
        summary = j['summary'] as String,
        analysis = j['analysis'] as String,
        uncertainties = j['uncertainties'] as String,
        recommendations = j['recommendations'] as String,
        status = j['status'] as String,
        authorId = j['author_id'] as String,
        sourceIds = (j['source_ids'] as List).cast<String>(),
        version = j['version'] as int;

  final String id;
  final String caseId;
  final String reference;
  final String reportType;
  final String title;
  final String summary;
  final String analysis;
  final String uncertainties;
  final String recommendations;
  final String status;
  final String authorId;
  final List<String> sourceIds;
  final int version;
}
