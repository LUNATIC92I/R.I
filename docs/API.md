# Référence de l'API / API reference

Généré depuis le code (`app.openapi()`). Base : `/api/v1`. Spécification complète : [`openapi.json`](openapi.json).
Toutes les routes, sauf `/health`, `/auth/login`, `/auth/oidc`, `/auth/mfa`, `/auth/refresh`, `/auth/recovery/complete` et `/integrations/siem/events` (clé de compte de service), exigent `Authorization: Bearer <access_token>`.
Les refus d'accès à un dossier hors du besoin d'en connaître répondent `404 not_found` (même réponse qu'un identifiant inexistant).

Codes d'erreur : corps JSON `{"code": "...", "message": "..."}`. Codes fréquents : `invalid_credentials`, `step_up_required`, `missing_permission`, `not_found`, `version_conflict`, `case_read_only`, `four_eyes_required`, `rate_limited`, `validation_error`.

## auth

| Méthode | Chemin | Opération |
|---|---|---|
| POST | `/api/v1/auth/login` | Login |
| POST | `/api/v1/auth/logout` | Logout |
| POST | `/api/v1/auth/mfa` | Mfa |
| POST | `/api/v1/auth/oidc` | Oidc Login |
| POST | `/api/v1/auth/recovery/complete` | Recovery Complete |
| POST | `/api/v1/auth/refresh` | Refresh |
| POST | `/api/v1/auth/step-up` | Step Up |

## me

| Méthode | Chemin | Opération |
|---|---|---|
| GET | `/api/v1/me` | Get Me |
| GET | `/api/v1/me/devices` | My Devices |
| POST | `/api/v1/me/devices/current/push-token` | Register Push |
| GET | `/api/v1/me/devices/current/status` | Current Device Status |
| POST | `/api/v1/me/devices/{device_id}/report-lost` | Report Lost |
| PATCH | `/api/v1/me/locale` | Set Locale |
| GET | `/api/v1/me/notifications` | Notifications |
| POST | `/api/v1/me/notifications/{notification_id}/read` | Mark Read |
| GET | `/api/v1/me/sessions` | My Sessions |
| DELETE | `/api/v1/me/sessions/{session_id}` | Revoke My Session |

## cases

| Méthode | Chemin | Opération |
|---|---|---|
| GET | `/api/v1/cases` | List Cases |
| POST | `/api/v1/cases` | Create Case |
| GET | `/api/v1/cases/{case_id}` | Get Case |
| PATCH | `/api/v1/cases/{case_id}` | Update Case |
| GET | `/api/v1/cases/{case_id}/assessments` | List Assessments |
| POST | `/api/v1/cases/{case_id}/assessments` | Add Assessment |
| POST | `/api/v1/cases/{case_id}/assessments/{assessment_id}/confirm` | Confirm Assessment |
| GET | `/api/v1/cases/{case_id}/documents` | List Documents |
| POST | `/api/v1/cases/{case_id}/documents` | Upload Document |
| GET | `/api/v1/cases/{case_id}/documents/{document_id}/content` | Download Document |
| GET | `/api/v1/cases/{case_id}/documents/{document_id}/versions` | Document Versions |
| GET | `/api/v1/cases/{case_id}/entities` | List Entities |
| POST | `/api/v1/cases/{case_id}/entities` | Add Entity |
| GET | `/api/v1/cases/{case_id}/events` | List Events |
| POST | `/api/v1/cases/{case_id}/events` | Add Event |
| GET | `/api/v1/cases/{case_id}/export-check` | Export Check |
| GET | `/api/v1/cases/{case_id}/history` | Case History |
| GET | `/api/v1/cases/{case_id}/links` | List Links |
| POST | `/api/v1/cases/{case_id}/links` | Add Link |
| GET | `/api/v1/cases/{case_id}/members` | List Members |
| POST | `/api/v1/cases/{case_id}/members` | Add Member |
| DELETE | `/api/v1/cases/{case_id}/members/{user_id}` | Remove Member |
| POST | `/api/v1/cases/{case_id}/offline` | Set Offline |
| GET | `/api/v1/cases/{case_id}/relations` | List Relations |
| POST | `/api/v1/cases/{case_id}/relations` | Add Relation |
| GET | `/api/v1/cases/{case_id}/sources` | List Sources |
| POST | `/api/v1/cases/{case_id}/sources` | Add Source |
| GET | `/api/v1/cases/{case_id}/statements` | List Statements |
| POST | `/api/v1/cases/{case_id}/statements` | Add Statement |
| POST | `/api/v1/cases/{case_id}/statements/{statement_id}/verify` | Verify Statement |
| POST | `/api/v1/cases/{case_id}/status` | Change Status |

## analysis

| Méthode | Chemin | Opération |
|---|---|---|
| GET | `/api/v1/analysis/correlations` | Correlations |
| GET | `/api/v1/analysis/map` | Geo Map |
| GET | `/api/v1/analysis/timeline` | Timeline |
| POST | `/api/v1/cases/{case_id}/assistant` | Run Assistant |
| GET | `/api/v1/cases/{case_id}/gaps` | Case Gaps |
| GET | `/api/v1/cases/{case_id}/graph` | Case Graph |
| GET | `/api/v1/cases/{case_id}/indicator-graph` | Indicator Graph |
| GET | `/api/v1/cases/{case_id}/indicators` | List Indicators |
| POST | `/api/v1/cases/{case_id}/indicators` | Add Indicator |
| POST | `/api/v1/cases/{case_id}/indicators/import-stix` | Import Stix |
| POST | `/api/v1/cases/{case_id}/indicators/{indicator_id}/enrich` | Indicator Enrich |
| POST | `/api/v1/cases/{case_id}/indicators/{indicator_id}/verdict` | Indicator Verdict |
| GET | `/api/v1/cases/{case_id}/osint` | List Osint |
| POST | `/api/v1/cases/{case_id}/osint` | Add Osint |
| GET | `/api/v1/cases/{case_id}/osint-clusters` | Osint Clusters |
| GET | `/api/v1/cases/{case_id}/osint/{item_id}/compare/{other_id}` | Compare Osint |
| GET | `/api/v1/cases/{case_id}/reports` | List Reports |
| POST | `/api/v1/cases/{case_id}/reports` | Create Report |
| GET | `/api/v1/cases/{case_id}/reports/{report_id}` | Get Report |
| PATCH | `/api/v1/cases/{case_id}/reports/{report_id}` | Update Report |
| POST | `/api/v1/cases/{case_id}/reports/{report_id}/decision` | Decide Report |
| GET | `/api/v1/cases/{case_id}/reports/{report_id}/export` | Export Report |
| POST | `/api/v1/cases/{case_id}/reports/{report_id}/submit` | Submit Report |
| GET | `/api/v1/cyber/campaigns` | Campaigns |
| GET | `/api/v1/reports/pending-validation` | Pending Validation |

## operations

| Méthode | Chemin | Opération |
|---|---|---|
| GET | `/api/v1/alerts` | List Alerts |
| POST | `/api/v1/alerts/{alert_id}/review` | Review Alert |
| GET | `/api/v1/dashboard` | Dashboard |
| GET | `/api/v1/health` | Health |
| GET | `/api/v1/health/details` | Health Details |
| POST | `/api/v1/integrations/siem/events` | Siem Events |
| GET | `/api/v1/search` | Search |
| GET | `/api/v1/sync/grants` | Active Grants |
| POST | `/api/v1/sync/offline-package/{case_id}` | Offline Package |
| POST | `/api/v1/sync/push` | Sync Push |

## admin

| Méthode | Chemin | Opération |
|---|---|---|
| GET | `/api/v1/admin/classifications` | List Classifications |
| POST | `/api/v1/admin/classifications` | Create Classification |
| GET | `/api/v1/admin/devices` | List Devices |
| POST | `/api/v1/admin/devices/{device_id}/revoke` | Revoke Device |
| GET | `/api/v1/admin/directory` | Directory |
| GET | `/api/v1/admin/permissions` | List Permissions |
| GET | `/api/v1/admin/recovery` | List Recovery |
| POST | `/api/v1/admin/recovery` | Request Recovery |
| POST | `/api/v1/admin/recovery/{request_id}/approve` | Approve Recovery |
| POST | `/api/v1/admin/reference-sites` | Add Site |
| GET | `/api/v1/admin/retention-rules` | List Retention |
| POST | `/api/v1/admin/retention-rules` | Create Retention |
| GET | `/api/v1/admin/roles` | List Roles |
| POST | `/api/v1/admin/service-accounts` | Create Service Account |
| POST | `/api/v1/admin/service-accounts/{account_id}/disable` | Disable Service Account |
| GET | `/api/v1/admin/services` | List Services |
| GET | `/api/v1/admin/users` | List Users |
| POST | `/api/v1/admin/users` | Create User |
| PATCH | `/api/v1/admin/users/{user_id}` | Update User |
| POST | `/api/v1/admin/users/{user_id}/revoke-sessions` | Revoke User Sessions |
| GET | `/api/v1/admin/users/{user_id}/sessions` | User Sessions |
| POST | `/api/v1/admin/users/{user_id}/unlock` | Unlock User |

## audit

| Méthode | Chemin | Opération |
|---|---|---|
| GET | `/api/v1/audit` | Read Audit |
| GET | `/api/v1/audit/verify` | Verify Audit |
