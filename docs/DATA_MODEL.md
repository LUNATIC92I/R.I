# Modèle de données

Schéma PostgreSQL créé par la migration Alembic `backend/migrations/versions/0001_initial_schema.py` (générée depuis `backend/app/models/`). Clés primaires UUID (sauf `audit_logs.seq`, séquentiel). Toutes les dates sont stockées en UTC (`timestamptz`).

## Entités

| Table | Rôle | Clés étrangères principales (règle de suppression) |
|---|---|---|
| `services` | Unités organisationnelles hiérarchiques | `parent_id → services` (RESTRICT) |
| `roles`, `permissions`, `role_permissions` | RBAC ; `roles.case_scope ∈ {none, membership, service}` | CASCADE sur la table d'association |
| `users`, `user_roles` | Agents : identifiant professionnel, habilitation, MFA, verrouillage | `service_id → services` (RESTRICT), `user_roles.role_id` (RESTRICT) |
| `devices` | Appareils enregistrés, statut `active/revoked/lost/stolen`, ordre d'effacement | `user_id → users` (CASCADE) ; unique (`user_id`, `install_id`) |
| `sessions` | Sessions serveur, HMAC du refresh token, fenêtre de step-up | `user_id` (CASCADE), `device_id` (CASCADE) |
| `mfa_challenges` | Tickets MFA à usage unique | CASCADE |
| `recovery_requests` | Récupération de compte à deux personnes | `requested_by`, `approved_by → users` (RESTRICT) |
| `service_accounts` | Identités machine (SIEM), clé hachée | `service_id` (RESTRICT) |
| `classification_levels` | Échelle de l'institution, `rank` unique, marquage | référencée par `cases`, `documents`, `reports`, `reference_sites` (RESTRICT) |
| `retention_rules` | Durée, base légale, action à l'échéance | référencée par `cases` (RESTRICT) |
| `cases` | Dossiers : métadonnées opérationnelles, base légale, révision, version (verrou optimiste) | `owner_id`, `service_id`, `classification_rank`, `retention_rule_id` (RESTRICT) |
| `case_members` | Besoin d'en connaître explicite, justification, échéance | `case_id` (CASCADE), `user_id` (CASCADE) |
| `case_links` | Relations documentées entre dossiers | CASCADE ; contrainte `from ≠ to` |
| `sources` | Provenance, fiabilité A à F, dates de publication et de collecte, référence protégée | `case_id` (CASCADE) |
| `statements` | Faits confirmés, informations non vérifiées, déclarations, hypothèses | `case_id` (CASCADE), `source_id` (SET NULL) ; **CHECK : un fait confirmé a une source et un vérificateur** |
| `documents` | Métadonnées documentaires | `case_id` (CASCADE) |
| `document_blobs` | Contenu chiffré par version (clé enveloppée, nonce, SHA-256) | `document_id` (CASCADE) ; unique (`document_id`, `version`) |
| `events` | Chronologie, précision de date et de localisation, provenance des coordonnées | `case_id` (CASCADE) ; CHECK coordonnées appariées et bornées |
| `entities`, `relations` | Graphe documenté (fondement, source, confiance, revendication causale) | CASCADE ; `relations.source_id` (SET NULL) |
| `threat_assessments` | Évaluations : faits, sources, fiabilité, crédibilité, hypothèses alternatives, incertitude | CASCADE ; **CHECK : menace confirmée ⇒ validateur** |
| `osint_items` | Sources ouvertes : dates distinctes, empreinte, points vérifiés/non vérifiés, versions | CASCADE |
| `indicators` | IOC : type, valeur normalisée, première/dernière observation, validité, verdict | CASCADE ; **CHECK : verdict malveillant ⇒ analyste + justification** |
| `security_events` | Événements SIEM reçus | `service_account_id` (RESTRICT) |
| `reports`, `validations`, `export_records` | Rapports, décisions des quatre yeux, traçabilité des exports | CASCADE |
| `alerts`, `notifications` | Signaux à vérifier ; notifications génériques | CASCADE |
| `offline_grants`, `sync_operations` | Autorisations hors ligne ; idempotence des opérations synchronisées | CASCADE |
| `reference_sites` | Infrastructures déclarées dans un référentiel autorisé | `classification_rank` (RESTRICT) |
| `audit_logs`, `audit_chain_head` | Journal chaîné append-only | aucune (le journal survit à la suppression des objets) |

## Index notables

`cases(service_id, status)`, `cases.review_date`, `cases.classification_rank`, `statements.case_id`, `events.occurred_at`, `indicators.value_hash`, `security_events.observable_hash`, `document_blobs.sha256`, `audit_logs(category, occurred_at)`, `audit_logs.action`.

## Suppression contrôlée

La suppression d'un dossier (`approve_deletion`) cascade sur tout son contenu mais **pas** sur le journal d'audit, qui conserve la référence, le demandeur, l'approbateur et la justification (sans contenu). La demande n'est possible que sur un dossier clos ou archivé ; l'approbation exige une autre personne et un step-up.

## Moindre privilège

`backend/deploy/sql/least_privilege.sql` : rôle `aic_migrator` (DDL, migrations), `aic_app` (DML sans UPDATE/DELETE sur l'audit), `aic_auditor_ro` (lecture de l'audit, aucun accès aux contenus chiffrés).
