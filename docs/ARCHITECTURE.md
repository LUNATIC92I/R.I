# Architecture

AFRICAN INTELLIGENCE CORE est un poste de travail numérique pour les analystes du renseignement intérieur d'institutions légalement habilitées. Ce document décrit l'architecture, les choix techniques et leur justification.

## Vue d'ensemble

```
┌──────────────────────────┐        HTTPS (TLS 1.2+)         ┌──────────────────────────────┐
│ Application Flutter      │  ─────────────────────────────▶ │ Reverse proxy institutionnel │
│ Android / iOS            │   Bearer JWT (10 min)           │ TLS, mTLS optionnel, WAF      │
│ - Keystore/Keychain      │   refresh token rotatif         └──────────────┬───────────────┘
│ - cache chiffré AES-GCM  │                                                │ réseau interne
│ - FLAG_SECURE, masquage  │                                 ┌──────────────▼───────────────┐
└──────────────────────────┘                                 │ API FastAPI (Python 3.13)     │
                                                             │ - authN : mot de passe+TOTP,  │
┌──────────────────────────┐   X-API-Key (compte service)    │   OIDC, step-up, sessions     │
│ SIEM institutionnel      │ ─────────────────────────────▶  │ - authZ : RBAC + ABAC         │
└──────────────────────────┘                                 │ - services métier             │
                                                             │ - audit chaîné (SHA-256)      │
┌──────────────────────────┐   OIDC (JWKS)                   │ - chiffrement d'enveloppe     │
│ Fournisseur d'identité   │ ◀────────────────────────────── │ - connecteurs (MISP, LLM)     │
└──────────────────────────┘                                 └──────────────┬───────────────┘
                                                                            │ TLS (sslmode)
                                                             ┌──────────────▼───────────────┐
                                                             │ PostgreSQL 16                 │
                                                             │ rôles aic_app / aic_migrator  │
                                                             │ audit_logs append-only        │
                                                             └──────────────────────────────┘
```

Trois environnements distincts (`AIC_ENV`) : `development`, `preproduction`, `production` (plus `test` pour la suite automatisée). Hors développement, l'application refuse de démarrer sans PostgreSQL, sans `sslmode` sur la connexion de base de données ou avec des secrets trop faibles (`app/core/config.py`).

## Technologies retenues

| Domaine | Choix | Raison |
|---|---|---|
| Mobile | Flutter 3.47 / Dart 3.13 | Base commune Android/iOS, rendu maîtrisé, accès natif simple (FLAG_SECURE). |
| Stockage sécurisé mobile | `flutter_secure_storage` (Keystore / Keychain `unlocked_this_device`) | Secrets jamais en préférences ni en fichiers ; non sauvegardés. |
| Biométrie | `local_auth` | Déverrouillage local uniquement ; aucune donnée biométrique ne sort de l'OS. |
| Cache hors ligne | `cryptography` AES-256-GCM, clé dans le Keystore | Données limitées dans le temps et authentifiées (intégrité). |
| Cartographie | `flutter_map` + serveur de tuiles institutionnel configurable | Aucun fournisseur tiers par défaut : pas de fuite des zones consultées. |
| Backend | Python 3.13, FastAPI, Pydantic v2 | Validation stricte des entrées (`extra="forbid"`), typage, écosystème crypto mûr. |
| ORM / migrations | SQLAlchemy 2.1, Alembic | Requêtes paramétrées (pas d'injection SQL), migrations versionnées. |
| Base | PostgreSQL 16 | Contraintes d'intégrité, rôles, triggers d'immuabilité de l'audit. |
| Hachage mots de passe | Argon2id (`argon2-cffi`) | Résistant aux attaques GPU. |
| Jetons | JWT HS256 avec `kid` (rotation), session serveur | Révocation immédiate : chaque requête vérifie la session et l'appareil en base. |
| MFA | TOTP RFC 6238 (`pyotp`), anti-rejeu par pas de temps | Fonctionne hors réseau téléphonique ; clés FIDO2 via l'IdP OIDC. |
| Chiffrement documents | Enveloppe : DEK AES-256-GCM par version, KEK via `KeyProvider` | Permet HSM/KMS en production, rotation des KEK. |
| Rapports | ReportLab (PDF), python-docx (DOCX) | Marquages de classification en en-tête et pied de page. |

## Arborescence

```
backend/
  app/
    core/        config, sécurité (Argon2, JWT, TOTP), crypto d'enveloppe, rate limiting, erreurs
    db/          base déclarative, sessions
    models/      identity.py (utilisateurs, rôles, appareils, sessions), intel.py (dossiers, sources,
                 énoncés, événements, documents, évaluations, OSINT), ops.py (IOC, rapports, alertes,
                 notifications, synchronisation, audit)
    authz/       policy.py : catalogue des permissions, rôles, décision RBAC+ABAC, filtre SQL
    services/    auth, cases, osint, cyber, correlation, reports, assistant, audit, notifications
    connectors/  oidc, threat_intel (MISP), push (FCM/APNs à brancher)
    api/         deps.py (authentification, permissions, step-up, chargement ABAC), routers/*
    schemas/     modèles Pydantic d'entrée/sortie
    seed.py, cli.py
  migrations/    Alembic (0001_initial_schema)
  deploy/sql/    least_privilege.sql
  tests/         94 tests (PostgreSQL et SQLite)
mobile/
  lib/
    core/        config, thème, API client, auth controller, stockage sécurisé, privacy guard, offline
    features/    auth, home (tableau de bord, alertes, notifications), cases, analysis (OSINT, cyber,
                 chronologie, carte, graphe, rapports), profile (sessions, appareils, sécurité), admin
    widgets/     états communs (chargement, vide, erreur), graphiques, marquage de classification
    l10n/        app_fr.arb, app_en.arb (ajout d'une langue = un fichier ARB)
  test/          22 tests (unitaires et widgets)
docs/            présente documentation
```

## Décisions d'architecture (résumé)

1. **Le contrôle d'accès est exclusivement serveur.** L'application masque les actions non permises pour l'ergonomie seulement ; chaque route résout le dossier via `load_case()` qui applique la décision ABAC et répond `404` en cas de refus (aucun oracle d'existence).
2. **Agrégats filtrés en SQL.** Listes, recherche, tableau de bord, corrélations et carte utilisent `accessible_case_filter()`, si bien qu'aucune statistique n'inclut un dossier hors du besoin d'en connaître. La corrélation ne franchit jamais ce périmètre.
3. **Statut épistémique explicite.** `statements.kind` distingue fait confirmé, information non vérifiée, déclaration, hypothèse de travail, hypothèse alternative. Une contrainte SQL impose qu'un fait confirmé ait une source et un vérificateur ; l'API impose que le vérificateur ne soit pas l'auteur.
4. **Séparation métadonnées/contenu.** `documents` (métadonnées) et `document_blobs` (contenu chiffré, clé enveloppée, nonce, empreinte) sont séparés ; le rôle d'audit externe n'a aucun droit sur les blobs.
5. **Audit inviolable par conception, vérifiable par calcul.** Chaîne de hachage SHA-256, verrou de tête de chaîne, rôle applicatif sans UPDATE/DELETE, trigger d'immuabilité.
6. **Aucune décision automatisée.** Alertes, corrélations et assistant produisent des signaux étiquetés comme tels ; toute confirmation (fait, menace, verdict malveillant, rapport, suppression) exige une personne habilitée, souvent distincte de l'auteur.
7. **Assistant local par défaut.** Le moteur analytique est déterministe et local ; un modèle institutionnel peut être branché mais il est refusé au-delà d'un niveau de classification configuré.
8. **Hors ligne sur autorisation explicite.** Pas de téléchargement automatique : un superviseur autorise le dossier, la classification doit être sous le plafond configuré, le paquet expire, les documents ne sont jamais inclus, la révocation de l'appareil révoque les autorisations.

## Personnalisation institutionnelle

- Nom affiché, code pays et couleur d'accent : `--dart-define=AIC_INSTITUTION=... AIC_COUNTRY=.. AIC_ACCENT=RRGGBB` (mobile) et `AIC_INSTITUTION_NAME`, `AIC_COUNTRY_CODE` (backend).
- Niveaux de classification : table `classification_levels`, configurable par l'institution ; la nomenclature fournie par `seed-reference` n'est qu'un exemple.
- Règles de conservation : table `retention_rules` avec base légale explicite.
- Langues : ajouter `lib/l10n/app_<code>.arb` (par exemple `app_sw.arb`, `app_ha.arb`, `app_wo.arb`) puis `flutter gen-l10n`.
