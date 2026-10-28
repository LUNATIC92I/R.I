# AFRICAN INTELLIGENCE CORE

Plateforme mobile sécurisée d'aide à l'analyse pour les services de renseignement intérieur **légalement habilités**. Elle centralise les informations autorisées, organise les dossiers, distingue faits, déclarations et hypothèses, relie les événements, produit des rapports validés et trace chaque accès.

> **Statut : prototype fonctionnel.** Le code est réel, testé et documenté, mais il n'a fait l'objet d'aucune revue de sécurité indépendante ni d'aucun test d'intrusion. **Ne pas l'utiliser avec des données réelles ou classifiées avant ces étapes** (voir [docs/PRODUCTION_READINESS.md](docs/PRODUCTION_READINESS.md)).

## Garde-fous intégrés

- Contrôle d'accès **côté serveur** : permission, habilitation ≥ classification, besoin d'en connaître, état du dossier. Un administrateur technique ne lit aucun dossier.
- **Aucune décision automatisée** : alertes, rapprochements et assistant sont étiquetés comme signaux à vérifier ; faits, menaces, verdicts malveillants, rapports et suppressions exigent une validation humaine, souvent par une autre personne que l'auteur.
- **Pas de fonction intrusive** : aucune collecte clandestine, interception, accès à des comptes privés, contournement de protection ni usurpation d'identité. L'OSINT se limite à l'enregistrement de ressources publiques.
- Base juridique obligatoire pour chaque dossier et chaque source ; identité des sources humaines jamais saisie.
- Proximité temporelle, géographique ou documentaire jamais présentée comme une causalité ; une adresse IP n'est jamais présentée comme la localisation d'une personne.
- Journal d'audit chaîné et vérifiable ; notifications génériques ; données mobiles minimales, chiffrées et expirantes.

## Contenu du dépôt

| Dossier | Contenu |
|---|---|
| [`backend/`](backend) | API FastAPI (Python 3.13), modèles SQLAlchemy, migrations Alembic, 94 tests |
| [`mobile/`](mobile) | Application Flutter Android/iOS, français et anglais, 22 tests |
| [`docs/`](docs) | Architecture, sécurité, données, API, guides d'installation, de déploiement et d'exploitation |
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | Lint, analyse statique, audit des dépendances, tests (PostgreSQL) |

## Démarrage rapide (développement, données fictives)

Prérequis : Python 3.12+, PostgreSQL 16, Flutter 3.47+. Détails : [docs/INSTALL_BACKEND.md](docs/INSTALL_BACKEND.md) et [docs/MOBILE_BUILD.md](docs/MOBILE_BUILD.md).

```bash
cd backend && pip install -r requirements-dev.txt
```

```bash
cp .env.example .env   # puis remplacer chaque valeur fictive par une valeur générée
```

```bash
set -a && . ./.env && set +a && alembic upgrade head && python -m app.cli seed-demo
```

```bash
uvicorn app.asgi:app --reload --port 8000
```

```bash
cd mobile && flutter run --dart-define=AIC_API_BASE_URL=http://10.0.2.2:8000/api/v1 --dart-define=AIC_DEV_ALLOW_HTTP=true
```

## Fonctionnalités : opérationnel, simulé, à configurer

| Domaine | État |
|---|---|
| Authentification mot de passe + TOTP obligatoire, enrôlement, anti-rejeu, verrouillage, step-up, sessions révocables, rotation des refresh tokens avec détection de réutilisation | **Opérationnel, testé** |
| Récupération de compte à deux personnes | **Opérationnel, testé** |
| RBAC + ABAC, 7 rôles, isolation des dossiers, anti-IDOR | **Opérationnel, testé** |
| Dossiers : création, consultation, filtres, versionnage optimiste, cycle de vie (révision, clôture, archivage, suppression à quatre yeux), membres à échéance, liens entre dossiers, historique | **Opérationnel, testé** |
| Sources, faits / informations non vérifiées / déclarations / hypothèses, vérification par une autre personne | **Opérationnel, testé** |
| Documents chiffrés (enveloppe AES-256-GCM), versions, contrôle de type, détection d'altération | **Opérationnel, testé** ; KEK locale (HSM/KMS **à brancher**) |
| Évaluations de menace (signal, anomalie, renseignement exploitable, menace confirmée) | **Opérationnel, testé** |
| OSINT : provenance, trois dates distinctes, empreinte, doublons, comparaison de versions, regroupement | **Opérationnel, testé** (saisie manuelle ; aucun robot de collecte, par choix) |
| Corrélation, chronologie, contradictions, lacunes, graphe des relations documentées, carte GeoJSON avec précision | **Opérationnel, testé** |
| Cyberrenseignement : IOC normalisés, fraîcheur, règles de verdict, import STIX 2.1 simple, ingestion SIEM par compte de service, alertes cloisonnées | **Opérationnel, testé** |
| Enrichissement MISP | Connecteur **implémenté, non testé** contre une instance réelle ; à configurer (`AIC_MISP_*`) |
| OIDC institutionnel (et clés physiques via l'IdP) | Connecteur **implémenté, non testé** contre un IdP réel ; à configurer (`AIC_OIDC_*`) |
| Rapports : préremplissage référencé, validation à quatre yeux liée à l'empreinte du contenu, export PDF/DOCX marqué, step-up, traçabilité | **Opérationnel, testé** |
| Assistant analytique local (résumé extractif, dates, contradictions, questions de vérification, lacunes, projet de note) | **Opérationnel, testé** ; modèle institutionnel optionnel **à configurer** (`AIC_LLM_*`) |
| Audit chaîné, vérification d'intégrité, rôle base de données append-only | **Opérationnel, testé** (y compris sur PostgreSQL avec le script de moindre privilège) |
| Hors ligne : paquets autorisés, chiffrés, expirants ; file d'opérations ; resynchronisation avec contrôle des droits et des versions | **Opérationnel, testé** (serveur et client) |
| Perte/vol d'appareil : déclaration, révocation immédiate, ordre d'effacement, purge locale | **Opérationnel, testé** |
| Notifications push | Texte générique **implémenté** ; envoi FCM/APNs **simulé** (journalisé) tant que les identifiants institutionnels ne sont pas fournis |
| Application mobile : 21 écrans, FR/EN, FLAG_SECURE, masquage en arrière-plan, biométrie locale | **Implémenté** ; `flutter analyze` sans constat, 22 tests ; non testé sur appareils physiques |
| WebAuthn natif dans l'API, limitation de débit multi-instance, épinglage de certificats, Play Integrity/App Attest | **Non implémenté** (voir [docs/RESIDUAL_RISKS.md](docs/RESIDUAL_RISKS.md)) |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) · [Modèle de sécurité](docs/SECURITY.md) · [Risques résiduels](docs/RESIDUAL_RISKS.md)
- [Modèle de données](docs/DATA_MODEL.md) · [Rôles et permissions](docs/ROLES_PERMISSIONS.md) · [API](docs/API.md) ([OpenAPI](docs/openapi.json))
- [Installation et développement](docs/INSTALL_BACKEND.md) · [Préproduction](docs/DEPLOY_PREPROD.md) · [Préparation à la production](docs/PRODUCTION_READINESS.md)
- [Sauvegarde et restauration](docs/BACKUP_RESTORE.md) · [Incidents de sécurité](docs/INCIDENT_RESPONSE.md)
- [Compilation Android et préparation iOS](docs/MOBILE_BUILD.md) · [Résultats des tests](docs/TEST_RESULTS.md)
