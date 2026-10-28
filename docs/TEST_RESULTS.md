# Résultats des tests exécutés

Environnement : Linux, Python 3.13.17, PostgreSQL 16, Flutter 3.47.8 / Dart 3.13.7. Données exclusivement synthétiques. Date : 2026-10-28.

## Backend

| Commande | Résultat |
|---|---|
| `AIC_TEST_DATABASE_URL=postgresql+psycopg://… pytest` | **94 passed** (140 s), dont le test de migration Alembic (`upgrade head` + `alembic check`) |
| `pytest` (SQLite) | **93 passed, 1 skipped** (test de migration réservé à PostgreSQL) |
| `ruff check app tests` (règles F, E, W, B, S, I, UP) | All checks passed |
| `bandit -q -r app -ll` | aucun constat de sévérité moyenne ou haute |
| `pip-audit -r requirements.txt` | No known vulnerabilities found |

Couverture fonctionnelle des tests : authentification (MFA obligatoire, anti-rejeu TOTP, ticket à usage unique, verrouillage, rotation et réutilisation du refresh token, déconnexion immédiate, jetons falsifiés et `alg=none`, step-up, limitation de débit), isolation des dossiers et IDOR (13 routes, objets enfants, listes, recherche, tableau de bord, corrélation, carte), habilitations et appartenances expirées, privilèges administrateur, cycle de vie et suppression à quatre yeux, vérification des faits, documents chiffrés/versionnés/altérés, rapports (validation, export PDF/DOCX marqué, step-up), audit (chaîne valide, modification et suppression détectées, absence de secrets et de contenu), appareils perdus/volés, synchronisation hors ligne (autorisation, idempotence, conflit, refus), cyber (normalisation, verdicts, STIX, SIEM cloisonné), OSINT (doublons, versions), corrélation non causale, assistant, en-têtes de sécurité, injection SQL, erreurs génériques, notifications génériques, récupération de compte, configuration refusant les secrets absents ou faibles, absence de secrets versionnés.

## Vérifications manuelles exécutées

- Lancement de développement documenté : `alembic upgrade head`, `seed-demo`, `uvicorn`, `GET /health` = ok, connexion renvoyant un ticket MFA avec enrôlement, `verify-audit` valide.
- `deploy/sql/least_privilege.sql` appliqué sur PostgreSQL 16 : en tant que `aic_app`, INSERT d'audit accepté, UPDATE et DELETE refusés (`InsufficientPrivilege`) ; DELETE par le propriétaire refusé par le trigger (`audit_logs is append-only`) ; une suppression antérieure à l'installation du trigger est bien signalée par `verify-audit` (`sequence_gap`).
- `bootstrap-admin` : création du premier administrateur acceptée, seconde exécution refusée.

## Mobile

| Commande | Résultat |
|---|---|
| `flutter analyze` | No issues found |
| `flutter test` | **22 tests passed** (cache chiffré : chiffrement, expiration, altération, purge, chemin ; HTTPS obligatoire ; MFA, rafraîchissement, déconnexion et effacement sur échec, ordre d'effacement à distance, déverrouillage biométrique, verrouillage en arrière-plan ; file hors ligne ; widgets : FR/EN, parcours de connexion jusqu'au tableau de bord, masquage hors premier plan, écran de verrouillage, états d'erreur et vides) |
| `flutter build apk --release` | voir section ci-dessous |

### APK

`flutter build apk --release --dart-define=AIC_API_BASE_URL=https://api.aic.invalid/api/v1` : **réussi** (`app-release.apk`, 58,8 Mo, SHA-256 `9ecda484a7145ad841d66023874b9a45d0ec2e90a7f851d3ebd2adad8c9f435d`). Les premières tentatives avaient échoué sur `HTTP 429` de Maven Central ; la compilation a abouti en redirigeant, sur la machine de build uniquement, Maven Central vers le miroir Google (`maven-central.storage-download.googleapis.com`). L'APK est signé avec la **clé de debug** (pas de `key.properties`) : usage de test interne uniquement. Il pointe vers une URL volontairement non résoluble ; recompiler avec l'URL de préproduction. L'APK n'est pas versionné. Un Android App Bundle exige la clé de signature de l'institution et n'a pas été produit. Non installé sur un appareil physique.

## Non exécuté

Tests sur appareils Android/iOS physiques, compilation iOS (macOS requis), tests de charge, audit d'accessibilité avec lecteur d'écran, tests d'intégration OIDC/MISP/FCM/APNs réels, test d'intrusion.
