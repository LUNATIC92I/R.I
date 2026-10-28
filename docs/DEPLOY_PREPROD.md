# Déploiement en préproduction

La préproduction reproduit la production (mêmes contrôles, mêmes versions) avec des **données synthétiques** uniquement. `AIC_ENV=preproduction` active les mêmes garde-fous que la production : PostgreSQL obligatoire, `sslmode` obligatoire, documentation OpenAPI désactivée, comptes de démonstration refusés.

## Topologie recommandée

- Reverse proxy institutionnel (TLS 1.2+/1.3, HSTS, limitation de débit, WAF) devant 2 instances API minimum.
- API sur un réseau interne non routé vers Internet ; sortie réseau limitée aux connecteurs autorisés (IdP, MISP, LLM institutionnel).
- PostgreSQL 16 dédié, chiffrement du volume, connexions TLS (`sslmode=verify-full`).
- Secrets injectés par le gestionnaire de secrets de l'orchestrateur sous forme de fichiers (`AIC_MASTER_KEY_FILE`, `AIC_JWT_KEYS_FILE`, etc.).
- Redis pour la limitation de débit partagée (à implémenter, voir RESIDUAL_RISKS R3) ; d'ici là, limiter au niveau du proxy.

## Étapes

1. Construire l'image : `docker build -t aic-backend:<version> backend/` (utilisateur non root, pas d'outils de compilation).
2. Créer la base et le rôle propriétaire, puis exécuter les migrations avec le rôle migrateur :
   ```bash
   AIC_MIGRATION_DATABASE_URL='postgresql+psycopg://aic_migrator:...@db:5432/aic?sslmode=verify-full' alembic upgrade head
   ```
3. Appliquer `backend/deploy/sql/least_privilege.sql` (adapter le nom de base) avec le rôle propriétaire.
4. Installer les référentiels : `python -m app.cli seed-reference`, puis remplacer la nomenclature d'exemple par celle de l'institution (`POST /admin/classifications`, `POST /admin/retention-rules`).
5. Créer les comptes par l'API d'administration (step-up requis) ; le premier administrateur technique est créé en présence de deux opérateurs avec `python -m app.cli bootstrap-admin --username ... --professional-id ... --service-code ... --service-name ... --operators OP1,OP2` (mot de passe saisi au clavier, commande refusée dès qu'un administrateur existe).
6. Configurer l'IdP OIDC (`AIC_OIDC_*`) et vérifier un parcours complet avec clé physique.
7. Configurer le SIEM : `POST /admin/service-accounts` (clé affichée une seule fois, stockée dans le coffre du SIEM).
8. Démarrer l'API avec `AIC_TRUSTED_PROXY_COUNT` égal au nombre de proxys.
9. Vérifier : `GET /api/v1/health`, `GET /api/v1/health/details` (rôle avec `system:health`), `python -m app.cli verify-audit`.
10. Compiler l'application mobile pointant vers l'URL de préproduction (voir [MOBILE_BUILD.md](MOBILE_BUILD.md)) et la distribuer via le canal interne (MDM, TestFlight interne).

## Recette

- Rejouer `pytest` contre la base de préproduction vide (base dédiée, jamais la base applicative).
- Exécuter le plan de test manuel : parcours de connexion, MFA, verrouillage, déclaration de perte, export avec step-up, isolation entre services.
- Test d'intrusion indépendant.
