# Sauvegarde et restauration

## Ce qu'il faut sauvegarder

| Élément | Méthode | Remarques |
|---|---|---|
| Base PostgreSQL | `pg_basebackup` + archivage WAL (PITR), ou `pg_dump -Fc` quotidien | Contient les documents chiffrés : la sauvegarde seule ne permet pas de les lire. |
| Clés (KEK/master key, clés JWT) | Coffre/HSM de l'institution, **séparément** de la base | Sans la clé maître, les documents sont irrécupérables. Deux dépositaires minimum. |
| Tête de la chaîne d'audit | Export quotidien de `audit_chain_head` (seq, hash) vers un stockage WORM | Permet de prouver qu'une restauration n'a pas réécrit l'historique. |
| Configuration | Dépôt de configuration de l'orchestrateur (sans secrets) | |

Les sauvegardes sont chiffrées (par exemple `pg_dump | age -r <clé publique>` ou chiffrement natif de l'outil de sauvegarde), stockées hors site sur une infrastructure souveraine, avec une durée de conservation conforme aux règles de l'institution.

## Exemple (dump logique)

```bash
pg_dump -Fc -d "$AIC_MIGRATION_DATABASE_URL" -f aic-$(date -u +%Y%m%dT%H%MZ).dump
```

```bash
psql "$AIC_MIGRATION_DATABASE_URL" -Atc "SELECT last_seq, last_hash FROM audit_chain_head" > audit-head-$(date -u +%Y%m%d).txt
```

## Restauration

1. Isoler l'environnement cible (pas d'accès utilisateur pendant l'opération).
2. Restaurer dans une base vide : `pg_restore -d <cible> --no-owner --role=aic_migrator aic-<date>.dump`.
3. Rejouer `alembic upgrade head` si la sauvegarde précède une migration.
4. Réappliquer `deploy/sql/least_privilege.sql`.
5. Injecter les **mêmes** clés (master key, clés JWT) que lors de la sauvegarde.
6. Vérifier l'intégrité : `python -m app.cli verify-audit`, puis comparer `audit_chain_head` à l'export WORM correspondant.
7. Révoquer toutes les sessions (une restauration peut réactiver des sessions révoquées après la sauvegarde) :
   ```sql
   UPDATE sessions SET revoked_at = now(), revoked_reason = 'restore' WHERE revoked_at IS NULL;
   ```
8. Rejouer manuellement les révocations d'appareils et de comptes intervenues après la date de sauvegarde (à partir du SIEM).
9. Consigner l'opération (procès-verbal signé par deux personnes).

## Test

Une restauration complète doit être testée au moins chaque trimestre en préproduction, avec mesure du temps de reprise. Cette procédure n'a pas été exécutée dans le cadre du développement du prototype.
