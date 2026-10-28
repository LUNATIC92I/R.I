# Préparation à la production

Le dépôt fournit un **prototype fonctionnel**. Les éléments ci-dessous doivent être réalisés et validés avant toute utilisation avec des données réelles ou classifiées.

## Bloquants

- [ ] Revue de sécurité indépendante (code, architecture, cryptographie) et test d'intrusion API et mobile.
- [ ] Analyse d'impact relative à la protection des données et validation juridique (base légale des traitements, durées de conservation, droits des personnes, contrôle externe).
- [ ] Remplacement de `LocalKeyProvider` par un HSM ou KMS souverain ; procédure de cérémonie de clés et de rotation.
- [ ] Nomenclature de classification et règles de conservation définies par l'institution.
- [ ] IdP OIDC institutionnel avec authentification par clé physique ; tests d'intégration réels.
- [ ] Limitation de débit partagée (Redis) ou au proxy ; WAF.
- [ ] Épinglage de certificats sur mobile ; distribution par MDM ; Play Integrity / App Attest si exigé.
- [ ] Ancrage externe de la chaîne d'audit (export périodique de la tête de chaîne vers un stockage WORM ou le SIEM).
- [ ] Sauvegardes chiffrées testées (voir [BACKUP_RESTORE.md](BACKUP_RESTORE.md)) et plan de reprise.
- [ ] Procédure d'incident adoptée et exercée (voir [INCIDENT_RESPONSE.md](INCIDENT_RESPONSE.md)).
- [ ] Tests de charge, d'accessibilité et campagne sur parc d'appareils Android et iOS.
- [ ] Signature Android par clé de l'institution (`android/key.properties`, jamais versionné) ; compte Apple Developer de l'institution.

## Configuration production

| Variable | Valeur attendue |
|---|---|
| `AIC_ENV` | `production` |
| `AIC_DATABASE_URL` | rôle `aic_app`, `sslmode=verify-full` |
| `AIC_JWT_KEYS`, `AIC_JWT_ACTIVE_KID` | au moins 2 clés pour la rotation, via `*_FILE` |
| `AIC_MASTER_KEY_FILE` | fichier monté depuis le gestionnaire de secrets (en attendant le HSM) |
| `AIC_ACCESS_TTL` | ≤ 600 |
| `AIC_REFRESH_TTL` | durée d'une vacation (ex. 28800) |
| `AIC_OFFLINE_MAX_CLASSIFICATION_RANK` | plafond validé par la sécurité (souvent 0 ou 1) |
| `AIC_LLM_*` | vide sauf modèle hébergé dans l'infrastructure de l'institution |

## Rotation des clés JWT

Ajouter la nouvelle clé dans `AIC_JWT_KEYS`, redémarrer, basculer `AIC_JWT_ACTIVE_KID` après une durée ≥ `AIC_ACCESS_TTL`, puis retirer l'ancienne clé.

## Surveillance

Exporter les événements d'audit `authentication`, `access` (refus), `security` et `session` vers le SIEM ; alerter sur : pics de `auth.login` en échec, `case.access_denied` répétés, `document.integrity_failure`, `token_reuse`, résultat invalide de `verify-audit`.
