# Modèle de sécurité

> Aucune application n'est inviolable. Ce document décrit les contrôles implémentés, ceux qui restent à configurer et les risques résiduels. **Une revue de sécurité indépendante et un test d'intrusion sont obligatoires avant tout usage avec des données réelles ou classifiées.**

## 1. Hypothèses et périmètre

- Les utilisateurs sont des agents identifiés d'institutions légalement habilitées ; les menaces considérées incluent l'attaquant externe, l'agent curieux hors de son besoin d'en connaître, l'administrateur technique trop privilégié, le vol ou la perte d'un téléphone, la compromission d'un compte et la manipulation de sources ouvertes.
- L'application est un outil d'aide à l'analyse. Elle **ne contient aucune fonction** de surveillance clandestine, d'interception de communications, d'accès à des comptes privés, de contournement de protections techniques, d'usurpation d'identité ou de décision coercitive automatisée.

## 2. Authentification et sessions (`app/services/auth.py`)

| Contrôle | Implémentation |
|---|---|
| Mots de passe | Argon2id (t=3, m=64 Mio, p=2) ; politique ≥ 12 caractères et 3 classes ; hachage factice pour égaliser le temps de réponse d'un identifiant inconnu. |
| Message d'erreur | Réponse unique `invalid_credentials` (inconnu, mauvais mot de passe, verrouillé, désactivé). |
| Multifacteur | Obligatoire : le mot de passe seul ne délivre jamais de jeton. TOTP RFC 6238, fenêtre ±1 pas, **anti-rejeu** (un pas consommé ne peut être réutilisé). Ticket MFA à usage unique, 5 minutes, 5 essais. Secret TOTP chiffré en base (AES-GCM). |
| Clés physiques (FIDO2/WebAuthn) | Prises en charge via le fournisseur OIDC institutionnel : si le jeton porte `amr` ∈ {`hwk`, `fido`, `mfa`, `sc`, `otp`}, la session s'ouvre ; sinon le TOTP local est exigé. Un enrôlement WebAuthn natif dans l'API n'est **pas** implémenté. |
| OIDC | Vérification de signature via JWKS, `iss`, `aud`, `exp`, `nonce` (`app/connectors/oidc.py`). Non testé contre un IdP réel dans ce dépôt. |
| Verrouillage | Après `AIC_MAX_FAILED_LOGINS` échecs (mot de passe, MFA, step-up) : verrouillage `AIC_LOCKOUT_MINUTES`, alerte de sécurité. |
| Jetons d'accès | JWT HS256, 10 min, `kid` pour la rotation, `iss`/`aud`/`jti`/`sid`. Refus de `alg=none` et des `kid` inconnus. |
| Session serveur | Chaque requête vérifie en base que la session n'est pas révoquée ni expirée, que l'appareil est actif et le compte actif : **la révocation est immédiate**. |
| Refresh | Rotation à chaque usage ; seul un HMAC du jeton est stocké. **Détection de réutilisation** : présenter un ancien jeton révoque toute la session et lève une alerte. |
| Réauthentification | `POST /auth/step-up` (mot de passe + TOTP) ouvre une fenêtre de 5 min exigée pour exports, téléchargements classifiés, archivage/suppression, confirmations, gestion des privilèges. |
| Récupération | Demande par un administrateur après vérification d'identité (référence de procès-verbal), approbation par une **autre** personne habilitée avec step-up, code à usage unique 24 h remis en main propre, révocation de toutes les sessions, réenrôlement TOTP forcé. |
| Anomalies | Nouvel appareil ou nouvelle adresse réseau : alerte « à vérifier », jamais blocage automatique. |
| Limitation de débit | Par IP et par identifiant sur les routes d'authentification ; par utilisateur sur l'API. Implémentation mémoire (une instance) ; Redis requis en multi-instance. |

## 3. Autorisation (`app/authz/policy.py`)

RBAC + ABAC appliqués côté serveur (voir [ROLES_PERMISSIONS.md](ROLES_PERMISSIONS.md)) : permission fonctionnelle, habilitation ≥ classification, besoin d'en connaître (membre explicite à échéance, propriétaire, ou portée de service), état du dossier. L'administrateur technique et l'auditeur ont une portée `none` : ils ne lisent aucun dossier.

Protection IDOR : chaque objet enfant (énoncé, source, document, rapport, indicateur, entité) est rechargé et son `case_id` comparé au dossier autorisé ; un refus répond `404` identique à un identifiant inexistant. Les tests `tests/test_authz_isolation.py` le démontrent pour 13 routes.

## 4. Protection des données

- **Transport** : HTTPS obligatoire (l'application refuse `http://` hors développement local explicite) ; Android : `cleartextTrafficPermitted=false`, seules les autorités de certification système sont acceptées ; iOS : ATS sans exception. L'épinglage de certificat est préparé (`network_security_config.xml`) mais les empreintes dépendent du déploiement.
- **Au repos (serveur)** : documents chiffrés par enveloppe (DEK AES-256-GCM par version, données authentifiées associées = identifiant/version, KEK dérivée par HKDF du `AIC_MASTER_KEY` ou fournie par un HSM/KMS via l'interface `KeyProvider`). Empreinte SHA-256 vérifiée à chaque lecture ; altération détectée et auditée. Secrets TOTP et jetons push chiffrés champ par champ. **Le chiffrement applicatif ne remplace pas** le chiffrement des volumes, des sauvegardes et la segmentation réseau.
- **Au repos (mobile)** : jetons dans Keystore/Keychain (`unlocked_this_device`, non synchronisés) ; cache hors ligne AES-256-GCM avec expiration ; sauvegardes Android désactivées (`allowBackup=false`, règles d'extraction) ; fichiers dans l'espace privé de l'application, effacés à la déconnexion, à la révocation et sur ordre d'effacement.
- **Écran** : `FLAG_SECURE` (pas de capture, vignette vide), masquage du contenu dès que l'application quitte le premier plan (aperçu iOS des applications récentes), verrouillage biométrique après 2 min en arrière-plan.
- **Notifications** : textes génériques uniquement (« Nouvelle activité dans votre espace de travail ») ; aucun titre, nom, lieu ou identifiant ne transite par FCM/APNs.
- **Journaux** : le service d'audit retire les clés sensibles (`password`, `token`, `code`, `secret`, `content`…) ; la recherche n'enregistre que la longueur de la requête ; les erreurs 500 renvoient un identifiant de requête, jamais une trace. Les réponses portent `Cache-Control: no-store`.
- **Sources humaines** : jamais d'identité, uniquement une référence vers le registre protégé de l'institution.

## 5. Validation des entrées et protections applicatives

Pydantic avec `extra="forbid"`, longueurs bornées, énumérations ; ORM paramétré (injection SQL testée), échappement des jokers `LIKE`; contrôle du type réel des fichiers (nombres magiques) et taille maximale ; noms de fichiers assainis ; en-têtes HSTS, CSP `default-src 'none'`, `X-Frame-Options: DENY`, `nosniff`. Pas de cookies : CSRF non applicable (jetons Bearer). Pas de vue web dans l'application (pas de surface XSS côté mobile) ; les champs sont restitués comme texte brut.

## 6. Audit (`app/services/audit.py`)

Chaque entrée : horodatage UTC, acteur, catégorie, action, résultat, cible, IP, identifiant de requête et de session, détails expurgés, `prev_hash`, `entry_hash = SHA256(prev_hash || JSON canonique)`. Une ligne de tête verrouillée (`SELECT … FOR UPDATE`) sérialise la chaîne. `GET /audit/verify` détecte modification, suppression, trou de séquence et troncature (testé). En production : `deploy/sql/least_privilege.sql` retire UPDATE/DELETE au rôle applicatif et ajoute un trigger d'immuabilité ; exporter périodiquement la tête de chaîne vers un système externe (SIEM, stockage WORM) pour se prémunir d'une réécriture complète par un administrateur de base.

## 7. Appareils perdus ou volés

1. L'agent déclare l'appareil depuis un autre appareil (`/me/devices/{id}/report-lost`) ou un administrateur le révoque (`/admin/devices/{id}/revoke`).
2. Effet immédiat : statut `lost`/`stolen`, toutes les sessions liées révoquées, autorisations hors ligne révoquées, ordre d'effacement enregistré, connexion future refusée depuis cet identifiant d'installation.
3. Si l'appareil se reconnecte, il reçoit 401 ou `wipe_requested` et efface jetons, cache et clé de cache.
4. Données sur l'appareil volé hors ligne : chiffrées, expirantes, protégées par le verrou de l'OS et le Keystore ; la clé reste extractible par un attaquant disposant d'un appareil déverrouillé et rooté. D'où le plafond de classification hors ligne et la durée courte.

La détection root/jailbreak est **heuristique** (présence de fichiers connus), contournable, et seulement remontée comme signal. Pour un niveau supérieur : Play Integrity / App Attest et une solution MDM institutionnelle (effacement à distance natif).

## 8. Assistant analytique et confidentialité

Moteur local déterministe par défaut, sans appel réseau. Le connecteur `InstitutionalLlm` n'accepte qu'une URL HTTPS et refuse tout contenu classifié au-delà de `AIC_LLM_MAX_CLASSIFICATION_RANK` (0 par défaut). Aucune donnée n'est envoyée à un fournisseur externe ; une telle intégration exigerait autorisation explicite, validation juridique et garanties contractuelles et techniques.

## 9. Chaîne d'approvisionnement et qualité

Dépendances backend épinglées (`requirements.txt`), `pip-audit` (aucune vulnérabilité connue au moment des tests), `bandit` (aucun constat de sévérité moyenne ou haute), `ruff` (règles de sécurité S activées), `flutter analyze` sans constat. Le CI (`.github/workflows/ci.yml`) rejoue ces contrôles.

## 10. Risques résiduels et contrôles à valider

Voir [RESIDUAL_RISKS.md](RESIDUAL_RISKS.md).
