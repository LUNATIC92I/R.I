# Procédure de gestion des incidents de sécurité

## Gravité

| Niveau | Exemples | Délai de prise en charge |
|---|---|---|
| Critique | Fuite avérée de données classifiées, compromission d'un compte administrateur, clé maître exposée, chaîne d'audit invalide | Immédiat |
| Élevé | Appareil volé non déverrouillé, réutilisation de jeton détectée, refus d'accès répétés ciblant des dossiers | < 1 h |
| Moyen | Verrouillages de comptes en série, signal root/jailbreak, intégration SIEM indisponible | < 4 h |
| Faible | Connexion inhabituelle isolée | Jour ouvré |

## Étapes

1. **Détection** : alertes de sécurité (`/alerts`, origine `security`), SIEM, signalement d'un agent.
2. **Qualification** par l'officier de sécurité de permanence ; ouverture d'une fiche d'incident (heure, source, périmètre supposé).
3. **Confinement**, selon le cas :
   - appareil perdu/volé : `POST /admin/devices/{id}/revoke` (`lost`/`stolen`, `wipe: true`) — sessions et autorisations hors ligne révoquées immédiatement ;
   - compte compromis : `PATCH /admin/users/{id}` `is_active=false` (step-up), puis `POST /admin/users/{id}/revoke-sessions` ;
   - jeton réutilisé : la session est déjà révoquée automatiquement ; vérifier les autres sessions de l'agent ;
   - compte de service SIEM compromis : `POST /admin/service-accounts/{id}/disable`, puis nouvelle clé ;
   - suspicion sur une clé JWT : ajouter une nouvelle clé, basculer `AIC_JWT_ACTIVE_KID`, retirer l'ancienne (tous les jetons d'accès deviennent invalides) ;
   - suspicion sur la clé maître : incident critique, procédure HSM/KMS de rotation et rechiffrement des DEK.
4. **Préservation des preuves** : `GET /audit` (filtrer par acteur, période, catégorie), `python -m app.cli verify-audit`, copie des journaux du proxy et de PostgreSQL. Ne jamais modifier la base de production pendant l'analyse.
5. **Analyse** : périmètre des dossiers consultés (`case.view`, `document.download`, `report.export` dans l'audit), comparaison avec le besoin d'en connaître.
6. **Éradication et rétablissement** : correctifs, rotation des secrets, récupération de compte à deux personnes pour l'agent concerné.
7. **Notification** des autorités et personnes prévues par la loi et la politique de l'institution, dans les délais légaux.
8. **Retour d'expérience** sous 15 jours : causes, mesures, mise à jour de cette procédure et de [RESIDUAL_RISKS.md](RESIDUAL_RISKS.md).

## Perte ou vol d'un téléphone : fiche réflexe

1. L'agent déclare la perte depuis un autre appareil (menu Appareils) ou appelle la permanence.
2. La permanence révoque l'appareil (`stolen` en cas de vol) et vérifie dans l'audit l'activité récente de cet appareil.
3. Si l'appareil avait un paquet hors ligne : identifier les dossiers concernés (`sync.offline_package` dans l'audit) et informer leurs responsables.
4. Déclencher l'effacement par la solution MDM de l'institution si elle est déployée.
5. Réémettre un appareil ; l'agent se reconnecte et enrôle de nouveau son second facteur si nécessaire.
