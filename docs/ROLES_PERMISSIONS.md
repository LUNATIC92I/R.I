# Modèle des rôles et permissions / Roles and permissions

Source de vérité : `backend/app/authz/policy.py` (installé en base par `python -m app.cli seed-reference`).

## Rôles

| Code | Rôle | Portée sur les dossiers |
|---|---|---|
| `tech_admin` | Administrateur technique / Technical administrator | aucune (jamais de contenu opérationnel) |
| `director` | Directeur du renseignement / Intelligence director | dossiers de son service et des sous-services, plus ses affectations |
| `supervisor` | Superviseur opérationnel / Operational supervisor | dossiers de son service et des sous-services, plus ses affectations |
| `analyst` | Analyste du renseignement / Intelligence analyst | dossiers dont l'agent est membre ou propriétaire |
| `investigator` | Enquêteur habilité / Authorised investigator | dossiers dont l'agent est membre ou propriétaire |
| `auditor` | Auditeur de sécurité / Security auditor | aucune (jamais de contenu opérationnel) |
| `consultant` | Consultant en lecture seule / Read-only consultant | dossiers dont l'agent est membre ou propriétaire |

## Règle de décision (RBAC + ABAC)

Une action sur un dossier n'est autorisée que si **toutes** les conditions suivantes sont réunies, côté serveur :

1. le rôle porte la permission fonctionnelle (ex. `case:read`) ;
2. l'habilitation de l'agent (`clearance_rank`) est supérieure ou égale à la classification du dossier ;
3. l'agent a le besoin d'en connaître : propriétaire, membre explicite non expiré, ou rôle à portée `service` couvrant le service du dossier ;
4. l'état du dossier permet l'action (dossier clos, archivé ou en suppression : lecture seule).

Règles des quatre yeux : un fait n'est confirmé que par une personne autre que son auteur ; un rapport n'est validé que par une personne autre que son auteur ; une menace confirmée exige un validateur distinct ; la suppression d'un dossier exige un approbateur distinct du demandeur ; la récupération de compte exige deux personnes.

Réauthentification (step-up) exigée pour : export de rapport et téléchargement de document classifiés, archivage et suppression de dossier, confirmation de menace, création d'utilisateur, changement de rôle ou d'habilitation, approbation de récupération, création de compte de service, modification des référentiels.

## Matrice

| Permission | Description | `tech_admin` | `director` | `supervisor` | `analyst` | `investigator` | `auditor` | `consultant` |
|---|---|---|---|---|---|---|---|---|
| `case:create` | Create a case |  | ✔ | ✔ | ✔ |  |  |  |
| `case:read` | Read cases within need-to-know |  | ✔ | ✔ | ✔ | ✔ |  | ✔ |
| `case:update` | Edit case content |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `case:close` | Close or reopen a case |  | ✔ | ✔ |  |  |  |  |
| `case:archive` | Archive a closed case |  | ✔ | ✔ |  |  |  |  |
| `case:delete_request` | Request controlled deletion of a case |  | ✔ | ✔ |  |  |  |  |
| `case:delete_approve` | Approve controlled deletion of a case |  | ✔ |  |  |  |  |  |
| `case:manage_members` | Grant or revoke need-to-know on a case |  | ✔ | ✔ |  |  |  |  |
| `case:offline_authorize` | Authorise offline availability of a case |  | ✔ | ✔ |  |  |  |  |
| `statement:write` | Record statements, sources, events and entities |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `statement:verify` | Mark a statement as a confirmed fact |  | ✔ | ✔ | ✔ |  |  |  |
| `document:upload` | Attach documents |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `document:download` | Download documents |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `assessment:write` | Write threat assessments |  | ✔ | ✔ | ✔ |  |  |  |
| `assessment:confirm` | Confirm a threat assessment |  | ✔ | ✔ |  |  |  |  |
| `osint:write` | Record open-source items |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `cyber:write` | Manage indicators of compromise |  | ✔ | ✔ | ✔ |  |  |  |
| `cyber:verdict` | Issue a malicious verdict on an indicator |  | ✔ | ✔ | ✔ |  |  |  |
| `cyber:integrations_manage` | Configure SIEM and threat-intel integrations | ✔ |  |  |  |  |  |  |
| `report:write` | Draft reports |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `report:validate` | Validate or reject reports |  | ✔ | ✔ |  |  |  |  |
| `report:export` | Export approved reports |  | ✔ | ✔ |  |  |  |  |
| `alert:review` | Review alerts |  | ✔ | ✔ | ✔ |  |  |  |
| `assistant:use` | Use the analytical assistant |  | ✔ | ✔ | ✔ | ✔ |  |  |
| `search:use` | Use the authorised global search |  | ✔ | ✔ | ✔ | ✔ |  | ✔ |
| `dashboard:service` | See service-level statistics |  | ✔ | ✔ |  |  |  |  |
| `audit:read` | Read the audit trail |  |  |  |  |  | ✔ |  |
| `user:manage` | Manage user accounts | ✔ |  |  |  |  |  |  |
| `role:manage` | Assign roles | ✔ |  |  |  |  |  |  |
| `session:revoke_any` | Revoke any session | ✔ |  |  |  |  |  |  |
| `device:revoke_any` | Revoke any device | ✔ |  |  |  |  |  |  |
| `recovery:request` | Open an account recovery request | ✔ |  |  |  |  |  |  |
| `recovery:approve` | Approve an account recovery request |  | ✔ |  |  |  |  |  |
| `classification:manage` | Configure classification levels | ✔ |  |  |  |  |  |  |
| `retention:manage` | Configure retention rules | ✔ |  |  |  |  |  |  |
| `reference:manage` | Manage authorised geographic referentials | ✔ |  |  |  |  |  |  |
| `system:health` | See technical service status | ✔ | ✔ |  |  |  | ✔ |  |
