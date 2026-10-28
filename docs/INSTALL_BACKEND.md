# Installation du backend et lancement en développement

Toutes les données de développement sont **synthétiques**. Ne jamais charger de données réelles dans un environnement de développement.

## Prérequis

- Python 3.12 ou plus récent (testé avec 3.13.17)
- PostgreSQL 16 (testé avec 16) ; SQLite n'est accepté qu'en `development`/`test`
- Aucun service externe n'est requis : OIDC, MISP, LLM et push sont désactivés si non configurés

## 1. Dépendances

```bash
cd backend
```

```bash
python3 -m venv .venv && . .venv/bin/activate
```

```bash
pip install -r requirements-dev.txt
```

## 2. Base de données

```bash
sudo -u postgres psql -c "CREATE ROLE aic_dev LOGIN PASSWORD 'choisir-un-mot-de-passe-local';" -c "CREATE DATABASE aic_dev OWNER aic_dev;"
```

## 3. Configuration

Copiez `backend/.env.example` vers `backend/.env` (jamais versionné) puis générez de vraies valeurs :

```bash
python -c "import secrets;print('AIC_JWT_KEYS=dev1:'+secrets.token_urlsafe(48))"
```

```bash
python -c "import os,base64;print('AIC_MASTER_KEY='+base64.b64encode(os.urandom(32)).decode())"
```

Renseignez `AIC_DATABASE_URL=postgresql+psycopg://aic_dev:<mot de passe>@localhost/aic_dev` et `AIC_ENV=development`, puis chargez le fichier :

```bash
set -a && . ./.env && set +a
```

## 4. Schéma, référentiels et comptes fictifs

```bash
alembic upgrade head
```

```bash
python -m app.cli seed-demo --password 'Mot-De-Passe-Dev-Long-2026!'
```

Comptes créés (tous fictifs) : `admin.tech`, `directeur`, `superviseur.nord`, `analyste.nord`, `enqueteur.nord`, `analyste.sud`, `auditeur`, `consultant`. À la première connexion, chaque compte enrôle son TOTP (la clé est renvoyée une seule fois, à saisir dans une application d'authentification).

## 5. Lancement

```bash
uvicorn app.asgi:app --reload --port 8000
```

- Santé : `GET http://localhost:8000/api/v1/health`
- Documentation interactive (désactivée hors développement) : `http://localhost:8000/docs`

Pour l'application mobile sur émulateur Android, utilisez `http://10.0.2.2:8000/api/v1` avec `--dart-define=AIC_DEV_ALLOW_HTTP=true` (accepté uniquement pour les adresses de bouclage et seulement en build debug).

## 6. Tests et contrôles qualité

```bash
AIC_TEST_DATABASE_URL=postgresql+psycopg://aic_dev:<mot de passe>@localhost/aic_test pytest
```

Sans `AIC_TEST_DATABASE_URL`, la suite utilise SQLite (le test de migration Alembic est alors ignoré). **La base de test est intégralement effacée à chaque test.**

```bash
ruff check app tests && bandit -q -r app -ll && pip-audit -r requirements.txt
```

## 7. Commandes utiles

```bash
python -m app.cli verify-audit
```

```bash
python -m app.cli seed-reference
```
