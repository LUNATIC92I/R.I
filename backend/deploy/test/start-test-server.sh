#!/bin/sh
# Starts a local AFRICAN INTELLIGENCE CORE test server with synthetic accounts.
# Requires Docker with the compose plugin. Secrets are generated here and stay in ./.env (never committed).
set -eu
cd "$(dirname "$0")"

if [ ! -f .env ]; then
  umask 077
  {
    echo "AIC_ENV=development"
    echo "AIC_TEST_DB_PASSWORD=$(openssl rand -hex 16)"
    echo "AIC_JWT_KEYS=test1:$(openssl rand -hex 32)"
    echo "AIC_JWT_ACTIVE_KID=test1"
    echo "AIC_MASTER_KEY=$(openssl rand -base64 32)"
    echo "AIC_DEMO_PASSWORD=Test-$(openssl rand -hex 6)-Aic!"
  } > .env
fi
set -a; . ./.env; set +a

docker compose -f docker-compose.test.yml up -d --build

echo "Waiting for the API..."
i=0
until curl -fsS http://127.0.0.1:8000/api/v1/health >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -gt 60 ] && { echo "API did not start: docker compose -f docker-compose.test.yml logs"; exit 1; }
  sleep 2
done

if command -v adb >/dev/null 2>&1; then
  adb reverse tcp:8000 tcp:8000 && echo "Phone connected: adb reverse tcp:8000 -> this computer"
else
  echo "adb not found: install Android platform-tools, then run: adb reverse tcp:8000 tcp:8000"
fi

echo
echo "Test server ready: http://127.0.0.1:8000/api/v1/health"
echo "Accounts: analyste.nord, superviseur.nord, directeur, enqueteur.nord, analyste.sud, admin.tech, auditeur, consultant"
echo "Shared password: $AIC_DEMO_PASSWORD"
echo "Stop: docker compose -f docker-compose.test.yml down   (add -v to erase the data)"
