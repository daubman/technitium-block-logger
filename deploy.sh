#!/usr/bin/env bash
# Build Block Logger and deploy it to a Technitium DNS node over SSH.
#
# Usage:
#   ./deploy.sh <host> <container-name>
#
# Example:
#   ./deploy.sh dns1.example.com technitium
#
# The host needs passwordless SSH and sudo. The app folder lives inside the
# technitium-config docker volume; override APP_DIR if yours differs. The
# container is restarted because .NET cannot unload the loaded assembly.
set -euo pipefail

HOST="${1:?usage: deploy.sh <host> <container-name>}"
CONTAINER="${2:?usage: deploy.sh <host> <container-name>}"
APP_DIR="${APP_DIR:-/var/lib/docker/volumes/technitium_technitium-config/_data/apps/Block Logger}"
APP_NAME="Block Logger"

cd "$(dirname "$0")"
echo "==> building"
docker build -f Dockerfile.build -o out .

echo "==> packaging"
ZIP="$(mktemp -t blocklogger)" && rm "$ZIP"
(cd out && zip -qr "$ZIP" .)

echo "==> staging on ${HOST}"
scp -q "$ZIP" "${HOST}:/tmp/blocklogger-deploy.zip"
ssh "$HOST" "sudo sh -c '
    cd \"${APP_DIR}\" || exit 1
    cp BlockLogger.dll \"BlockLogger.dll.bak-\$(date +%Y%m%d-%H%M%S)\" 2>/dev/null || true
    python3 -m zipfile -e /tmp/blocklogger-deploy.zip .
    rm /tmp/blocklogger-deploy.zip'"
rm "$ZIP"

echo "==> restarting ${CONTAINER} on ${HOST}"
ssh "$HOST" "sudo docker restart ${CONTAINER} >/dev/null && sleep 12 &&
    sudo docker ps --filter name=${CONTAINER} --format '{{.Status}}' &&
    sudo sh -c 'grep -l . /var/lib/docker/volumes/technitium_technitium-logs/_data/*.log | xargs grep -h \"${APP_NAME}\" 2>/dev/null | tail -5'"

echo "==> done; verify a blocked query gets a [group=..., list=...] marker in the query log"
