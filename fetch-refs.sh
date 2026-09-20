#!/usr/bin/env bash
# Fetch the Technitium reference assemblies this app compiles against from the
# official docker image into ./lib (gitignored, populated per Technitium version).
#
# Usage: ./fetch-refs.sh [technitium-version]   (default: 15.5.0)
set -euo pipefail

VERSION="${1:-15.5.0}"
IMAGE="technitium/dns-server:${VERSION}"
LIBDIR="$(cd "$(dirname "$0")" && pwd)/lib"
mkdir -p "$LIBDIR"

CID="$(docker create "$IMAGE")"
trap 'docker rm "$CID" >/dev/null 2>&1 || true' EXIT
for dll in DnsServerCore.ApplicationCommon.dll TechnitiumLibrary.Net.dll TechnitiumLibrary.dll; do
    docker cp "${CID}:/opt/technitium/dns/${dll}" "$LIBDIR/"
done
echo "reference assemblies for ${IMAGE} written to ${LIBDIR}"
