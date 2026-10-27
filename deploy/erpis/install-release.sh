#!/bin/sh
# Usage: install-release.sh <tag> <sha256 of SHA256SUMS>
# Downloads the release binaries, verifies them and builds the local image
# erpis-rustdesk-server:<tag>. Changes nothing that is running.
set -eu
TAG="$1"; SUMS_SHA="$2"
REPO="github-eg-g/erpis-rustdesk-server"
DIR="/opt/erpis-rustdesk/$TAG"
mkdir -p "$DIR" && cd "$DIR"
for f in hbbs hbbr Dockerfile SHA256SUMS; do
  curl -fsSL -o "$f" "https://github.com/$REPO/releases/download/$TAG/$f"
done
echo "$SUMS_SHA  SHA256SUMS" | sha256sum -c -
sha256sum -c SHA256SUMS
chmod 755 hbbs hbbr
docker build -q -t "erpis-rustdesk-server:$TAG" .
docker run --rm "erpis-rustdesk-server:$TAG" hbbs --version
