#!/usr/bin/env bash
# Downloads XposedBridgeApi-89.jar into app/libs/
# Run once before building: bash fetch_xposed_api.sh

set -e
DEST="app/libs/XposedBridgeApi-89.jar"
URL="https://github.com/rovo89/XposedBridge/releases/download/art/XposedBridgeApi-89.jar"

mkdir -p app/libs
curl -L "$URL" -o "$DEST"
echo "Saved to $DEST"
