#!/bin/bash
set -euo pipefail

APP_NAME="LANScanner"
APP_PATH=".build/release/${APP_NAME}.app"
ENTITLEMENTS="Resources/entitlements.plist"
IDENTITY=${1:-"-"}

if [ ! -d "$APP_PATH" ]; then
    echo "Error: App bundle not found at $APP_PATH"
    echo "Run package.sh first"
    exit 1
fi

echo "Signing ${APP_NAME}..."
codesign --deep --force --verify --verbose \
    --options runtime \
    --entitlements "${ENTITLEMENTS}" \
    --sign "${IDENTITY}" \
    "${APP_PATH}"

echo "Verifying signature..."
codesign --verify --deep --strict --verbose=2 "${APP_PATH}"
spctl --assess --verbose=2 "${APP_PATH}"

echo "Signing complete"
