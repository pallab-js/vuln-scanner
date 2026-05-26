#!/bin/bash
set -euo pipefail

APP_NAME="LANScanner"
DMG_NAME="${APP_NAME}-v1.0.0.dmg"
BUNDLE_ID="com.lanscanner.app"
AC_USERNAME=${1:-""}
AC_PASSWORD=${2:-""}

if [ -z "$AC_USERNAME" ] || [ -z "$AC_PASSWORD" ]; then
    echo "Usage: $0 <apple-id> <app-specific-password>"
    echo "Create app-specific password at appleid.apple.com"
    exit 1
fi

if [ ! -f "$DMG_NAME" ]; then
    echo "Error: DMG not found at $DMG_NAME"
    exit 1
fi

echo "Submitting ${DMG_NAME} for notarization..."
xcrun notarytool submit "$DMG_NAME" \
    --apple-id "$AC_USERNAME" \
    --password "$AC_PASSWORD" \
    --team-id "" \
    --wait

echo "Stapling notarization ticket..."
xcrun stapler staple "$DMG_NAME"

echo "Verifying staple..."
spctl -a -v --type install "$DMG_NAME"

echo "Notarization complete"
