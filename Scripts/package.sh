#!/bin/bash
set -euo pipefail

APP_NAME="LANScanner"
BUILD_DIR=".build/release"
DMG_NAME="${APP_NAME}-v1.0.0.dmg"

echo "Building release binary..."
swift build -c release --target App

echo "Creating app bundle..."
APP_BUNDLE="${BUILD_DIR}/${APP_NAME}.app"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${BUILD_DIR}/${APP_NAME}" "${APP_BUNDLE}/Contents/MacOS/"

cat > "${APP_BUNDLE}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>
    <string>com.lanscanner.app</string>
    <key>CFBundleName</key>
    <string>${APP_NAME}</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
</dict>
</plist>
EOF

cp "Resources/entitlements.plist" "${APP_BUNDLE}/Contents/Resources/"

echo "App bundle created at ${APP_BUNDLE}"

if command -v create-dmg &> /dev/null; then
    echo "Creating DMG..."
    create-dmg --volname "${APP_NAME}" --window-pos 200 120 --window-size 800 400 \
        --icon-size 100 --icon "${APP_NAME}.app" 200 190 \
        --hide-extension "${APP_NAME}.app" --app-drop-link 600 185 \
        "${DMG_NAME}" "${BUILD_DIR}/"
    echo "DMG created: ${DMG_NAME}"
else
    echo "create-dmg not found. Install with: brew install create-dmg"
fi
