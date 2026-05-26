#!/bin/bash
set -euo pipefail

echo "Building LANScanner..."
swift build -c release --target App

echo "Build complete: .build/release/LANScanner"
