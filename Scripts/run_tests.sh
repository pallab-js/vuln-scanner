#!/bin/bash
set -euo pipefail

FRAMEWORKS_PATH="/Library/Developer/CommandLineTools/Library/Developer/Frameworks"
LIBS_PATH="/Library/Developer/CommandLineTools/Library/Developer/usr/lib"

swift test \
  -Xswiftc "-F" -Xswiftc "$FRAMEWORKS_PATH" \
  -Xlinker "-rpath" -Xlinker "$FRAMEWORKS_PATH" \
  -Xlinker "-rpath" -Xlinker "$LIBS_PATH" \
  -Xlinker "-F" -Xlinker "$FRAMEWORKS_PATH" \
  2>&1
