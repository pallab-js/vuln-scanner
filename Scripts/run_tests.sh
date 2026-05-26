#!/bin/bash
set -euo pipefail

FRAMEWORKS_PATH="/Library/Developer/CommandLineTools/Library/Developer/Frameworks"

swift test \
  -Xswiftc "-F" -Xswiftc "$FRAMEWORKS_PATH" \
  -Xlinker "-rpath" -Xlinker "$FRAMEWORKS_PATH" \
  2>&1
