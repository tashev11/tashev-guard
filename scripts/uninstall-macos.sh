#!/bin/zsh
set -euo pipefail
PLIST="$HOME/Library/LaunchAgents/dev.tashev.guard.plist"
launchctl bootout "gui/$(id -u)" "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
echo "Tashev Guard удалён из автозапуска."
