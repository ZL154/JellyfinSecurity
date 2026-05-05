#!/usr/bin/env bash
# Reset a single user's 2FA enrolment when the admin can't reach the web UI.
# Documented in RESET.md.
#
# Usage:
#   reset-user.sh <jellyfin-config-path> <user-guid>
#
# Example:
#   reset-user.sh /opt/jellyfin/config d3686505c10641cc92c6fbbcf96dfc96

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: $0 <jellyfin-config-path> <user-guid>" >&2
    exit 1
fi

JF_CONFIG=$1
USER_GUID=$2

# Strip dashes if user supplied a dashed GUID
USER_GUID=${USER_GUID//-/}

USER_FILE="$JF_CONFIG/plugins/configurations/TwoFactorAuth/users/${USER_GUID}.json"

if [ ! -f "$USER_FILE" ]; then
    echo "No 2FA file for user $USER_GUID at $USER_FILE" >&2
    echo "Either the GUID is wrong or the user has never enrolled — they can sign in already." >&2
    exit 2
fi

# Best-effort stop. Ignore errors; restart at the end either way.
echo "Stopping Jellyfin…"
if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q "^jellyfin\."; then
    sudo systemctl stop jellyfin || true
elif command -v docker >/dev/null && docker ps --format '{{.Names}}' | grep -qx jellyfin; then
    sudo docker stop jellyfin || true
else
    echo "Could not find a jellyfin service or container — stop it manually then press enter." >&2
    read -r
fi

BACKUP_PATH="${USER_FILE}.disabled-$(date +%s)"
mv "$USER_FILE" "$BACKUP_PATH"
echo "Renamed $USER_FILE → $BACKUP_PATH"

echo "Starting Jellyfin…"
if command -v systemctl >/dev/null && systemctl list-unit-files | grep -q "^jellyfin\."; then
    sudo systemctl start jellyfin
elif command -v docker >/dev/null && docker ps -a --format '{{.Names}}' | grep -qx jellyfin; then
    sudo docker start jellyfin
fi

echo
echo "Done. The user can now sign in with just their password and re-enrol from the Setup page."
echo "Old data is preserved at $BACKUP_PATH if you need to inspect it."
