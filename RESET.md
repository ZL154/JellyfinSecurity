# Resetting a user's 2FA from outside the web UI

Use this when an admin is locked out of their own account and the web
panel can't be reached — i.e. you can SSH to the server, but the admin's
TOTP / recovery codes are gone.

## Prerequisite

You need to know the **user's GUID** (not their username). Find it in
Jellyfin's database:

```bash
# Inside the Jellyfin Docker container OR with sqlite3 installed locally
sqlite3 <jellyfin-config>/data/jellyfin.db \
  "SELECT Id, Username FROM Users;"
```

The `Id` column is the GUID you want, in `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
form (no dashes).

## Procedure

```bash
./reset-user.sh <jellyfin-config-path> <user-guid>
```

This script:
1. Stops Jellyfin (assumes systemd service named `jellyfin` or Docker
   container named `jellyfin` — adjust the script for other setups)
2. Renames the user's plugin data file to `.disabled-<timestamp>` so
   nothing is lost
3. Starts Jellyfin

When the user signs in next, the plugin sees no enrolment and lets them
through with just their password. They can then re-enrol from the Setup
page.

## Manual equivalent (no script)

```bash
# 1. Stop Jellyfin
sudo systemctl stop jellyfin
# OR: docker stop jellyfin

# 2. Disable that user's 2FA file
USER_GUID=d3686505c10641cc92c6fbbcf96dfc96   # from sqlite query above
JF=/opt/jellyfin/config
mv "$JF/plugins/configurations/TwoFactorAuth/users/${USER_GUID}.json" \
   "$JF/plugins/configurations/TwoFactorAuth/users/${USER_GUID}.json.disabled-$(date +%s)"

# 3. Start Jellyfin
sudo systemctl start jellyfin
# OR: docker start jellyfin
```

That's it. Restoring the user's old 2FA is impossible without their
recovery codes — they re-enrol from scratch.

## Don't have shell on the server?

Then the only option is asking another admin (any user with admin
privileges) to disable 2FA from the admin panel:

**Dashboard → Plugins → Two-Factor Authentication → Users → [user] →
Disable**

If you're the only admin and you're locked out, this is the only path
forward. Plan ahead: keep recovery codes printed, or set a 2nd admin.
