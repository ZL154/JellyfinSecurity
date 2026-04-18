# Backing up the Jellyfin 2FA plugin

The plugin's entire state — TOTP seeds, recovery code hashes, paired
devices, trusted browsers, app passwords, audit log, signing keys — lives
in two locations under your Jellyfin config dir:

```
<jellyfin-config>/plugins/configurations/Jellyfin.Plugin.TwoFactorAuth.xml
<jellyfin-config>/plugins/configurations/TwoFactorAuth/   (whole directory)
```

A normal filesystem backup of `<jellyfin-config>/` already covers both. If
you use Restic, Borg, Duplicati, rsnapshot, or just rsync, you don't need
anything plugin-specific.

## Minimal manual backup

```bash
# Adjust the source path for your install
JF=/opt/jellyfin/config

tar -czf jellyfin-2fa-backup-$(date +%F).tgz \
    -C "$JF/plugins/configurations" \
    Jellyfin.Plugin.TwoFactorAuth.xml \
    TwoFactorAuth
```

Restore by extracting that tarball back into the same path with Jellyfin
stopped. After restart, the plugin will pick up where it left off and
existing trust cookies / TOTP enrolments will continue to work.

## What to NEVER ship in a backup

The two key files in `TwoFactorAuth/`:
- `secret.key` — symmetric AES key for TOTP seed encryption
- `cookie.key` — HMAC key for trust cookies

**Encrypt your backups.** Anyone with these keys plus the plugin's user
JSON files can decrypt every TOTP secret and forge any user's trust cookie.
At minimum, set tight file permissions on the backup file (chmod 0600).

## Migrating to a new server

1. Stop Jellyfin on both old and new
2. Tar the two paths above on the old server
3. Untar them into the corresponding paths on the new server
4. Make sure file ownership matches the new Jellyfin user
5. Start the new server

That's it. No re-enrolment needed.

## Disaster recovery (lost backup, lost authenticators)

If a user lost their authenticator AND their recovery codes AND the
trust cookies are all gone, an admin must reset that user from the
admin panel: **Dashboard → Plugins → Two-Factor Authentication → Users
→ Disable for that user**. The user can then re-enrol next sign-in.

If admins themselves are locked out (lost their own 2FA), see
[RESET.md](RESET.md) for the offline reset procedure.
