```text
██████╗ ███████╗ █████╗
╚════██╗██╔════╝██╔══██╗
 █████╔╝█████╗  ███████║
██╔═══╝ ██╔══╝  ██╔══██║
███████╗██║     ██║  ██║
╚══════╝╚═╝     ╚═╝  ╚═╝
```

<p align="center">
  <img src="https://img.shields.io/badge/Jellyfin-10.11%2B-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
  <img src="https://img.shields.io/badge/Type-Plugin-00a4dc?style=for-the-badge&labelColor=000000&color=00a4dc" />
  <img src="https://img.shields.io/badge/System-Authentication-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
  <img src="https://img.shields.io/badge/Version-1.1.0-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
  <img src="https://img.shields.io/badge/License-MIT-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
</p>

# 🔐 Two-Factor Authentication for Jellyfin

A native server-side 2FA plugin that **enforces verification on every login** using TOTP authenticator apps, recovery codes, or email OTP. Built around a per-device trust model so users only enter codes when needed.

> **Why this exists:** Reverse-proxy 2FA (Authelia, Authentik) breaks native Jellyfin clients. This plugin handles 2FA inside Jellyfin so the web UI works correctly while still requiring a second factor for browser sign-ins.

---

## 📑 Table of contents

- [How it works](#-how-it-works)
- [Features](#-features)
- [Installation](#%EF%B8%8F-installation)
- [First-time setup](#-first-time-setup)
- [Daily use](#-daily-use)
- [Admin guide](#%EF%B8%8F-admin-guide)
- [SMTP setup (email OTP)](#-smtp-setup-email-otp)
- [Recovery — locked out](#-recovery--locked-out)
- [Architecture](#-architecture)
- [API endpoints](#-api-endpoints)
- [Security model](#-security-model)
- [Limitations](#-limitations)
- [License](#-license)

---

## ⚡ How it works

1. Each user opts into 2FA via `/TwoFactorAuth/Setup` — scans a QR code with an authenticator app and saves recovery codes.
2. On normal login, Jellyfin's `SessionStarted` event fires. The plugin checks if the user has 2FA enabled.
3. If yes, the plugin **blocks all subsequent API requests from that session** until the user completes 2FA via `/TwoFactorAuth/Login`.
4. After successful verification, a signed `__2fa_trust` cookie is set in the browser. **For 30 days, that browser doesn't need 2FA again** — but new browsers/devices still do.
5. The block applies regardless of how the user authenticated (Jellyfin web, mobile API, anything that creates a session).

The standard Jellyfin login page gets a small "Sign in with 2FA" button injected so users with 2FA enrolled can route directly to the plugin's login form.

---

## 🧩 Features

### Authentication
- **TOTP** (RFC 6238) compatible with Google Authenticator, Authy, 1Password, Microsoft Authenticator, Bitwarden, etc.
- **10 single-use recovery codes** generated at enrollment, stored as SHA-256 hashes, displayable once
- **Email OTP fallback** via configurable SMTP — codes expire in 5 minutes, single-use
- **Per-device trust** via signed HTTP-only cookie (HMAC-SHA256, 30-day expiry, `SameSite=Strict`)

### Enforcement
- Session-level enforcement via `ISessionManager.SessionStarted` — works for all clients, not just web
- API-level request blocking — even valid Jellyfin tokens get 401 until 2FA is completed
- Per-IP rate limiting on verify (10/min) and email send (5/5min)
- Per-challenge attempt limit (5 attempts before challenge is burned)
- Per-user lockout after 5 failed attempts (15-minute cool-down, configurable)
- LAN bypass (configurable CIDR ranges) so local devices can skip 2FA
- Force-2FA-for-all-users mode (admin setting)

### Security
- TOTP secrets encrypted at rest with **AES-GCM** using a persistent 32-byte key (survives restarts)
- Cookie signatures use **HMAC-SHA256** with persistent key
- Constant-time comparison for all secret material (`CryptographicOperations.FixedTimeEquals`)
- TOTP replay prevention (used time-steps tracked per user)
- Recovery codes marked used immediately on validation (not on full login success) — stolen codes can't be retried
- Atomic file writes for user data — crash mid-write doesn't corrupt 2FA state
- Generic error messages prevent account enumeration ("invalid credentials" whether password or code is wrong)

### UI
- Polished login page with lockout countdown
- Setup page with QR code, recovery code generation, trusted device list
- Admin dashboard with users, devices, audit log (paginated, filterable), and settings
- Per-user email address management for OTP delivery
- "Sign in with 2FA" button auto-injected into Jellyfin's standard login page

### Notifications
- Push notifications for login attempts via **ntfy** or **Gotify**
- Audit log of every 2FA-related event (1000 entries default, FIFO, 90-day prune)

---

## ⚙️ Installation

1. Open Jellyfin → **Dashboard → Plugins → Repositories**
2. Click **+** and add this URL:

```
https://raw.githubusercontent.com/ZL154/JellyfinSecurity/main/manifest.json
```

3. Save and refresh plugins
4. Go to the **Catalogue** tab → install **Two-Factor Authentication**
5. Restart Jellyfin

### Build from source

```powershell
# Windows
.\build.ps1 -Install
```

```bash
# Linux/macOS
chmod +x build.sh && ./build.sh --install
```

### Manual install

Copy these 4 files into `<jellyfin-data>/plugins/TwoFactorAuth/`:

```
TwoFactorAuth/
├── meta.json
├── Jellyfin.Plugin.TwoFactorAuth.dll
├── Otp.NET.dll
└── QRCoder.dll
```

Plugin directories by OS:
- **Docker:** `/config/plugins/TwoFactorAuth/`
- **Linux:** `~/.local/share/jellyfin/plugins/TwoFactorAuth/`
- **Windows:** `%LOCALAPPDATA%\jellyfin\plugins\TwoFactorAuth\`

Restart Jellyfin after copying.

---

## 🚀 First-time setup

### As an admin

1. After installing, go to **Dashboard → Plugins → Two-Factor Authentication**
2. Open the **Settings** tab and verify:
   - ✅ Plugin Enabled
   - ✅ LAN Bypass enabled (skip 2FA on local network)
   - ✅ Email OTP allowed (optional fallback)
3. If you're behind a reverse proxy (Cloudflare Tunnel, nginx, Caddy), enable **Trust X-Forwarded-For** and add your proxy IPs to **Trusted Proxy CIDRs**

### As a user (enroll in 2FA)

1. Visit `https://your-jellyfin/TwoFactorAuth/Setup`
2. Click **Set up Authenticator App**
3. Scan the QR code with your authenticator app
4. Type the 6-digit code shown in the app to confirm
5. **Generate recovery codes** and save them somewhere safe (password manager). Each code works once and can sign you in if you lose your phone.

---

## 🔄 Daily use

### Web login (browser)

- On the standard Jellyfin login page, click the **🔐 Sign in with Two-Factor Authentication** button
- Enter your username, password, and 6-digit code from your app
- After first sign-in on this browser, you won't be asked for the code again for 30 days

### Mobile apps (Swiftfin, Findroid, etc.)

Mobile apps don't currently support 2FA flows. Workaround:
1. Sign in once via the web on the same device using `/TwoFactorAuth/Login`
2. Then configure the mobile app — it will use a session token from a successful 2FA login

A native mobile flow requires app-side support which is out of scope for this plugin.

### Sonarr / Radarr / Overseerr / Jellyseerr

Use Jellyfin's standard API keys (Dashboard → API Keys). API key auth bypasses user authentication entirely, so 2FA doesn't apply.

---

## 🛠️ Admin guide

The admin dashboard at **Dashboard → Plugins → Two-Factor Authentication** has 5 tabs:

### Users
Per-user 2FA status: TOTP on/off, trusted device count, recovery codes remaining, email address (for OTP), lockout status.
- **Set per-user email** — for email OTP delivery (admin sets these manually)
- **Toggle 2FA on/off** — disabling wipes all 2FA state for that user (secret, codes, devices)

### Trusted Devices
Every trusted device across all users with last-used time and expiry. Revoke any to force 2FA on that browser's next login.

### Pairings
Pending TV pairing requests (currently a stub — see "Limitations" below).

### Audit Log
Paginated, filterable login attempt history. Tracks success, failures, lockouts, bypasses, and challenge issuances.

### Settings
- **General** — plugin toggle, force 2FA for all users, email OTP toggle
- **LAN Bypass** — CIDR ranges, X-Forwarded-For trust, trusted proxies
- **Security** — failed-attempt threshold, lockout duration, audit log size
- **SMTP** — host, port, SSL, credentials, from-address (required for email OTP)
- **Push Notifications** — ntfy URL/topic, Gotify URL/token, admin email addresses

---

## 📧 SMTP setup (email OTP)

Email OTP requires SMTP credentials. Common providers:

### Gmail (with app password)
```
SMTP Host: smtp.gmail.com
SMTP Port: 587
Use SSL/TLS: ✓
SMTP Username: your-email@gmail.com
SMTP Password: <generate at https://myaccount.google.com/apppasswords>
From Address: your-email@gmail.com
From Name: Jellyfin 2FA
```

### Generic SMTP relay
```
SMTP Host: mail.example.com
SMTP Port: 587 (STARTTLS) or 465 (implicit TLS)
Use SSL/TLS: ✓
```

### Per-user email addresses

Email OTP needs the user's email address. In **Admin → Users**, edit each user's email field. The plugin doesn't auto-pull from Jellyfin user metadata (Jellyfin's `User` entity exposes email inconsistently across versions).

---

## 🆘 Recovery — locked out

### Lost authenticator app + have recovery codes
Sign in via `/TwoFactorAuth/Login`. In the code field, enter one of your recovery codes (format: `XXXXX-XXXXX`). Click "Use a recovery code instead" if your authenticator app field is showing.

### Lost authenticator AND lost recovery codes (admin)
SSH into the Jellyfin server and edit the user data file:

```bash
# Path
/config/plugins/configurations/TwoFactorAuth/users/{userId}.json

# Set:
"TotpEnabled": false,
"TotpVerified": false,
"EncryptedTotpSecret": null,
"RecoveryCodes": [],
"TrustedDevices": []
```

Restart Jellyfin. The user can now log in normally and re-enroll.

### Plugin breaking your server
Disable the plugin without uninstalling:

```bash
# Edit
/config/plugins/configurations/Jellyfin.Plugin.TwoFactorAuth.xml

# Set
<Enabled>false</Enabled>
```

Restart Jellyfin. All 2FA enforcement turns off; users can log in normally.

---

## 🏗️ Architecture

The plugin uses **5 ASP.NET Core middleware** components plus an `ISessionManager.SessionStarted` event handler:

1. **`IndexHtmlInjectionMiddleware`** — injects the "Sign in with 2FA" button script into Jellyfin's `index.html`
2. **`TrustCookieMiddleware`** — checks the `__2fa_trust` cookie on auth requests; if valid, marks the user as pre-verified for the upcoming session
3. **`TwoFactorEnforcementMiddleware`** — inspects responses from auth endpoints (catches the auth response shape regardless of which Jellyfin route was used)
4. **`RequestBlockerMiddleware`** — blocks API requests from authenticated users who haven't completed 2FA yet (returns 401)
5. **`AuthenticationEventHandler`** (hosted service) — subscribes to `SessionStarted`; if a session for a 2FA-enabled user starts without verification, the user is added to the blocker's blocklist

Persistent state:
- `users/{userId}.json` — per-user TOTP secret (AES-GCM encrypted), recovery codes (SHA-256 hashed), trusted devices, lockout state
- `secret.key` — 32-byte AES-GCM key for TOTP secret encryption
- `cookie.key` — 32-byte HMAC-SHA256 key for trust cookie signing
- `audit.json` — login attempt log

All file writes use atomic write-then-rename so crashes mid-write don't corrupt user state.

---

## 📡 API endpoints

### User-facing (anonymous or self-auth)
```
GET  /TwoFactorAuth/Login                                — login page (HTML)
GET  /TwoFactorAuth/Setup                                — enrollment page (HTML)
GET  /TwoFactorAuth/Challenge?token=...                  — challenge page (HTML)
GET  /TwoFactorAuth/inject.js                            — login button injection
POST /TwoFactorAuth/Authenticate                         — username + password + code login
POST /TwoFactorAuth/Verify                               — verify code against challenge token
POST /TwoFactorAuth/Email/Send                           — request email OTP for current challenge

POST /TwoFactorAuth/Setup/Totp                           — generate TOTP secret + QR (auth)
POST /TwoFactorAuth/Setup/Totp/Confirm                   — confirm TOTP enrollment (auth)
POST /TwoFactorAuth/Setup/Disable                        — disable 2FA for self (auth)
POST /TwoFactorAuth/RecoveryCodes/Generate               — generate recovery codes (auth)
GET  /TwoFactorAuth/RecoveryCodes/Status                 — count remaining (auth)

GET  /TwoFactorAuth/Devices                              — own trusted devices (auth)
DELETE /TwoFactorAuth/Devices/{id}                       — revoke own trusted device (auth)
POST /TwoFactorAuth/Devices/Register                     — pre-register device ID (auth)
```

### Admin-only (`RequiresElevation`)
```
GET    /TwoFactorAuth/Users                              — all users with 2FA status
POST   /TwoFactorAuth/Users/{id}/Toggle                  — enable/disable 2FA for user
GET    /TwoFactorAuth/AllTrustedDevices                  — devices across all users
DELETE /TwoFactorAuth/Users/{userId}/Devices/{deviceId}  — admin revoke
GET    /TwoFactorAuth/AuditLog                           — login history
GET    /TwoFactorAuth/Pairings                           — pending TV pairings
POST   /TwoFactorAuth/Pairings/{code}/Approve            — approve pairing
POST   /TwoFactorAuth/Pairings/{code}/Deny               — deny pairing
GET    /TwoFactorAuth/ApiKeys                            — list managed API keys
POST   /TwoFactorAuth/ApiKeys                            — generate new API key
DELETE /TwoFactorAuth/ApiKeys/{id}                       — delete API key
POST   /TwoFactorAuth/Sessions/{id}/Revoke               — revoke an active session
```

---

## 🔒 Security model

| Threat | Mitigation |
|---|---|
| Stolen password (no 2FA bypass) | All sessions blocked until 2FA completed; correct password alone gives 401 on every API call |
| TOTP brute force on the 6-digit code space | Per-IP rate limit (10/min on verify, 10/min on auth), per-challenge attempt limit (5), per-user lockout (5 failures → 15min) |
| Stolen recovery code | Marked used immediately on validation regardless of password outcome — can't be retried |
| Stolen trust cookie | HMAC-SHA256 signed with persistent server-side key; HttpOnly, Secure, SameSite=Strict; tied to a server-side trust record (revocable) |
| Account enumeration | Identical "invalid credentials" message whether password is wrong, user doesn't exist, or 2FA code is wrong |
| Disk corruption mid-write | Atomic write-then-rename for all user state files |
| TOTP secret theft from disk | AES-GCM encrypted with persistent 32-byte key |
| Replay attacks on TOTP | Used time-steps tracked per user |
| Timing attacks | `CryptographicOperations.FixedTimeEquals` on all secret comparisons |
| Service integrations breaking | Standard Jellyfin API keys bypass user auth — Sonarr/Radarr unaffected |
| Authelia/Authentik breaking native apps | Native plugin, no proxy dependency |

---

## ⚠️ Limitations

- **Mobile apps (Swiftfin, Findroid)** — these don't support a 2FA flow yet. Workaround: do a 2FA login via web on the same device first; mobile clients can then use the resulting session token. A native mobile flow requires app-side changes.
- **TV pairing flow** — backend exists, no TV-side UI yet. Use trusted device tokens or admin pre-registration of device IDs.
- **Quick Connect** — works as Jellyfin's normal flow but creates a session subject to 2FA enforcement (user will be blocked until they complete 2FA via `/TwoFactorAuth/Login`).
- **Email OTP requires admin to set per-user email** — Jellyfin's user entity doesn't expose email consistently across versions, so admins enter emails in the Users tab.
- **Cookie isn't bound to IP** — a stolen trust cookie works from any IP for 30 days. Standard for browser cookies; revoke the device in admin if a browser is compromised.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

| You can | You must | You cannot |
|---------|----------|------------|
| Use on any server, personal or commercial | Keep the copyright notice in any redistribution | Hold the authors liable for damage |
| Fork and modify | | Claim author endorsement of your fork |
| Redistribute, modified or unmodified | | |

---

⭐ If you use this plugin, consider starring the repository.
