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
  <img src="https://img.shields.io/badge/Version-1.0.0-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
  <img src="https://img.shields.io/badge/License-MIT-0b0b0b?style=for-the-badge&labelColor=000000&color=2b2b2b" />
</p>

# 🔐 Two-Factor Authentication for Jellyfin

A native server-side 2FA plugin that intercepts all login requests via `IAuthenticationProvider`. Every client — web, mobile, TV, and service integrations — goes through the same pipeline with no client-side bypass possible.

> **Why this exists:** Reverse-proxy solutions (Authelia, Authentik) break native app authentication. This plugin handles 2FA natively within Jellyfin so every client works out of the box.

---

## 📑 Table of contents

- [Overview](#-overview)
- [Core features](#-core-features) — TOTP, email OTP, device pairing, bypass, notifications, admin
- [Installation](#%EF%B8%8F-installation)
- [Setup](#-setup)
- [Client compatibility](#-client-compatibility)
- [API endpoints](#-api-endpoints)
- [Security](#-security)
- [License](#-license)

---

## ✨ Overview

Server-side two-factor authentication that enforces OTP verification at the API level. Supports TOTP (RFC 6238) with authenticator apps, email OTP as fallback, trusted device tokens for seamless re-login, TV device pairing for limited-input devices, LAN bypass for local access, and static API keys for service integrations like Sonarr and Radarr.

---

## 🧩 Core features

### 🔑 TOTP (Time-Based One-Time Passwords)
- **RFC 6238 compliant** — works with Google Authenticator, Authy, Microsoft Authenticator, and any TOTP app
- **QR code enrollment** — scan to set up, enter a code to confirm
- **160-bit secrets** encrypted at rest via ASP.NET Core `IDataProtectionProvider`
- **±1 time-step tolerance** (30-second windows)
- **Replay prevention** — used codes tracked per user per time window, rejected on resubmission
- **Constant-time comparison** via `CryptographicOperations.FixedTimeEquals`

### 📧 Email OTP (Fallback)
- **6-digit numeric codes** sent via Jellyfin's mail system
- **5-minute TTL**, single use
- **Rate limited** — max 3 sends per user per 10-minute window
- Available as a fallback when TOTP isn't configured, or selectable by the user during challenge

### 📱 Trusted Device Tokens
- After successful 2FA, opt in to "Trust this device" — future logins skip 2FA
- **256-bit tokens** generated via `RandomNumberGenerator`, stored as SHA-256 hashes
- Per-user, per-device — sent via `X-TwoFactor-Token` header
- Individually revocable from the user setup page or admin dashboard

### 📺 TV / Limited-Input Device Pairing
- TV shows a **5-character alphanumeric code** (ambiguous characters excluded: 0, O, 1, I, L)
- **Admin approves or denies** from the admin dashboard or push notification
- On approval, the TV gets a session token and is registered as a trusted device
- **5-minute code TTL** — codes expire automatically

### 🏠 LAN Bypass
- Skip 2FA for requests from local network IPs
- **Default CIDR ranges:** `192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`
- Configurable ranges in admin settings
- **X-Forwarded-For support** with configurable trusted proxy CIDRs for reverse proxy setups
- IPv4 and IPv6 support

### 🔧 API Key Bypass
- Generate **static API keys** for service integrations (Sonarr, Radarr, Overseerr, etc.)
- Requests using a plugin-managed API key bypass 2FA entirely
- Standard Jellyfin API keys also bypass since they don't use user authentication

### 🛡️ Brute Force Protection
- **5 failed attempts** → 15-minute lockout per user (configurable)
- Failed attempts logged to audit log
- Push notification after 3+ consecutive failures
- Lockout state tracked per user in persistent storage

### 🔔 Push Notifications
- **ntfy** — HTTP POST to your ntfy server/topic
- **Gotify** — HTTP POST with app token
- **Email** — via Jellyfin's SMTP to configured admin addresses
- Triggers: new device login, failed attempts, pending TV pairing, pairing completion

### 📋 Audit Logging
- Full login attempt history — IP, device, timestamp, result, method
- **1000 entries** (configurable), FIFO with 90-day auto-prune
- Searchable/filterable from the admin dashboard

### 🛠️ Admin Dashboard
- **Pending Pairings** — approve/deny TV device pairing requests (auto-refreshes)
- **User Management** — table of all users with 2FA status, toggle enable/disable per user
- **Trusted Devices** — all trusted devices across all users, with revoke
- **Audit Log** — searchable login attempt history
- **API Keys** — generate and manage static API keys
- **Settings** — LAN bypass CIDRs, notification config, brute force thresholds, email OTP settings

### 🌐 Web Challenge Page
- **Standalone dark-themed page** at `/TwoFactorAuth/Challenge` — no Jellyfin UI modifications needed
- 6-digit code input with method selector (TOTP / Email)
- "Trust this device" checkbox
- Auto-redirect back to Jellyfin on successful verification
- Resilient to Jellyfin web UI updates (standalone page, not injected JS)

---

## ⚙️ Installation

1. Go to **Dashboard → Plugins → Repositories**
2. Add:

```
https://raw.githubusercontent.com/ZL154/Jellyfin2FA/main/manifest.json
```

3. Save and refresh plugins
4. Install **Two-Factor Authentication**
5. Restart Jellyfin

### Build from Source

**Prerequisites:** Jellyfin 10.11.x, .NET 9 SDK

```powershell
# Windows — build and install to local Jellyfin
.\build.ps1 -Install
```

```bash
# Linux/macOS — build and install to local Jellyfin
chmod +x build.sh && ./build.sh --install
```

### Manual Install

Copy these 4 files into `<jellyfin-data>/plugins/TwoFactorAuth/`:

```
TwoFactorAuth/
├── meta.json
├── Jellyfin.Plugin.TwoFactorAuth.dll
├── Otp.NET.dll
└── QRCoder.dll
```

Plugin directories by OS:
- **Windows:** `%LOCALAPPDATA%\jellyfin\plugins\TwoFactorAuth\`
- **Linux:** `~/.local/share/jellyfin/plugins/TwoFactorAuth/`
- **Docker:** `/config/plugins/TwoFactorAuth/`

Restart Jellyfin after copying.

---

## 🚀 Setup

### 1. Enable & Configure

Go to **Dashboard → Plugins → Two-Factor Authentication** to open the admin dashboard. In the **Settings** tab:

- **Enabled** — global on/off
- **Require for All Users** — force 2FA for everyone (otherwise per-user opt-in)
- **LAN Bypass** — skip 2FA for local network (enabled by default)
- **Notifications** — configure ntfy/Gotify URLs for push alerts

### 2. Set Up TOTP (Per User)

1. Navigate to the plugin setup page in user settings
2. Click **Set Up Authenticator App**
3. Scan the QR code with your authenticator app
4. Enter the 6-digit code to confirm setup

### 3. Service Integrations (Sonarr, Radarr, etc.)

1. Generate an **API key** in the admin dashboard **API Keys** tab
2. Use the API key in the service's Jellyfin connection settings
3. API key requests bypass 2FA entirely

### 4. TV / Limited-Input Devices

1. Log in from the TV — a 5-character pairing code appears
2. Admin approves from the **Pairings** tab (or push notification)
3. The device is registered as trusted for future logins

---

## 📱 Client Compatibility

| Client | 2FA Experience | Bypass Path |
|--------|---------------|-------------|
| Web browser | Redirect to challenge page → enter code → redirect back | LAN bypass |
| Swiftfin (iOS) | First login: enter code or admin pairs. Subsequent: auto-bypass | Trusted device token |
| Findroid (Android) | Same as Swiftfin | Trusted device token |
| Android TV | Pairing code flow (code shown, admin approves) | Registered device ID |
| Apple TV / Infuse | Pre-register device ID via admin, or pairing code flow | Registered device ID |
| Sonarr / Radarr | Use Jellyfin API keys (never hit user auth) | N/A (API key auth) |
| Kodi | Trusted device token after first approval | Trusted device token |

---

## 📡 API Endpoints

### User-facing (require auth)
```
POST   /TwoFactorAuth/Verify                    — verify OTP code against challenge
POST   /TwoFactorAuth/Setup/Totp                — generate TOTP secret + QR code
POST   /TwoFactorAuth/Setup/Totp/Confirm         — confirm TOTP setup with verification code
POST   /TwoFactorAuth/Setup/Disable              — disable 2FA for current user
GET    /TwoFactorAuth/Devices                    — list trusted devices
DELETE /TwoFactorAuth/Devices/{id}               — revoke a trusted device
POST   /TwoFactorAuth/Devices/Register           — pre-register a device ID
POST   /TwoFactorAuth/Email/Send                 — request email OTP for pending challenge
```

### Admin-only (require `RequiresElevation`)
```
GET    /TwoFactorAuth/Pairings                   — list pending TV pairing requests
POST   /TwoFactorAuth/Pairings/{code}/Approve    — approve a TV pairing
POST   /TwoFactorAuth/Pairings/{code}/Deny       — deny a TV pairing
GET    /TwoFactorAuth/Users                      — list all users with 2FA status
POST   /TwoFactorAuth/Users/{id}/Toggle          — enable/disable 2FA for a user
GET    /TwoFactorAuth/AuditLog                   — get login attempt log
GET    /TwoFactorAuth/ApiKeys                    — list API keys
POST   /TwoFactorAuth/ApiKeys                    — generate new API key
DELETE /TwoFactorAuth/ApiKeys/{id}               — delete an API key
POST   /TwoFactorAuth/Sessions/{id}/Revoke       — revoke an active session
```

---

## 🔒 Security

| Threat | Mitigation |
|--------|-----------|
| Port-forwarded Jellyfin with stolen password | 2FA required for all remote logins |
| Cloudflare Tunnel exposure | All non-LAN requests require 2FA |
| Authelia/Authentik breaking native apps | Native plugin, no proxy dependency |
| Service integrations breaking | API keys bypass user auth entirely |
| TOTP secret theft from disk | Encrypted at rest via DataProtectionProvider |
| Brute force on OTP codes | Rate limiting + lockout after 5 failures |
| Replay attacks on TOTP | Used-code tracking per time window |
| Timing attacks on code comparison | `CryptographicOperations.FixedTimeEquals` |

---

## 📜 License

This project is released under the [MIT License](LICENSE).

| You can | You must | You cannot |
|---------|----------|------------|
| Use on any server | Keep the copyright notice | Hold authors liable |
| Fork and modify | | Claim endorsement |
| Redistribute freely | | |

---

⭐ If you use this plugin, consider starring the repository.
