# Jellyfin 2FA Plugin

Native two-factor authentication plugin for Jellyfin 10.11.x. Enforces 2FA server-side via `IAuthenticationProvider`, so every client (web, mobile, TV, service integrations) goes through the same pipeline with no client-side bypass possible.

## Features

- **TOTP** (RFC 6238) — Google Authenticator, Authy, etc.
- **Email OTP** — fallback method with rate limiting
- **Trusted device tokens** — skip 2FA on remembered devices
- **TV device pairing** — 5-character codes for limited-input devices (Android TV, Apple TV)
- **LAN bypass** — configurable CIDR ranges for local network access
- **API key bypass** — static keys for Sonarr, Radarr, and other service integrations
- **Brute force protection** — lockout after failed attempts
- **Push notifications** — ntfy, Gotify, email alerts for login events
- **Audit logging** — full login attempt history
- **Admin dashboard** — manage users, devices, pairings, API keys, and settings

## Client Compatibility

| Client | 2FA Experience | Bypass Path |
|--------|---------------|-------------|
| Web browser | Redirect to challenge page | LAN bypass |
| Swiftfin (iOS) | Trusted device token after first login | Trusted device |
| Findroid (Android) | Trusted device token after first login | Trusted device |
| Android TV | Pairing code (admin approves) | Registered device |
| Apple TV / Infuse | Pairing code or pre-registered device | Registered device |
| Sonarr / Radarr | Use Jellyfin API keys (no user auth) | N/A |

## Installation

### Prerequisites

- Jellyfin 10.11.x
- .NET 9 SDK (for building from source)

### Build & Install

**Windows (PowerShell):**

```powershell
# Build only
.\build.ps1

# Build and install to local Jellyfin
.\build.ps1 -Install
```

**Linux/macOS:**

```bash
chmod +x build.sh

# Build only
./build.sh

# Build and install to local Jellyfin
./build.sh --install
```

### Manual Install

1. Build the plugin:
   ```bash
   cd src/Jellyfin.Plugin.TwoFactorAuth
   dotnet publish -c Release
   ```

2. Copy these files to your Jellyfin plugins directory:
   ```
   <jellyfin-data>/plugins/TwoFactorAuth/
   ├── meta.json
   ├── Jellyfin.Plugin.TwoFactorAuth.dll
   ├── Otp.NET.dll
   └── QRCoder.dll
   ```

   Plugin directories by OS:
   - **Windows:** `%LOCALAPPDATA%\jellyfin\plugins\TwoFactorAuth\`
   - **Linux:** `~/.local/share/jellyfin/plugins/TwoFactorAuth/`
   - **Docker:** `/config/plugins/TwoFactorAuth/`

3. Copy `meta.json` from `src/Jellyfin.Plugin.TwoFactorAuth/meta.json` into the same folder.

4. Restart Jellyfin.

## Setup

### 1. Enable the Plugin

After installation and restart, go to **Dashboard > Plugins**. The "Two-Factor Authentication" plugin should appear. Click it to open the admin dashboard.

### 2. Configure Settings

In the admin dashboard **Settings** tab:

- **Enabled** — toggle the plugin on/off
- **Require for All Users** — force 2FA for everyone (otherwise per-user opt-in)
- **LAN Bypass** — skip 2FA for local network requests (enabled by default)
- **LAN CIDR Ranges** — customize local network ranges
- **Notifications** — configure ntfy/Gotify server URLs for push alerts

### 3. Set Up TOTP (Per User)

Each user sets up their own 2FA from the setup page:

1. Navigate to the plugin setup page in user settings
2. Click **Set Up Authenticator App**
3. Scan the QR code with your authenticator app (Google Authenticator, Authy, etc.)
4. Enter the 6-digit code to confirm setup

### 4. Service Integrations

For Sonarr, Radarr, and similar services:

- Generate an **API key** in the admin dashboard **API Keys** tab
- Use the API key in the service's Jellyfin connection settings
- API key requests bypass 2FA entirely

### 5. TV / Limited-Input Devices

1. Try logging in from the TV — it will show a 5-character pairing code
2. An admin approves the pairing from the **Pairings** tab in the admin dashboard
3. The device is registered as trusted for future logins

## API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/TwoFactorAuth/Verify` | POST | Anonymous | Verify OTP code |
| `/TwoFactorAuth/Setup/Totp` | POST | User | Generate TOTP secret + QR code |
| `/TwoFactorAuth/Setup/Totp/Confirm` | POST | User | Confirm TOTP setup |
| `/TwoFactorAuth/Setup/Disable` | POST | User | Disable 2FA |
| `/TwoFactorAuth/Devices` | GET | User | List trusted devices |
| `/TwoFactorAuth/Devices/{id}` | DELETE | User | Revoke trusted device |
| `/TwoFactorAuth/Devices/Register` | POST | User | Pre-register device ID |
| `/TwoFactorAuth/Email/Send` | POST | Anonymous | Request email OTP |
| `/TwoFactorAuth/Pairings` | GET | Admin | List pending pairings |
| `/TwoFactorAuth/Pairings/{code}/Approve` | POST | Admin | Approve pairing |
| `/TwoFactorAuth/Pairings/{code}/Deny` | POST | Admin | Deny pairing |
| `/TwoFactorAuth/Users` | GET | Admin | List users with 2FA status |
| `/TwoFactorAuth/Users/{id}/Toggle` | POST | Admin | Toggle 2FA for user |
| `/TwoFactorAuth/AuditLog` | GET | Admin | View login history |
| `/TwoFactorAuth/ApiKeys` | GET/POST/DELETE | Admin | Manage API keys |
| `/TwoFactorAuth/Sessions/{id}/Revoke` | POST | Admin | Revoke session |

## Security

- TOTP secrets encrypted at rest via ASP.NET Core `IDataProtectionProvider`
- Device tokens stored as SHA-256 hashes
- Constant-time code comparison (`CryptographicOperations.FixedTimeEquals`)
- TOTP replay prevention (used codes tracked per time window)
- Challenge tokens: 256-bit, 5-minute TTL, single use
- Email OTP: rate limited (3 per 10 minutes), 5-minute TTL

## License

MIT
