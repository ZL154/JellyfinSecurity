namespace Jellyfin.Plugin.TwoFactorAuth.Models;

/// <summary>v2.5.0: payload for the admin Settings → Localization picker
/// that persists PluginConfiguration.DefaultLanguage (the pre-login fallback
/// language used by login.html / challenge.html / setup.html before a
/// per-user preference is known).</summary>
public class DefaultLanguageRequest
{
    public string? DefaultLanguage { get; set; }
}

public class VerifyRequest
{
    public string ChallengeToken { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;

    public string Method { get; set; } = "totp";

    public bool TrustDevice { get; set; }
}

public class ConfirmTotpRequest
{
    public string Code { get; set; } = string.Empty;
}

public class RegisterDeviceRequest
{
    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;
}

public class CreateApiKeyRequest
{
    public string Label { get; set; } = string.Empty;
}

public class SendEmailOtpRequest
{
    public string ChallengeToken { get; set; } = string.Empty;
}

public class ChallengeTokenRequest
{
    public string ChallengeToken { get; set; } = string.Empty;
}

public class ForcedEnrollmentConfirmRequest
{
    public string ChallengeToken { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;

    public bool TrustDevice { get; set; }
}

public class ToggleUserRequest
{
    public bool Enabled { get; set; }
}

public class LoginWithCodeRequest
{
    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;

    public bool TrustDevice { get; set; }
}

public class TestSmtpRequest
{
    public string ToAddress { get; set; } = string.Empty;
}

public class SetEmailRequest
{
    public string Email { get; set; } = string.Empty;
}

public class InitiatePairingRequest
{
    public string Username { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;
}

/// <summary>v2.5.0: optional fresh code carried by the disable-2FA request
/// when RequireTwoFactorToDisable is on.</summary>
public class DisableRequest
{
    public string? Code { get; set; }
}

/// <summary>v2.5.0: body for exchanging a fresh 2FA code for a short-lived
/// step-up token.</summary>
public class StepUpVerifyRequest
{
    public string? Code { get; set; }
}

/// <summary>v2.5.0: payload for the focused hardening-config save endpoint
/// (gated by step-up). Only carries the v2.5.0 hardening fields; broader
/// plugin config still flows through Jellyfin's built-in PUT /Plugins/...
/// /Configuration endpoint (which the plugin can't intercept to gate).</summary>
public class HardeningConfigRequest
{
    public bool? RequireTwoFactorToDisable { get; set; }
    public Jellyfin.Plugin.TwoFactorAuth.Configuration.StepUpLevel? StepUpLevel { get; set; }
    public int? StepUpWindowSeconds { get; set; }
    /// <summary>v2.5.0: admin-side master switch that gates the per-device
    /// indefinite-trust user opt-in.</summary>
    public bool? AllowIndefiniteTrust { get; set; }
}

/// <summary>v2.5.0: per-device opt-in for indefinite trust. Set on a single
/// trusted browser or paired device, gated by the admin-side AllowIndefiniteTrust
/// master switch.</summary>
public class SetIndefiniteTrustRequest
{
    public bool Indefinite { get; set; }
}

/// <summary>v2.5.0: payload for POST /TwoFactorAuth/Config/Import. Envelope is
/// the JSON exported by GET /Config/Export. Passphrase only required when the
/// envelope is a "full" export with encrypted secrets.</summary>
public class ImportConfigRequest
{
    public string? Envelope { get; set; }
    public string? Passphrase { get; set; }
}

/// <summary>v2.5.0: payload for PUT /TwoFactorAuth/users/{userId}/preferences.
/// Null or empty Language clears the per-user override (reverts to admin
/// DefaultLanguage).</summary>
public class UpdatePreferencesRequest
{
    public string? Language { get; set; }
}
