using System;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Admin actions that may require step-up re-auth, grouped by the
/// minimum StepUpLevel that gates them.</summary>
public enum StepUpAction
{
    // Destructive (level >= 1)
    DisableEnforcement,
    ResetOtherUser2fa,
    ExportWithSecrets,
    UnbanAll,
    ExportFullConfig,
    // AllConfigChanges (level >= 2)
    ConfigChange,
    Unban,
    ConfigImport,
    ImportConfig,
    // Everything (level >= 3)
    ViewAuditLog,
}

/// <summary>v2.5.0: verifies a fresh 2FA code for step-up / disable-guard, and
/// classifies which admin actions require step-up at the configured level.</summary>
public class StepUpService
{
    private readonly TotpService _totp;
    private readonly ChallengeStore _challenges;
    private readonly ILogger<StepUpService> _logger;

    public StepUpService(TotpService totp, ChallengeStore challenges, ILogger<StepUpService> logger)
    {
        _totp = totp;
        _challenges = challenges;
        _logger = logger;
    }

    /// <summary>Verify a submitted TOTP or recovery code against this user's
    /// 2FA state. If a recovery code matches, it is marked Used on
    /// <paramref name="userData"/> — the CALLER MUST PERSIST userData (e.g.
    /// inside a UserTwoFactorStore.MutateAsync block) when this returns true.</summary>
    public bool VerifyUserCode(UserTwoFactorData userData, string code)
    {
        if (userData is null || string.IsNullOrWhiteSpace(code)) return false;

        // 1. TOTP
        if (!string.IsNullOrEmpty(userData.EncryptedTotpSecret))
        {
            try
            {
                var secret = _totp.DecryptSecret(userData.EncryptedTotpSecret, userData.UserId);
                if (_totp.ValidateCode(secret, code, userData.UserId.ToString()))
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[2FA] step-up TOTP decrypt/validate failed; trying recovery");
            }
        }

        // 2. Recovery codes — single use, constant-time-ish (no early return on match)
        var normalized = RecoveryCodeService.NormalizeForCompare(code);
        int found = -1;
        for (int i = 0; i < userData.RecoveryCodes.Count; i++)
        {
            if (userData.RecoveryCodes[i].Used) continue;
            if (RecoveryCodeService.Verify(normalized, userData.RecoveryCodes[i].Hash) && found < 0)
            {
                found = i;
            }
        }
        if (found >= 0)
        {
            userData.RecoveryCodes[found].Used = true;
            return true;
        }
        return false;
    }

    /// <summary>Pure classifier: does <paramref name="action"/> require step-up
    /// at the given <paramref name="level"/>? Static + parameterized so it's
    /// unit-testable without Plugin.Instance.</summary>
    public static bool RequiresStepUp(StepUpLevel level, StepUpAction action)
    {
        if (level == StepUpLevel.Off) return false;
        var minLevel = action switch
        {
            StepUpAction.DisableEnforcement or StepUpAction.ResetOtherUser2fa
                or StepUpAction.ExportWithSecrets or StepUpAction.UnbanAll
                or StepUpAction.ExportFullConfig => StepUpLevel.Destructive,
            StepUpAction.ConfigChange or StepUpAction.Unban or StepUpAction.ConfigImport
                or StepUpAction.ImportConfig => StepUpLevel.AllConfigChanges,
            StepUpAction.ViewAuditLog => StepUpLevel.Everything,
            _ => StepUpLevel.Destructive,
        };
        return (int)level >= (int)minLevel;
    }

    /// <summary>Config-reading wrapper for controllers. Returns true if the
    /// action requires step-up AND the admin has no valid step-up token.</summary>
    public bool NeedsStepUpToken(Guid adminUserId, StepUpAction action)
    {
        var level = Plugin.Instance?.Configuration?.StepUpLevel ?? StepUpLevel.Off;
        if (!RequiresStepUp(level, action)) return false;
        return !_challenges.IsStepUpVerified(adminUserId);
    }
}
