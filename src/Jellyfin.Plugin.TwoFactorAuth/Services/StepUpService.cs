using System;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

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
}
