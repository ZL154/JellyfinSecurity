using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class StepUpServiceTests
{
    [Fact]
    public void Config_defaults_are_opt_in_off()
    {
        var cfg = new PluginConfiguration();
        Assert.False(cfg.RequireTwoFactorToDisable);
        Assert.Equal(StepUpLevel.Off, cfg.StepUpLevel);
        Assert.Equal(300, cfg.StepUpWindowSeconds);
    }
}

public class StepUpServiceVerifyTests
{
    private static (StepUpService svc, TotpService totp) NewService()
    {
        var paths = TestApplicationPaths.Create();
        var totp = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
        var svc = new StepUpService(totp, new ChallengeStore(), Substitute.For<ILogger<StepUpService>>());
        return (svc, totp);
    }

    [Fact]
    public void VerifyUserCode_accepts_valid_totp()
    {
        var (svc, totp) = NewService();
        var userId = Guid.NewGuid();
        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var base32 = Base32Encoding.ToString(secretBytes);
        var userData = new UserTwoFactorData
        {
            UserId = userId,
            EncryptedTotpSecret = totp.EncryptSecret(base32, userId),
        };
        var code = new Totp(secretBytes).ComputeTotp();

        Assert.True(svc.VerifyUserCode(userData, code));
    }

    [Fact]
    public void VerifyUserCode_rejects_wrong_totp()
    {
        var (svc, totp) = NewService();
        var userId = Guid.NewGuid();
        var base32 = Base32Encoding.ToString(KeyGeneration.GenerateRandomKey(20));
        var userData = new UserTwoFactorData
        {
            UserId = userId,
            EncryptedTotpSecret = totp.EncryptSecret(base32, userId),
        };
        Assert.False(svc.VerifyUserCode(userData, "000000"));
    }

    [Fact]
    public void VerifyUserCode_accepts_recovery_code_once()
    {
        var (svc, _) = NewService();
        var raw = "ABCDE-FGHIJ";
        var normalized = RecoveryCodeService.NormalizeForCompare(raw);
        var userData = new UserTwoFactorData
        {
            UserId = Guid.NewGuid(),
            RecoveryCodes = new List<RecoveryCode>
            {
                new() { Hash = RecoveryCodeService.HashCodeV2(normalized), Used = false },
            },
        };

        Assert.True(svc.VerifyUserCode(userData, raw));   // first use
        Assert.True(userData.RecoveryCodes[0].Used);       // marked used
        Assert.False(svc.VerifyUserCode(userData, raw));   // second use rejected
    }

    [Fact]
    public void VerifyUserCode_rejects_empty()
    {
        var (svc, _) = NewService();
        Assert.False(svc.VerifyUserCode(new UserTwoFactorData { UserId = Guid.NewGuid() }, ""));
    }
}
