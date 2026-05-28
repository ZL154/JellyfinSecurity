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

public class StepUpClassificationTests
{
    [Theory]
    // Off → nothing requires step-up
    [InlineData(StepUpLevel.Off, StepUpAction.DisableEnforcement, false)]
    [InlineData(StepUpLevel.Off, StepUpAction.ViewAuditLog, false)]
    // Destructive → destructive yes, config-change no, audit-view no
    [InlineData(StepUpLevel.Destructive, StepUpAction.DisableEnforcement, true)]
    [InlineData(StepUpLevel.Destructive, StepUpAction.ResetOtherUser2fa, true)]
    [InlineData(StepUpLevel.Destructive, StepUpAction.ConfigChange, false)]
    [InlineData(StepUpLevel.Destructive, StepUpAction.ViewAuditLog, false)]
    // AllConfigChanges → destructive + config yes, audit-view no
    [InlineData(StepUpLevel.AllConfigChanges, StepUpAction.ConfigChange, true)]
    [InlineData(StepUpLevel.AllConfigChanges, StepUpAction.ConfigImport, true)]
    [InlineData(StepUpLevel.AllConfigChanges, StepUpAction.ViewAuditLog, false)]
    // Everything → all yes
    [InlineData(StepUpLevel.Everything, StepUpAction.ViewAuditLog, true)]
    [InlineData(StepUpLevel.Everything, StepUpAction.DisableEnforcement, true)]
    public void RequiresStepUp_matches_level(StepUpLevel level, StepUpAction action, bool expected)
    {
        Assert.Equal(expected, StepUpService.RequiresStepUp(level, action));
    }
}
