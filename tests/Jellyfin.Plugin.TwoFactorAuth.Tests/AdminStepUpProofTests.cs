using System;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Issue #194. The admin step-up modal accepted a TOTP or recovery code and
/// nothing else, so an admin whose factor is email OTP or a passkey could
/// never clear the gate. VerifyAdminProof takes the same proofs the
/// self-service step-up takes: the code paths, an emailed code, or the
/// single-use token the passkey assertion mints.
/// </summary>
public class AdminStepUpProofTests
{
    private static (StepUpService svc, TotpService totp, ChallengeStore challenges) NewService()
    {
        var paths = TestApplicationPaths.Create();
        var totp = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
        var challenges = new ChallengeStore();
        var svc = new StepUpService(totp, challenges, Substitute.For<ILogger<StepUpService>>());
        return (svc, totp, challenges);
    }

    private static (UserTwoFactorData data, string code) TotpUser(TotpService totp, Guid userId)
    {
        var secretBytes = KeyGeneration.GenerateRandomKey(20);
        var base32 = Base32Encoding.ToString(secretBytes);
        var data = new UserTwoFactorData
        {
            UserId = userId,
            EncryptedTotpSecret = totp.EncryptSecret(base32, userId),
        };
        return (data, new Totp(secretBytes).ComputeTotp());
    }

    [Fact]
    public void ATotpCodeStillPassesAndTheEmailPathIsNotConsulted()
    {
        var (svc, totp, _) = NewService();
        var userId = Guid.NewGuid();
        var (data, code) = TotpUser(totp, userId);
        var emailAsked = false;

        Assert.True(svc.VerifyAdminProof(data, userId, code, null, _ => { emailAsked = true; return true; }));
        Assert.False(emailAsked);
    }

    [Fact]
    public void AnEmailedCodeIsAcceptedWhenItIsNotATotpOrRecoveryCode()
    {
        var (svc, _, _) = NewService();
        var userId = Guid.NewGuid();
        var data = new UserTwoFactorData { UserId = userId };
        string? seen = null;

        Assert.True(svc.VerifyAdminProof(data, userId, "48213907", null, c => { seen = c; return c == "48213907"; }));
        Assert.Equal("48213907", seen);
        Assert.False(svc.VerifyAdminProof(data, userId, "00000000", null, _ => false));
    }

    [Fact]
    public void ThePasskeyTokenIsAcceptedOnceAndOnlyForItsOwner()
    {
        var (svc, _, challenges) = NewService();
        var admin = Guid.NewGuid();
        var other = Guid.NewGuid();
        var data = new UserTwoFactorData { UserId = admin };

        var token = challenges.MintUserStepUpToken(admin);
        // The token is tried first, so a stale code in the field cannot spoil it.
        Assert.True(svc.VerifyAdminProof(data, admin, "stale", token, _ => false));
        // Single use.
        Assert.False(svc.VerifyAdminProof(data, admin, null, token, _ => false));

        var foreign = challenges.MintUserStepUpToken(other);
        Assert.False(svc.VerifyAdminProof(data, admin, null, foreign, _ => false));
    }

    [Fact]
    public void NoProofAtAllIsRefusedWithoutAskingTheEmailPath()
    {
        var (svc, _, _) = NewService();
        var userId = Guid.NewGuid();
        var data = new UserTwoFactorData { UserId = userId };
        var emailAsked = false;

        Assert.False(svc.VerifyAdminProof(data, userId, null, null, _ => { emailAsked = true; return true; }));
        Assert.False(svc.VerifyAdminProof(data, userId, "   ", "", _ => { emailAsked = true; return true; }));
        Assert.False(emailAsked);
    }
}
