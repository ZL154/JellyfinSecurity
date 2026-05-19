using System;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;
using Microsoft.Extensions.Logging;
using NSubstitute;
using OtpNet;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class TotpServiceTests
{
    private static TotpService NewService()
    {
        var paths = TestApplicationPaths.Create();
        return new TotpService(paths, Substitute.For<ILogger<TotpService>>());
    }

    private static string NewBase32Secret()
    {
        var bytes = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(bytes);
    }

    private static string CurrentCode(string base32Secret)
    {
        var bytes = Base32Encoding.ToBytes(base32Secret);
        return new Totp(bytes, step: 30, totpSize: 6).ComputeTotp();
    }

    // ---- Input validation --------------------------------------------------

    [Theory]
    [InlineData("12345")]      // too short
    [InlineData("1234567")]    // too long
    [InlineData("")]
    [InlineData("   ")]
    public void ValidateCode_rejects_wrong_length(string code)
    {
        var svc = NewService();
        var secret = NewBase32Secret();

        Assert.False(svc.ValidateCode(secret, code, "user-A"));
    }

    [Fact]
    public void ValidateCode_rejects_invalid_base32_secret()
    {
        var svc = NewService();
        Assert.False(svc.ValidateCode("not!valid!base32!", "123456", "user-A"));
    }

    [Fact]
    public void ValidateCode_rejects_wrong_code()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        Assert.False(svc.ValidateCode(secret, "000000", "user-A"));
    }

    // ---- Happy path --------------------------------------------------------

    [Fact]
    public void ValidateCode_accepts_current_code()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A"));
    }

    // ---- Replay protection -------------------------------------------------

    [Fact]
    public void ValidateCode_rejects_replay_of_same_step()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A", 0, out var acceptedStep));
        Assert.True(acceptedStep > 0);

        // Same code, same user, same step — must be rejected as a replay.
        Assert.False(svc.ValidateCode(secret, code, "user-A", 0, out _));
    }

    [Fact]
    public void ValidateCode_replay_protection_is_per_user()
    {
        var svc = NewService();
        var secretA = NewBase32Secret();
        var codeA = CurrentCode(secretA);
        var secretB = NewBase32Secret();
        var codeB = CurrentCode(secretB);

        Assert.True(svc.ValidateCode(secretA, codeA, "user-A"));
        // user-B has a separate replay cache — fresh slate.
        Assert.True(svc.ValidateCode(secretB, codeB, "user-B"));
    }

    [Fact]
    public void ValidateCode_rejects_code_at_or_below_persisted_floor()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A", 0, out var step));

        // Reset cache and replay with the floor = matched step — must reject.
        svc.ResetReplayCache("user-A");
        Assert.False(svc.ValidateCode(secret, code, "user-A", step, out _));
    }

    [Fact]
    public void ResetReplayCache_allows_revalidation_after_secret_rotation()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var code = CurrentCode(secret);

        Assert.True(svc.ValidateCode(secret, code, "user-A"));
        Assert.False(svc.ValidateCode(secret, code, "user-A"));

        svc.ResetReplayCache("user-A");
        Assert.True(svc.ValidateCode(secret, code, "user-A"));
    }

    // ---- Encryption (AES-GCM with userId AAD) ------------------------------

    [Fact]
    public void EncryptSecret_then_DecryptSecret_roundtrips_v1_format()
    {
        var svc = NewService();
        var secret = NewBase32Secret();

        var encrypted = svc.EncryptSecret(secret);
        Assert.DoesNotContain("v2:", encrypted);
        Assert.Equal(secret, svc.DecryptSecret(encrypted));
    }

    [Fact]
    public void EncryptSecret_with_userId_uses_v2_format()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var encrypted = svc.EncryptSecret(secret, userId);
        Assert.StartsWith("v2:", encrypted);
        Assert.Equal(secret, svc.DecryptSecret(encrypted, userId));
    }

    [Fact]
    public void DecryptSecret_v2_requires_userId()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var encrypted = svc.EncryptSecret(secret, userId);
        // ThrowsAny — .NET's AesGcm raises AuthenticationTagMismatchException
        // on AAD mismatch, which is a subclass of CryptographicException.
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => svc.DecryptSecret(encrypted, null));
    }

    [Fact]
    public void DecryptSecret_v2_with_wrong_userId_throws()
    {
        // SEC-M3: AAD binding means swapping the v2 ciphertext to a different
        // user's record fails authentication, blocking on-disk identity swap.
        var svc = NewService();
        var secret = NewBase32Secret();
        var userA = Guid.NewGuid();
        var userB = Guid.NewGuid();

        var encrypted = svc.EncryptSecret(secret, userA);
        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => svc.DecryptSecret(encrypted, userB));
    }

    [Fact]
    public void MigrateToV2_promotes_v1_ciphertext()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var v1 = svc.EncryptSecret(secret); // no userId -> v1
        Assert.DoesNotContain("v2:", v1);

        var v2 = svc.MigrateToV2(v1, userId);
        Assert.NotNull(v2);
        Assert.StartsWith("v2:", v2);
        Assert.Equal(secret, svc.DecryptSecret(v2!, userId));
    }

    [Fact]
    public void MigrateToV2_is_idempotent_on_v2_input()
    {
        var svc = NewService();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var v2 = svc.EncryptSecret(secret, userId);
        var twice = svc.MigrateToV2(v2, userId);
        Assert.Equal(v2, twice);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void MigrateToV2_passes_through_empty_input(string? input)
    {
        var svc = NewService();
        var result = svc.MigrateToV2(input, Guid.NewGuid());
        Assert.Equal(input, result);
    }

    [Fact]
    public void Encrypted_secret_persists_across_service_restarts()
    {
        // The persistent secret.key allows new service instances pointed at the
        // same plugin directory to decrypt ciphertexts produced by an earlier
        // instance. Without this, every Jellyfin restart would invalidate every
        // TOTP enrollment — the exact bug v1.0.15 fixed.
        var paths = TestApplicationPaths.Create();
        var secret = NewBase32Secret();
        var userId = Guid.NewGuid();

        var first = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
        var ciphertext = first.EncryptSecret(secret, userId);

        var second = new TotpService(paths, Substitute.For<ILogger<TotpService>>());
        Assert.Equal(secret, second.DecryptSecret(ciphertext, userId));
    }
}
