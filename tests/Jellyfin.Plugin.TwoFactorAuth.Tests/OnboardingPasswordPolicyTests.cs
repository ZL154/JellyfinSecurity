using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class OnboardingPasswordPolicyTests
{
    [Fact]
    public void FromConfiguration_clamps_length_and_copies_symbol_requirement()
    {
        var policy = OnboardingPasswordPolicy.FromConfiguration(new PluginConfiguration
        {
            OnboardingPasswordMinLength = 999,
            OnboardingPasswordRequireSymbol = true,
        });

        Assert.Equal(256, policy.MinLength);
        Assert.True(policy.RequireSymbol);
    }

    [Theory]
    [InlineData("Abcdefghijklmn1!", null)]
    [InlineData("Abcdefghijklmn12", "Password must contain a symbol.")]
    [InlineData("Abcdefghijklmn1\u00A9", null)]
    [InlineData("Abcdefghijklmn1 ", "Password must contain a symbol.")]
    public void Validate_enforces_symbol_without_counting_whitespace(string password, string? expected)
    {
        var policy = new OnboardingPasswordPolicy(16, true, true, true, true);
        Assert.Equal(expected, policy.Validate(password));
    }
}
