using System.Text.Json;
using System.Xml.Serialization;
using Jellyfin.Plugin.TwoFactorAuth.Api;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class PasskeysEnabledTests
{
    internal static void SetEnabled(PluginConfiguration config, bool enabled)
    {
        var property = typeof(PluginConfiguration).GetProperty("PasskeysEnabled");
        Assert.NotNull(property);
        property.SetValue(config, enabled);
    }

    [Fact]
    public void Missing_settings_default_to_enabled_and_explicit_false_round_trips()
    {
        var property = typeof(PluginConfiguration).GetProperty("PasskeysEnabled");
        Assert.NotNull(property);
        Assert.Equal(true, property.GetValue(JsonSerializer.Deserialize<PluginConfiguration>("{}")));
        var serializer = new XmlSerializer(typeof(PluginConfiguration));
        using var legacy = new StringReader("<PluginConfiguration />");
        Assert.Equal(true, property.GetValue(serializer.Deserialize(legacy)));
        var config = new PluginConfiguration();
        SetEnabled(config, false);
        using var writer = new StringWriter();
        serializer.Serialize(writer, config);
        using var reader = new StringReader(writer.ToString());
        Assert.Equal(false, property.GetValue(serializer.Deserialize(reader)));
        Assert.Equal(false, property.GetValue(JsonSerializer.Deserialize<PluginConfiguration>(JsonSerializer.Serialize(config))));
    }

    public static IEnumerable<object[]> Matrix()
    {
        foreach (var enabled in new[] { false, true })
        foreach (var totp in new[] { false, true })
        foreach (var emailEnabled in new[] { false, true })
        foreach (var address in new[] { false, true })
        foreach (var scope in Enum.GetValues<EnforcementScope>())
        foreach (var admin in new[] { false, true })
        foreach (var preference in new[] { false, true })
            yield return new object[] { enabled, totp, emailEnabled, address, scope, admin, preference };
    }

    [Theory]
    [MemberData(nameof(Matrix))]
    public void Only_enabled_passkeys_count_without_changing_stored_state(
        bool enabled, bool totp, bool emailEnabled, bool address,
        EnforcementScope scope, bool admin, bool preference)
    {
        var config = new PluginConfiguration { EmailOtpEnabled = emailEnabled, EnforcementScope = scope };
        SetEnabled(config, enabled);
        var data = new UserTwoFactorData
        {
            UserId = Guid.NewGuid(), TotpEnabled = totp, TotpVerified = totp,
            PasskeyRequiresSecondFactor = preference,
            Passkeys = { new PasskeyCredential { Id = "saved-key", CredentialId = "credential" } },
        };
        if (address) config.SetUserEmail(data.UserId.ToString("N"), "person@example.test");
        var reason = config.ShouldEnforceFor(admin) ? "scope"
            : totp ? "authenticator" : enabled && preference ? "passkey" : "none";
        Assert.Equal(reason, SignInChallengePolicy.GetReason(data, config, admin));
        Assert.Equal(totp || enabled || (emailEnabled && address), SelfServiceFactors.HasAny(data, config));
        var body = JsonSerializer.SerializeToElement(TwoFactorAuthController.BuildPublicConfig(config, false));
        Assert.Equal(enabled, body.GetProperty("passkeysEnabled").GetBoolean());
        SetEnabled(config, true);
        Assert.True(SelfServiceFactors.HasAny(data, config));
        Assert.Equal(preference, data.PasskeyRequiresSecondFactor);
        Assert.Equal("credential", Assert.Single(data.Passkeys).CredentialId);
    }
}
