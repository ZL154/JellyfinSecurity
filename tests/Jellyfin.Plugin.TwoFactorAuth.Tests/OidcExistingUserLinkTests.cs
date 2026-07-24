using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class OidcExistingUserLinkTests
{
    [Fact]
    public void Existing_username_link_is_disabled_by_default()
    {
        Assert.False(OidcService.AllowsExistingUsernameLink(new OidcProvider()));
    }

    [Fact]
    public void Existing_username_link_can_be_enabled_without_auto_create()
    {
        var provider = new OidcProvider
        {
            AutoCreateUsers = false,
            LinkExistingUsersByUsername = true,
        };

        Assert.True(OidcService.AllowsExistingUsernameLink(provider));
    }

    [Fact]
    public void Auto_create_preserves_existing_username_link_compatibility()
    {
        var provider = new OidcProvider { AutoCreateUsers = true };
        Assert.True(OidcService.AllowsExistingUsernameLink(provider));
    }

    [Fact]
    public void Different_subject_for_same_provider_is_a_conflict()
    {
        var data = new UserTwoFactorData
        {
            SsoLinks =
            {
                new SsoLink { ProviderId = "keycloak", Subject = "original-subject" },
            },
        };

        Assert.True(
            OidcService.HasConflictingProviderLink(
                data,
                "keycloak",
                "replacement-subject"));
    }

    [Fact]
    public void Same_subject_or_different_provider_is_not_a_conflict()
    {
        var data = new UserTwoFactorData
        {
            SsoLinks =
            {
                new SsoLink { ProviderId = "keycloak", Subject = "subject-a" },
            },
        };

        Assert.False(OidcService.HasConflictingProviderLink(data, "keycloak", "subject-a"));
        Assert.False(OidcService.HasConflictingProviderLink(data, "other-provider", "subject-b"));
        Assert.False(OidcService.HasConflictingProviderLink(null, "keycloak", "subject-b"));
    }
}
