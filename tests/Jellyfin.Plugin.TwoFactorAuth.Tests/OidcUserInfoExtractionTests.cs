using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Issue #29: many IdPs (Authelia, Keycloak, Authentik) emit `groups` only in
/// the /userinfo response, not the id_token. ExtractGroupsFromJson must
/// handle every common shape so the AllowedGroups allowlist works against the
/// merged claim set, regardless of how the IdP encoded the value.
/// </summary>
public class OidcUserInfoExtractionTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public void ExtractGroups_FromJsonArray_ReturnsEachMember()
    {
        // Authelia 4.38+ / Keycloak / Authentik default shape.
        var json = Parse("""{ "groups": ["jellyfin-users", "admins"] }""");

        var result = OidcService.ExtractGroupsFromJson(json);

        Assert.Equal(new[] { "jellyfin-users", "admins" }, result);
    }

    [Fact]
    public void ExtractGroups_FromCommaSeparatedString_Splits()
    {
        // Some legacy IdP configs and a handful of custom OIDC providers
        // serialise groups as a single comma-separated string. Split + trim.
        var json = Parse("""{ "groups": "jellyfin-users, admins , video" }""");

        var result = OidcService.ExtractGroupsFromJson(json);

        Assert.Equal(new[] { "jellyfin-users", "admins", "video" }, result);
    }

    [Fact]
    public void ExtractGroups_MergesGroupsAndRoles()
    {
        // Keycloak uses `roles`, Authelia uses `groups`, some configs use
        // both. We treat them as equivalent for the AllowedGroups check.
        var json = Parse("""{ "groups": ["jellyfin-users"], "roles": ["admin"] }""");

        var result = OidcService.ExtractGroupsFromJson(json);

        Assert.Equal(new[] { "jellyfin-users", "admin" }, result);
    }

    [Fact]
    public void ExtractGroups_NoGroupsOrRoles_ReturnsEmpty()
    {
        // The id_token-only flow with no userinfo groups falls through here
        // — must not crash, must return an empty array so the caller's
        // Concat+Distinct merge stays correct.
        var json = Parse("""{ "sub": "user@example.com", "email": "user@example.com" }""");

        var result = OidcService.ExtractGroupsFromJson(json);

        Assert.Empty(result);
    }

    [Fact]
    public void ExtractGroups_NonObjectRoot_ReturnsEmpty()
    {
        // Defensive: if /userinfo returned a bare string or null (malformed
        // server), we must not crash. Empty array lets the merge continue
        // with id_token groups only.
        var nullJson = Parse("null");
        var stringJson = Parse(""" "not-an-object" """);
        var arrayJson = Parse("[]");

        Assert.Empty(OidcService.ExtractGroupsFromJson(nullJson));
        Assert.Empty(OidcService.ExtractGroupsFromJson(stringJson));
        Assert.Empty(OidcService.ExtractGroupsFromJson(arrayJson));
    }

    [Fact]
    public void ExtractGroups_FromArrayWithEmptyAndWhitespaceEntries_DropsThem()
    {
        // A misconfigured IdP can send empty strings or whitespace-only
        // entries. These would never legitimately match an allowed-group
        // name, but more importantly they'd waste log lines and confuse
        // admins reviewing forensics. Drop them at the parse layer.
        var json = Parse("""{ "groups": ["jellyfin-users", "", "   ", "admins"] }""");

        var result = OidcService.ExtractGroupsFromJson(json);

        Assert.Equal(new[] { "jellyfin-users", "admins" }, result);
    }
}
