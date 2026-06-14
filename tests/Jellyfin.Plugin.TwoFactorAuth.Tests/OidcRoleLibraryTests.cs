using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// [v2.5.10] (issue #65) Tests the pure role -> library mapping logic that
/// backs OIDC "Set library access from IdP groups/roles". This can't be
/// verified end-to-end without a groups-emitting IdP, so the mapping itself is
/// locked in here: union across matched roles, case-insensitive role match,
/// stale-id filtering, dedup, and the "no match -> no libraries" rule.
/// </summary>
public class OidcRoleLibraryTests
{
    private static ISet<string> Existing(params string[] ids)
        => new HashSet<string>(ids, StringComparer.OrdinalIgnoreCase);

    private static OidcRoleLibraryMapping Map(string role, string libs)
        => new() { Role = role, LibraryIds = libs };

    private static string[] Sorted(string[] a)
    {
        Array.Sort(a, StringComparer.Ordinal);
        return a;
    }

    [Fact]
    public void SingleMatchedRole_GrantsItsLibraries()
    {
        var mappings = new List<OidcRoleLibraryMapping> { Map("family", "lib-movies,lib-tv") };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "family" }, Existing("lib-movies", "lib-tv", "lib-4k"));
        Assert.Equal(new[] { "lib-movies", "lib-tv" }, Sorted(result));
    }

    [Fact]
    public void MultipleMatchedRoles_UnionOfLibraries()
    {
        var mappings = new List<OidcRoleLibraryMapping>
        {
            Map("family", "lib-movies"),
            Map("friends", "lib-tv"),
            Map("admins", "lib-4k"),
        };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "family", "friends" }, Existing("lib-movies", "lib-tv", "lib-4k"));
        Assert.Equal(new[] { "lib-movies", "lib-tv" }, Sorted(result));
    }

    [Fact]
    public void NoMatchingRole_ReturnsEmpty()
    {
        var mappings = new List<OidcRoleLibraryMapping> { Map("admins", "lib-4k") };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "guest" }, Existing("lib-4k"));
        Assert.Empty(result);
    }

    [Fact]
    public void RoleMatch_IsCaseInsensitive()
    {
        var mappings = new List<OidcRoleLibraryMapping> { Map("Family", "lib-movies") };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "FAMILY" }, Existing("lib-movies"));
        Assert.Equal(new[] { "lib-movies" }, result);
    }

    [Fact]
    public void StaleLibraryId_FilteredOut()
    {
        var mappings = new List<OidcRoleLibraryMapping> { Map("family", "lib-movies,lib-deleted") };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "family" }, Existing("lib-movies"));
        Assert.Equal(new[] { "lib-movies" }, result);
    }

    [Fact]
    public void OverlappingMappings_AreDeduped()
    {
        var mappings = new List<OidcRoleLibraryMapping>
        {
            Map("a", "lib-x"),
            Map("b", "lib-x,lib-y"),
        };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "a", "b" }, Existing("lib-x", "lib-y"));
        Assert.Equal(new[] { "lib-x", "lib-y" }, Sorted(result));
    }

    [Fact]
    public void BlankRoleMapping_IsSkipped()
    {
        var mappings = new List<OidcRoleLibraryMapping>
        {
            Map("   ", "lib-x"),
            Map("family", "lib-y"),
        };
        var result = OidcService.ComputeGrantedLibraryIds(
            mappings, new[] { "family", string.Empty }, Existing("lib-x", "lib-y"));
        Assert.Equal(new[] { "lib-y" }, result);
    }

    [Fact]
    public void EmptyGroups_ReturnsEmpty()
    {
        var mappings = new List<OidcRoleLibraryMapping> { Map("family", "lib-x") };
        Assert.Empty(OidcService.ComputeGrantedLibraryIds(
            mappings, Array.Empty<string>(), Existing("lib-x")));
    }

    [Fact]
    public void NullMappings_ReturnsEmpty()
    {
        Assert.Empty(OidcService.ComputeGrantedLibraryIds(
            null!, new[] { "family" }, Existing("lib-x")));
    }
}
