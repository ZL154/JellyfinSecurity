using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Jellyfin.Extensions.Json;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using NSubstitute;
using NSubstitute.ReturnsExtensions;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[Collection("SignInPolicy")]
public class PasskeyDisableSaveTests
{
    [Theory]
    [InlineData("94879a0c-da24-4eb1-aa06-f28b4b9333b1")]
    [InlineData("94879a0cda244eb1aa06f28b4b9333b1")]
    public async Task A_dependent_user_refuses_the_whole_save_with_a_sorted_conflict_body(string pluginId)
    {
        using var api = new PasskeyDisableSaveApi();
        await api.AddAsync("Zoe");
        var first = await api.AddAsync("alice");
        var before = JsonSerializer.Serialize(api.Config);
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        incoming.SmtpHost = "must-not-be-saved.example.test";
        using var response = await api.Client.PostAsJsonAsync("/Plugins/" + pluginId + "/Configuration", incoming, JsonDefaults.Options);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var users = body.RootElement.GetProperty("users").EnumerateArray().ToArray();
        Assert.Equal(new[] { "alice", "Zoe" }, users.Select(x => x.GetProperty("name").GetString()));
        Assert.Equal(first, users[0].GetProperty("id").GetGuid());
        var message = body.RootElement.GetProperty("message").GetString()!;
        Assert.Contains("authenticator app", message);
        Assert.Contains("Reset 2FA (full wipe)", message);
        Assert.Contains("Users tab", message);
        Assert.Equal(before, JsonSerializer.Serialize(api.Config));
        Assert.Empty(await api.Store.GetAuditLogAsync());
    }

    // Opted-out passkeys (PasskeyRequiresSecondFactor false), so only the
    // challenge inventory and the self-service factors decide. A recovery code
    // or a Telegram chat answers the challenge but is not a factor the Setup
    // page step-up asks for, so the switch would drop that step-up: refused.
    [Theory]
    [InlineData("totp", false, true)]
    [InlineData("unverified", false, false)]
    [InlineData("address", true, true)]
    [InlineData("address", false, false)]
    [InlineData("none", true, false)]
    [InlineData("recovery", false, false)]
    [InlineData("spent-recovery", false, false)]
    [InlineData("telegram", true, false)]
    [InlineData("telegram", false, false)]
    [InlineData("sso", false, false)]
    public async Task The_guard_reads_the_new_configuration_and_the_challenge_inventory(string other, bool deliveryEnabled, bool allowed)
    {
        using var api = new PasskeyDisableSaveApi();
        var id = await api.AddAsync("alice", other);
        api.Config.EmailOtpEnabled = true;
        api.Config.SetUserEmail(id.ToString("N"), other == "address" ? "alice@example.test" : string.Empty);
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        incoming.EmailOtpEnabled = deliveryEnabled;
        using var response = await api.SaveAsync(incoming);
        Assert.Equal(allowed ? HttpStatusCode.NoContent : HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(!allowed, api.Config.PasskeysEnabled);
        Assert.Equal(!allowed || deliveryEnabled, api.Config.EmailOtpEnabled);
        var stored = await api.Store.GetUserDataAsync(id);
        Assert.Single(stored.Passkeys);
        Assert.False(stored.PasskeyRequiresSecondFactor);
    }

    // The email code answers the challenge but never asks for it: with the
    // passkey as the only reason, turning passkeys off would leave password
    // sign-in with no second factor, unless the enforcement scope covers the
    // user.
    [Theory]
    [InlineData(EnforcementScope.Optional, false, false)]
    [InlineData(EnforcementScope.Admins, false, false)]
    [InlineData(EnforcementScope.Admins, true, true)]
    [InlineData(EnforcementScope.All, false, true)]
    public async Task A_passkey_that_alone_makes_password_sign_in_ask_for_a_second_factor_refuses_the_switch(
        EnforcementScope scope, bool admin, bool allowed)
    {
        using var api = new PasskeyDisableSaveApi();
        var id = await api.AddAsync("alice", "address", secondFactor: true, admin: admin);
        api.Config.EmailOtpEnabled = true;
        api.Config.SetUserEmail(id.ToString("N"), "alice@example.test");
        api.Config.EnforcementScope = scope;
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        using var response = await api.SaveAsync(incoming);
        Assert.Equal(allowed ? HttpStatusCode.NoContent : HttpStatusCode.Conflict, response.StatusCode);
        Assert.Equal(!allowed, api.Config.PasskeysEnabled);
        if (allowed) return;
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("alice", Assert.Single(body.RootElement.GetProperty("users").EnumerateArray()).GetProperty("name").GetString());
        Assert.Contains("rely on a passkey for their second factor", body.RootElement.GetProperty("message").GetString());
    }

    [Fact]
    public async Task No_dependents_allows_disabling_and_unchanged_off_or_reenabled_saves_are_never_blocked()
    {
        using var api = new PasskeyDisableSaveApi();
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        using var disabled = await api.SaveAsync(incoming);
        Assert.Equal(HttpStatusCode.NoContent, disabled.StatusCode);
        await api.AddAsync("late-user");
        incoming = api.Copy();
        incoming.SmtpHost = "saved.example.test";
        using var otherChange = await api.SaveAsync(incoming);
        Assert.Equal(HttpStatusCode.NoContent, otherChange.StatusCode);
        Assert.Equal("saved.example.test", api.Config.SmtpHost);
        incoming = api.Copy();
        incoming.PasskeysEnabled = true;
        using var enabled = await api.SaveAsync(incoming);
        Assert.Equal(HttpStatusCode.NoContent, enabled.StatusCode);
        Assert.True(api.Config.PasskeysEnabled);
    }

    [Fact]
    public async Task Deleted_users_do_not_block_a_switch_the_admin_cannot_migrate_in_the_Users_tab()
    {
        using var api = new PasskeyDisableSaveApi();
        var id = await api.AddAsync("deleted-user");
        api.Users.GetUserById(id).ReturnsNull();
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        using var response = await api.SaveAsync(incoming);
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Single((await api.Store.GetUserDataAsync(id)).Passkeys);
    }

    [Fact]
    public async Task Step_up_answers_before_the_body_is_read_or_the_turn_off_guard_runs()
    {
        using var api = new PasskeyDisableSaveApi();
        await api.AddAsync("alice");
        api.Config.StepUpLevel = StepUpLevel.AllConfigChanges;
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        using var denied = await api.SaveAsync(incoming);
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        using var body = JsonDocument.Parse(await denied.Content.ReadAsStringAsync());
        Assert.True(body.RootElement.GetProperty("stepUpRequired").GetBoolean());
        using var malformed = new StringContent("not-json", Encoding.UTF8, "application/json");
        using var stillDenied = await api.Client.PostAsync(PasskeyDisableSaveApi.SavePath, malformed);
        Assert.Equal(HttpStatusCode.Forbidden, stillDenied.StatusCode);
        api.Challenges.MarkStepUpVerified(api.Admin);
        using var conflict = await api.SaveAsync(incoming);
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.True(api.Config.PasskeysEnabled);
    }

    [Fact]
    public async Task The_guard_uses_the_configuration_materialized_by_the_action()
    {
        using var api = new PasskeyDisableSaveApi();
        await api.AddAsync("alice");
        // Jellyfin accepts the PascalCase setting and ignores the camelCase lookalike.
        using var content = new StringContent("{\"PasskeysEnabled\":false,\"passkeysEnabled\":true}", Encoding.UTF8, "application/json");
        using var response = await api.Client.PostAsync(PasskeyDisableSaveApi.SavePath, content);
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.True(api.Config.PasskeysEnabled);
    }
}
