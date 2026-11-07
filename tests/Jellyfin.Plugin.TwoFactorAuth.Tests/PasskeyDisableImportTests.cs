using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

[Collection("SignInPolicy")]
public class PasskeyDisableImportTests
{
    private static string Envelope(PluginConfiguration config, bool encrypted, List<UserTwoFactorData>? users = null)
    {
        object payload = encrypted
            ? ConfigExportService.EncryptPayloadForTest(JsonSerializer.Serialize(new FullExportPayload { Configuration = config, Users = users ?? new() }), "test-phrase")
            : new ConfigExportPayload { Configuration = config };
        return JsonSerializer.Serialize(new ExportEnvelope { Encrypted = encrypted, Payload = payload });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Dependent_users_refuse_config_and_full_imports_before_any_write(bool encrypted)
    {
        using var api = new PasskeyDisableSaveApi();
        var id = await api.AddAsync("alice");
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        incoming.SmtpHost = "must-not-be-saved.example.test";
        var before = JsonSerializer.Serialize(api.Config);
        var beforeData = JsonSerializer.Serialize(await api.Store.GetUserDataAsync(id));
        var replacement = new UserTwoFactorData { UserId = id, Passkeys = { new PasskeyCredential { Id = "replacement" } } };
        var result = await api.Export.ImportAsync(Envelope(incoming, encrypted, new() { replacement }), encrypted ? "test-phrase" : null);
        Assert.False(result.Success);
        Assert.Contains("alice", result.Error!);
        Assert.Contains("authenticator app", result.Error!);
        Assert.Contains("Reset 2FA (full wipe)", result.Error!);
        Assert.Equal(before, JsonSerializer.Serialize(api.Config));
        Assert.Equal(beforeData, JsonSerializer.Serialize(await api.Store.GetUserDataAsync(id)));
    }

    [Theory]
    [InlineData(true, true)]
    [InlineData(false, false)]
    public async Task Import_uses_the_incoming_delivery_setting(bool enabled, bool allowed)
    {
        using var api = new PasskeyDisableSaveApi();
        var id = await api.AddAsync("alice");
        api.Config.EmailOtpEnabled = true;
        api.Config.SetUserEmail(id.ToString("N"), "alice@example.test");
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        incoming.EmailOtpEnabled = enabled;
        var result = await api.Export.ImportAsync(Envelope(incoming, false), null);
        Assert.Equal(allowed, result.Success);
        Assert.Equal(!allowed, api.Config.PasskeysEnabled);
    }

    [Fact]
    public async Task Full_import_checks_the_effective_replacement_records()
    {
        using var api = new PasskeyDisableSaveApi();
        var id = await api.AddAsync("alice", "totp");
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        var replacement = new UserTwoFactorData { UserId = id, Passkeys = { new PasskeyCredential { Id = "replacement" } } };
        var refused = await api.Export.ImportAsync(Envelope(incoming, true, new() { replacement }), "test-phrase");
        Assert.False(refused.Success);
        Assert.True((await api.Store.GetUserDataAsync(id)).TotpVerified);
        replacement.TotpEnabled = true;
        replacement.TotpVerified = true;
        var accepted = await api.Export.ImportAsync(Envelope(incoming, true, new() { replacement }), "test-phrase");
        Assert.True(accepted.Success);
        Assert.False(api.Config.PasskeysEnabled);
    }

    [Fact]
    public async Task An_import_with_no_dependents_can_turn_passkeys_off()
    {
        using var api = new PasskeyDisableSaveApi();
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        Assert.True((await api.Export.ImportAsync(Envelope(incoming, false), null)).Success);
        Assert.False(api.Config.PasskeysEnabled);
    }

    [Fact]
    public async Task Exports_carry_the_flag_and_off_to_off_and_off_to_on_imports_remain_allowed()
    {
        using var api = new PasskeyDisableSaveApi();
        api.Config.PasskeysEnabled = false;
        await api.AddAsync("alice");
        var exported = (ConfigExportPayload)(await api.Export.BuildConfigOnlyExportAsync()).Payload;
        Assert.False(exported.Configuration.PasskeysEnabled);
        var full = await api.Export.BuildFullExportAsync("test-phrase");
        var restored = JsonSerializer.Deserialize<FullExportPayload>(ConfigExportService.DecryptPayloadForTest((string)full.Payload, "test-phrase"))!;
        Assert.False(restored.Configuration.PasskeysEnabled);
        Assert.Single(Assert.Single(restored.Users).Passkeys);
        Assert.False(Assert.Single(restored.Users).PasskeyRequiresSecondFactor);
        var incoming = api.Copy();
        Assert.True((await api.Export.ImportAsync(Envelope(incoming, false), null)).Success);
        incoming.PasskeysEnabled = true;
        Assert.True((await api.Export.ImportAsync(Envelope(incoming, false), null)).Success);
        Assert.True(api.Config.PasskeysEnabled);
    }

    [Fact]
    public async Task The_import_route_steps_up_first_and_then_returns_the_failure_text_and_names()
    {
        using var api = new PasskeyDisableSaveApi();
        await api.AddAsync("alice");
        api.Config.StepUpLevel = StepUpLevel.AllConfigChanges;
        var incoming = api.Copy();
        incoming.PasskeysEnabled = false;
        var envelope = Envelope(incoming, false);
        using var denied = await api.Client.PostAsJsonAsync("/TwoFactorAuth/Config/Import", new { envelope });
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
        api.Challenges.MarkStepUpVerified(api.Admin);
        using var refused = await api.Client.PostAsJsonAsync("/TwoFactorAuth/Config/Import", new { envelope });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        using var body = JsonDocument.Parse(await refused.Content.ReadAsStringAsync());
        Assert.Contains("alice", body.RootElement.GetProperty("message").GetString()!);
        Assert.True(api.Config.PasskeysEnabled);
    }
}
