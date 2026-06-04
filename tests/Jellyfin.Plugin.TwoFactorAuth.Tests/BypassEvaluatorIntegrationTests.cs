using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Integration-style tests for <see cref="BypassEvaluator.Evaluate"/> — the
/// decision logic that <c>TwoFactorEnforcementMiddleware</c> calls per request.
/// LAN-bypass paths require <c>Plugin.Instance</c> singleton state and are
/// covered by the dedicated CIDR + XFF parser tests instead.
/// </summary>
public class BypassEvaluatorIntegrationTests
{
    private static BypassEvaluator NewEvaluator()
        => new(Substitute.For<ILogger<BypassEvaluator>>());

    // ---- API key bypass ----------------------------------------------------

    [Fact]
    public void Evaluate_returns_apikey_bypass_for_matching_hashed_key()
    {
        var evaluator = NewEvaluator();
        const string rawKey = "raw-api-key-with-256-bits-of-entropy";
        var hashed = BypassEvaluator.HashApiKey(rawKey);
        var apiKeys = new List<ApiKeyEntry>
        {
            new() { Label = "test", KeyHash = hashed },
        };

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: null,
            deviceId: null,
            embyToken: rawKey,
            trustedDevices: new List<TrustedDevice>(),
            registeredDeviceIds: new List<string>(),
            apiKeys: apiKeys);

        Assert.True(result.IsBypassed);
        Assert.Equal("apikey", result.Reason);
    }

    [Fact]
    public void Evaluate_returns_no_bypass_for_non_matching_api_key()
    {
        var evaluator = NewEvaluator();
        var apiKeys = new List<ApiKeyEntry>
        {
            new() { Label = "test", KeyHash = BypassEvaluator.HashApiKey("the-real-key") },
        };

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: null,
            deviceId: null,
            embyToken: "wrong-key",
            trustedDevices: new List<TrustedDevice>(),
            registeredDeviceIds: new List<string>(),
            apiKeys: apiKeys);

        Assert.False(result.IsBypassed);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Evaluate_supports_legacy_plaintext_api_key_storage()
    {
        // Pre-v1.3.3 API keys were stored as plaintext in Key. The evaluator
        // hashes them on-the-fly to maintain compatibility until upgrade.
        var evaluator = NewEvaluator();
        const string rawKey = "legacy-plaintext-key";
        var apiKeys = new List<ApiKeyEntry>
        {
            new() { Label = "legacy", Key = rawKey },
        };

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: null,
            deviceId: null,
            embyToken: rawKey,
            trustedDevices: new List<TrustedDevice>(),
            registeredDeviceIds: new List<string>(),
            apiKeys: apiKeys);

        Assert.True(result.IsBypassed);
        Assert.Equal("apikey", result.Reason);
    }

    // ---- Trusted device token bypass ---------------------------------------

    [Fact]
    public void Evaluate_returns_trusted_device_bypass_for_matching_token_and_deviceId()
    {
        var evaluator = NewEvaluator();
        var tokenService = new DeviceTokenService();
        var (rawToken, device) = tokenService.CreateDeviceToken("device-42", "Living Room");

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: rawToken,
            deviceId: "device-42",
            embyToken: null,
            trustedDevices: new List<TrustedDevice> { device },
            registeredDeviceIds: new List<string>(),
            apiKeys: new List<ApiKeyEntry>());

        Assert.True(result.IsBypassed);
        Assert.Equal("trusted_device", result.Reason);
    }

    [Fact]
    public void Evaluate_rejects_trusted_device_token_when_deviceId_differs()
    {
        // Stolen-token-from-device-A-replayed-on-device-B scenario: must NOT bypass.
        var evaluator = NewEvaluator();
        var tokenService = new DeviceTokenService();
        var (rawToken, device) = tokenService.CreateDeviceToken("device-42", "Living Room");

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: rawToken,
            deviceId: "device-99",
            embyToken: null,
            trustedDevices: new List<TrustedDevice> { device },
            registeredDeviceIds: new List<string>(),
            apiKeys: new List<ApiKeyEntry>());

        Assert.False(result.IsBypassed);
    }

    [Fact]
    public void Evaluate_rejects_trusted_device_when_token_is_wrong()
    {
        var evaluator = NewEvaluator();
        var tokenService = new DeviceTokenService();
        var (_, device) = tokenService.CreateDeviceToken("device-42", "Living Room");

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: "not-the-token",
            deviceId: "device-42",
            embyToken: null,
            trustedDevices: new List<TrustedDevice> { device },
            registeredDeviceIds: new List<string>(),
            apiKeys: new List<ApiKeyEntry>());

        Assert.False(result.IsBypassed);
    }

    // ---- Registered device ID bypass (native client pairing) ---------------
    // v2.5.6: default-off bypass behavior is the secure baseline. The
    // opt-in path (admin sets BareDeviceIdBypassEnabled=true) is covered by
    // integration testing against a running server, not these unit tests.

    [Fact]
    public void Evaluate_no_registered_device_bypass_for_matching_id_when_default_off()
    {
        var evaluator = NewEvaluator();

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: null,
            deviceId: "swiftfin-uuid-12345",
            embyToken: null,
            trustedDevices: new List<TrustedDevice>(),
            registeredDeviceIds: new List<string> { "swiftfin-uuid-12345" },
            apiKeys: new List<ApiKeyEntry>());

        // SECURITY [v2.5.6] (ext review bare-DeviceId): the registered-device
        // bypass is now gated on PluginConfiguration.BareDeviceIdBypassEnabled
        // (default false). In tests Plugin.Instance is null so the gate
        // resolves to false-by-default — bypass no longer fires. Bare
        // DeviceId is client-supplied and lacks integrity binding; admins
        // re-enable explicitly to opt into the legacy convenience.
        Assert.False(result.IsBypassed);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Evaluate_no_registered_device_bypass_when_bareDeviceId_default_off()
    {
        // Tizen webview deviceId pattern: stable base64 prefix + "|<millis>".
        // Even with a matching prefix-normalised id in registered list, the
        // v2.5.6 default closes the bypass — clients must re-prove via
        // signed trusted-device cookie or use the opt-in flag.
        var evaluator = NewEvaluator();

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: null,
            deviceId: "VGhpc0lzQVZlcnlMb25nQmFzZTY0SXNoUHJlZml4|1700099999999",
            embyToken: null,
            trustedDevices: new List<TrustedDevice>(),
            registeredDeviceIds: new List<string>
            {
                "VGhpc0lzQVZlcnlMb25nQmFzZTY0SXNoUHJlZml4|1700000000000",
            },
            apiKeys: new List<ApiKeyEntry>());

        Assert.False(result.IsBypassed);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Evaluate_no_bypass_when_no_paths_match()
    {
        var evaluator = NewEvaluator();

        var result = evaluator.Evaluate(
            remoteIp: "203.0.113.5",
            forwardedFor: null,
            twoFactorToken: null,
            deviceId: "unknown-device",
            embyToken: "unknown-token",
            trustedDevices: new List<TrustedDevice>(),
            registeredDeviceIds: new List<string>(),
            apiKeys: new List<ApiKeyEntry>());

        Assert.False(result.IsBypassed);
        Assert.Null(result.Reason);
    }
}
