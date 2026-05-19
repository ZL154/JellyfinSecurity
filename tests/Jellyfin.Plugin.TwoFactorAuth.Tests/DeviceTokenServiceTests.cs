using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Models;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class DeviceTokenServiceTests
{
    [Fact]
    public void CreateDeviceToken_returns_url_safe_token_and_device_record()
    {
        var svc = new DeviceTokenService();
        var (token, device) = svc.CreateDeviceToken("device-1", "Bedroom TV");

        Assert.False(string.IsNullOrEmpty(token));
        Assert.DoesNotContain('+', token);
        Assert.DoesNotContain('/', token);
        Assert.DoesNotContain('=', token);

        Assert.Equal("device-1", device.DeviceId);
        Assert.Equal("Bedroom TV", device.DeviceName);
        Assert.False(string.IsNullOrEmpty(device.TokenHash));
        Assert.False(string.IsNullOrEmpty(device.Id));
        Assert.NotEqual(default, device.CreatedAt);
    }

    [Fact]
    public void CreateDeviceToken_produces_unique_tokens()
    {
        var svc = new DeviceTokenService();
        var (a, _) = svc.CreateDeviceToken("device-1", "TV");
        var (b, _) = svc.CreateDeviceToken("device-1", "TV");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void HashToken_is_deterministic()
    {
        var a = DeviceTokenService.HashToken("some-token-value");
        var b = DeviceTokenService.HashToken("some-token-value");
        Assert.Equal(a, b);
    }

    [Fact]
    public void HashToken_changes_when_input_changes()
    {
        var a = DeviceTokenService.HashToken("token-A");
        var b = DeviceTokenService.HashToken("token-B");
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ValidateToken_accepts_correct_token_and_device()
    {
        var svc = new DeviceTokenService();
        var (token, device) = svc.CreateDeviceToken("device-1", "TV");

        var ok = svc.ValidateToken(token, new List<TrustedDevice> { device }, "device-1", out var matched);

        Assert.True(ok);
        Assert.NotNull(matched);
        Assert.Equal("device-1", matched!.DeviceId);
    }

    [Fact]
    public void ValidateToken_rejects_wrong_deviceId_even_with_correct_token()
    {
        // The device-id binding is critical: a stolen token from device-1 must not
        // grant bypass when submitted by device-2, even if the token itself matches.
        var svc = new DeviceTokenService();
        var (token, device) = svc.CreateDeviceToken("device-1", "TV");

        var ok = svc.ValidateToken(token, new List<TrustedDevice> { device }, "device-2", out var matched);

        Assert.False(ok);
        Assert.Null(matched);
    }

    [Fact]
    public void ValidateToken_rejects_wrong_token_for_correct_device()
    {
        var svc = new DeviceTokenService();
        var (_, device) = svc.CreateDeviceToken("device-1", "TV");

        var ok = svc.ValidateToken("not-the-token", new List<TrustedDevice> { device }, "device-1", out var matched);

        Assert.False(ok);
        Assert.Null(matched);
    }

    [Fact]
    public void ValidateToken_rejects_when_device_list_is_empty()
    {
        var svc = new DeviceTokenService();
        var ok = svc.ValidateToken("any", new List<TrustedDevice>(), "device-1", out var matched);
        Assert.False(ok);
        Assert.Null(matched);
    }
}
