using System;
using Jellyfin.Plugin.TwoFactorAuth.Helpers;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

// [#216] A client that cannot open a browser (an LG webOS TV refuses the link
// and has no keyboard for the copy path) needs the authorize URL as something
// a phone can read. The flow is already device-based: the poll token, not the
// device, finishes the sign-in, so the consent may be granted on another
// screen. These tests pin the modal contract around that.
public class OidcDeviceFlowQrTests
{
    [Fact]
    public void The_sign_in_modal_shows_the_qr_when_the_server_sends_one()
    {
        var inject = ResourceReader.ReadEmbeddedText(
            "Jellyfin.Plugin.TwoFactorAuth.Pages.inject.js");

        Assert.NotNull(inject);

        // The QR is an optional third argument, so a modal opened before the
        // server answers (showOidcModal(name, '#', null)) renders without it.
        Assert.Contains("function showOidcModal(name, authUrl, qrBase64)", inject, StringComparison.Ordinal);
        Assert.Contains("showOidcModal(name, '#', null)", inject, StringComparison.Ordinal);

        // The field comes straight from Oidc/LoginInfo, tolerating either
        // casing because Jellyfin's JSON options differ between hosts.
        Assert.Contains("info.qrCodeBase64 || info.QrCodeBase64 || null", inject, StringComparison.Ordinal);

        // Rendered as a data URI, and only when there is something to render.
        Assert.Contains("data:image/png;base64,' + qrBase64", inject, StringComparison.Ordinal);
        Assert.Contains("tfa.login.oidc_qr_help", inject, StringComparison.Ordinal);
    }

    [Fact]
    public void The_qr_caption_exists_in_every_supported_language()
    {
        foreach (var lang in new[] { "en", "de", "es", "fr", "it", "ja", "pt", "zh" })
        {
            var json = ResourceReader.ReadEmbeddedText(
                $"Jellyfin.Plugin.TwoFactorAuth.Pages.translations.{lang}.json");

            Assert.NotNull(json);
            Assert.Contains("\"tfa.login.oidc_qr_help\"", json, StringComparison.Ordinal);
        }
    }
}
