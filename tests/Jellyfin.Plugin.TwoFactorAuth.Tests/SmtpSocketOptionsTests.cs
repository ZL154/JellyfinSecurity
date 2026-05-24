using Jellyfin.Plugin.TwoFactorAuth.Services;
using MailKit.Security;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>
/// Issue #29: System.Net.Mail.SmtpClient silently failed on port 465 because
/// EnableSsl=true sends EHLO in plaintext while the server expects an SSL
/// ClientHello (Implicit TLS). MailKit picks the right transport per port —
/// these tests pin that mapping so a future refactor can't accidentally send
/// STARTTLS to a 465 server again.
/// </summary>
public class SmtpSocketOptionsTests
{
    [Fact]
    public void PickSocketOptions_Port465_UsesSslOnConnect()
    {
        // The whole reason this code exists. Port 465 = Implicit TLS / SMTPS.
        // The server expects a TLS handshake BEFORE any SMTP commands.
        Assert.Equal(SecureSocketOptions.SslOnConnect,
            EmailOtpService.PickSocketOptions(port: 465, useSsl: true));
    }

    [Fact]
    public void PickSocketOptions_Port587_UsesStartTls()
    {
        // Standard submission port — plaintext greeting, then STARTTLS upgrade.
        Assert.Equal(SecureSocketOptions.StartTls,
            EmailOtpService.PickSocketOptions(port: 587, useSsl: true));
    }

    [Fact]
    public void PickSocketOptions_Port25_UsesStartTlsWhenAvailable()
    {
        // Legacy plain SMTP. Some relays advertise STARTTLS, some don't.
        // StartTlsWhenAvailable upgrades opportunistically without hard-failing
        // on servers that don't advertise it.
        Assert.Equal(SecureSocketOptions.StartTlsWhenAvailable,
            EmailOtpService.PickSocketOptions(port: 25, useSsl: true));
    }

    [Fact]
    public void PickSocketOptions_UseSslFalse_AlwaysNone()
    {
        // User explicitly opted out of TLS — e.g. for a local MailHog
        // / Mailpit container during dev. Don't second-guess them.
        Assert.Equal(SecureSocketOptions.None,
            EmailOtpService.PickSocketOptions(port: 465, useSsl: false));
        Assert.Equal(SecureSocketOptions.None,
            EmailOtpService.PickSocketOptions(port: 587, useSsl: false));
        Assert.Equal(SecureSocketOptions.None,
            EmailOtpService.PickSocketOptions(port: 25, useSsl: false));
    }

    [Fact]
    public void PickSocketOptions_NonStandardPortWithSsl_FallsBackToOpportunistic()
    {
        // Mailgun / SendGrid use 2525 when 25 is blocked. Cloud providers
        // sometimes use 2526 etc. We don't have port-specific knowledge for
        // these, so opportunistic STARTTLS is the safest default.
        Assert.Equal(SecureSocketOptions.StartTlsWhenAvailable,
            EmailOtpService.PickSocketOptions(port: 2525, useSsl: true));
        Assert.Equal(SecureSocketOptions.StartTlsWhenAvailable,
            EmailOtpService.PickSocketOptions(port: 1025, useSsl: true));
    }
}
