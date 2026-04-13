using System;
using System.Collections.Generic;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;

namespace Jellyfin.Plugin.TwoFactorAuth;

public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    public Plugin(IApplicationPaths applicationPaths, IXmlSerializer xmlSerializer)
        : base(applicationPaths, xmlSerializer)
    {
        Instance = this;
    }

    public static Plugin? Instance { get; private set; }

    public override string Name => "Two-Factor Authentication";

    public override string Description => "Native two-factor authentication for Jellyfin with TOTP, email OTP, device pairing, and trusted device support.";

    public override Guid Id => new("a1b2c3d4-e5f6-7890-abcd-ef1234567890");

    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = "TwoFactorAuthChallenge",
                EmbeddedResourcePath = $"{GetType().Namespace}.Pages.challenge.html",
            },
            new PluginPageInfo
            {
                Name = "TwoFactorAuthSetup",
                EmbeddedResourcePath = $"{GetType().Namespace}.Pages.setup.html",
            },
            new PluginPageInfo
            {
                Name = "TwoFactorAuthAdmin",
                EmbeddedResourcePath = $"{GetType().Namespace}.Pages.admin.html",
            },
        };
    }
}
