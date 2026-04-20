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

    public override string Name => "Jellyfin Security";

    public override string Description => "Comprehensive Jellyfin security: TOTP & email 2FA, passkeys, OIDC/SSO sign-in (Google, GitHub, Authelia, Authentik, Keycloak, PocketID, Cloudflare Access, ...), brute-force IP banning, impossible-travel detection, per-user IP allowlist, device pairing, trusted browsers, and audit log.";

    public override Guid Id => new("94879a0c-da24-4eb1-aa06-f28b4b9333b1");

    public IEnumerable<PluginPageInfo> GetPages()
    {
        return new[]
        {
            new PluginPageInfo
            {
                Name = "TwoFactorAuth",
                EmbeddedResourcePath = GetType().Namespace + ".Pages.admin.html",
            },
        };
    }
}
