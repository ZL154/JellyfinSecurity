using System;
using System.Collections.Generic;
using System.IO;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Model.Plugins;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth;

public class Plugin : BasePlugin<PluginConfiguration>, IHasWebPages
{
    private readonly IApplicationHost _appHost;
    private readonly ILogger<Plugin> _logger;

    // [#213] IApplicationHost rather than IUserManager: the user manager is
    // resolved only when the plugin is uninstalled, the same lazy lookup
    // TwoFactorAuthProvider uses, so building the plugin never pulls the user
    // manager (and with it every authentication provider) into existence.
    public Plugin(
        IApplicationPaths applicationPaths,
        IXmlSerializer xmlSerializer,
        IApplicationHost appHost,
        ILogger<Plugin> logger)
        : base(applicationPaths, xmlSerializer)
    {
        _appHost = appHost;
        _logger = logger;
        Instance = this;

        // [#203] The zip ships the last RID's native libraries at the plugin
        // root (linux-musl-x64), which is the wrong build on almost every host,
        // and both the .NET runtime and QuestPDF look for them there. Put the
        // host RID's copies in place now, before the server takes a single
        // request, so nothing can map the wrong file and nothing is ever
        // rewritten underneath a live mapping. Never throws.
        NativeDependencyLayout.EnsureRidCorrectRootCopies(
            Path.GetDirectoryName(typeof(Plugin).Assembly.Location));
    }

    public static Plugin? Instance { get; private set; }

    /// <summary>
    /// [#213] Jellyfin calls this before it removes the plugin, while the server
    /// is still running. Accounts moved onto this plugin's sign-in provider are
    /// handed back first; left there, they could not sign in once the plugin
    /// was gone.
    /// </summary>
    public override void OnUninstalling()
    {
        SignInProviderRestore.RestoreOnUninstall(_appHost, _logger);
        base.OnUninstalling();
    }

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
