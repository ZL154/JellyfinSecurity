using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Loader;
using Jellyfin.Database.Implementations.Entities;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using MediaBrowser.Common;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Common.Plugins;
using MediaBrowser.Controller.Authentication;
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

    /// <summary>Checks whether the blank-password gate and the current provider
    /// assignment rule out ordinary password sign-in for this resolved account.</summary>
    internal bool AccountPasswordSignInUnavailable(User? user)
    {
        try
        {
            var config = Configuration;
            if (!config.Enabled || !config.BlockEmptyPasswordLogin || user is null || !string.IsNullOrEmpty(user.Password))
            {
                return false;
            }

            var providerId = user.AuthenticationProviderId;
            if (!string.Equals(providerId, SignInProviderRestore.PluginProviderId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // The host omits failed activations from GetExports. Inspect every
            // declared type so a later password attempt cannot pick another delegate.
            var providers = _appHost.GetExportTypes<IAuthenticationProvider>().ToList();
            if (!providers.Remove(typeof(TwoFactorAuthProvider)))
            {
                return false;
            }

            var serverAssembly = AssemblyLoadContext.Default.Assemblies.SingleOrDefault(
                assembly => assembly.GetName().Name == "Jellyfin.Server.Implementations");
            if (serverAssembly is null
                || serverAssembly.GetType(SignInProviderRestore.JellyfinDefaultProviderId) is not Type passwordProvider
                || passwordProvider.Assembly != serverAssembly
                || !providers.Remove(passwordProvider))
            {
                return false;
            }

            // On both supported host lines the password provider is always enabled
            // and InvalidAuthProvider is always disabled. Any other entry, including
            // a duplicate, leaves the delegate uncertain.
            return providers.Count == 0
                || (providers is [Type other]
                    && other.Assembly == serverAssembly
                    && other.FullName == "Jellyfin.Server.Implementations.Users.InvalidAuthProvider");
        }
        catch (Exception)
        {
            // Incomplete account or provider evidence must keep the existing challenge.
            return false;
        }
    }

    /// <summary>
    /// [#213] Jellyfin calls this before it removes the plugin, while the server
    /// is still running. Accounts moved onto this plugin's sign-in provider are
    /// handed back first; left there, they could not sign in once the plugin
    /// was gone. They are also listed, so a reinstall takes them back
    /// (<see cref="SignInProviderReclaimService"/>).
    /// </summary>
    public override void OnUninstalling()
    {
        SignInProviderRestore.RestoreOnUninstall(_appHost, ApplicationPaths, _logger);
        base.OnUninstalling();
    }

    /// <summary>
    /// [#268] Jellyfin's POST /Plugins/{id}/Configuration lands here with what
    /// the admin page sent, and the page only ever held
    /// <see cref="ConfigSecrets.SavedMarker"/> for a saved secret
    /// (<see cref="PluginConfigSecretsFilter"/>). Put the stored values back
    /// before the save replaces them.
    /// </summary>
    public override void UpdateConfiguration(BasePluginConfiguration configuration)
    {
        if (configuration is PluginConfiguration incoming)
        {
            // [#345] Inspect the exact object Jellyfin materialized, before secrets
            // or live configuration are changed. No competing parse of the body.
            if (Configuration.PasskeysEnabled && !incoming.PasskeysEnabled)
            {
                _appHost.Resolve<PasskeyDisableGuard>()
                    .EnsureCanApplyAsync(Configuration, incoming).GetAwaiter().GetResult();
            }
            ConfigSecrets.KeepSaved(incoming, Configuration);
        }

        base.UpdateConfiguration(configuration);
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
