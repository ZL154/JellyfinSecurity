using System;
using System.IO;
using MediaBrowser.Common.Configuration;
using NSubstitute;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests.Helpers;

/// <summary>
/// Builds an <see cref="IApplicationPaths"/> stub backed by a unique temp directory.
/// Used by services that touch <c>PluginConfigurationsPath</c> (CookieSigner,
/// TotpService) so each test gets isolated on-disk state.
/// </summary>
public static class TestApplicationPaths
{
    public static IApplicationPaths Create(out string sandboxRoot)
    {
        sandboxRoot = Path.Combine(
            Path.GetTempPath(),
            "jfsec-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sandboxRoot);

        var pluginConfigs = Path.Combine(sandboxRoot, "config", "plugins");
        Directory.CreateDirectory(pluginConfigs);

        var paths = Substitute.For<IApplicationPaths>();
        paths.PluginConfigurationsPath.Returns(pluginConfigs);
        paths.ProgramDataPath.Returns(sandboxRoot);
        return paths;
    }

    public static IApplicationPaths Create() => Create(out _);
}
