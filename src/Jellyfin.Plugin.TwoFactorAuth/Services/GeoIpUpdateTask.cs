using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Jellyfin.Plugin.TwoFactorAuth.Configuration;
using MediaBrowser.Model.Tasks;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#351] "Update GeoIP databases" under Dashboard, Scheduled Tasks. Jellyfin
/// finds it in the plugin's assembly and builds it with the plugin's
/// services. It does nothing while automatic GeoIP updates are off, which is
/// why every server can keep its default triggers: at startup, so a server
/// that was off over a month change or lost its data folder gets the
/// databases right away, and every 24 hours, counted by Jellyfin from the
/// last run. With the current release on disk a run makes no request.
/// </summary>
public sealed class GeoIpUpdateTask : IScheduledTask
{
    private readonly GeoIpDownloadService _downloads;
    private readonly Func<PluginConfiguration?> _configAccessor;

    public GeoIpUpdateTask(GeoIpDownloadService downloads)
        : this(downloads, () => Plugin.Instance?.Configuration)
    {
    }

    // Test seam, as in GeoIpService: tests hand in the configuration without
    // the Plugin singleton.
    internal GeoIpUpdateTask(GeoIpDownloadService downloads, Func<PluginConfiguration?> configAccessor)
    {
        _downloads = downloads;
        _configAccessor = configAccessor;
    }

    public string Name => "Update GeoIP databases";

    public string Key => "TwoFactorAuthGeoIpUpdate";

    public string Description => "Downloads the free DB-IP Lite databases that Jellyfin Security's suspicious-login and impossible-travel detection read, when automatic GeoIP updates are on in its settings.";

    public string Category => "Jellyfin Security";

    public async Task ExecuteAsync(IProgress<double> progress, CancellationToken cancellationToken)
    {
        var config = _configAccessor();
        if (config is null)
        {
            return;
        }

        var run = await _downloads.UpdateAsync(config, progress, cancellationToken).ConfigureAwait(false);
        if (run is { Failed: true })
        {
            // Jellyfin marks the run as failed and shows this message on the
            // task and in the activity log. Databases already on disk stay in
            // use.
            var reasons = run.Editions
                .Where(e => e.Outcome == GeoIpDownloadOutcome.Failed)
                .Select(e => $"{GeoIpDownloadService.Label(e.Edition)}: {e.Failure}");
            throw new InvalidOperationException("GeoIP update failed. " + string.Join("; ", reasons));
        }
    }

    public IEnumerable<TaskTriggerInfo> GetDefaultTriggers() => new[]
    {
        new TaskTriggerInfo { Type = TaskTriggerInfoType.StartupTrigger },
        new TaskTriggerInfo { Type = TaskTriggerInfoType.IntervalTrigger, IntervalTicks = TimeSpan.FromHours(24).Ticks },
    };
}
