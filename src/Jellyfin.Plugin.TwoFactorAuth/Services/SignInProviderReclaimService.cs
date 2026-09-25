using System.Threading;
using System.Threading.Tasks;
using MediaBrowser.Common.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#213] On the first start after a reinstall, moves the accounts the uninstall
/// handed to Jellyfin's own provider back onto <see cref="TwoFactorAuthProvider"/>,
/// so the app passwords they already had work again. Does nothing when no
/// uninstall left a list behind. See <see cref="SignInProviderRestore"/>.
/// </summary>
public class SignInProviderReclaimService : IHostedService
{
    private readonly IUserManager _userManager;
    private readonly IApplicationPaths _paths;
    private readonly ILogger<SignInProviderReclaimService> _logger;

    public SignInProviderReclaimService(
        IUserManager userManager,
        IApplicationPaths paths,
        ILogger<SignInProviderReclaimService> logger)
    {
        _userManager = userManager;
        _paths = paths;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
        => SignInProviderRestore.ReclaimAfterReinstallAsync(_userManager, _paths, _logger);

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
