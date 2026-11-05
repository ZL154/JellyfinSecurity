using Jellyfin.Data.Events.Users;
using MediaBrowser.Controller.Events;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>Clears the plugin's temporary lockout after Jellyfin completes a credential change.</summary>
public sealed class CredentialChangeLockoutConsumer : IEventConsumer<UserPasswordChangedEventArgs>
{
    private readonly UserTwoFactorStore _store;
    private readonly ILogger<CredentialChangeLockoutConsumer> _logger;

    public CredentialChangeLockoutConsumer(UserTwoFactorStore store, ILogger<CredentialChangeLockoutConsumer> logger)
    {
        _store = store;
        _logger = logger;
    }

    public async Task OnEvent(UserPasswordChangedEventArgs eventArgs)
    {
        try
        {
            var data = await _store.GetUserDataAsync(eventArgs.Argument.Id).ConfigureAwait(false);
            // Unknown users have empty state. Avoid creating a file when there is nothing to clear.
            if (data.FailedAttemptCount == 0 && data.LockoutEnd is null)
            {
                return;
            }

            await _store.ResetFailedAttemptsAsync(eventArgs.Argument.Id).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Jellyfin has already saved the change. A store failure must not report it as failed,
            // and exception details can contain identity data or paths to per-user records.
            _logger.LogError("[2FA] Could not clear temporary sign-in lockout after a completed credential change.");
        }
    }
}
