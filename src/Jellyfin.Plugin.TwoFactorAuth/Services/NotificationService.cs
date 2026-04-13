using System.Net.Http;
using System.Net.Http.Json;
using System.Text;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

public class NotificationService
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<NotificationService> _logger;

    public NotificationService(IHttpClientFactory httpClientFactory, ILogger<NotificationService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    public async Task NotifyLoginAttemptAsync(string username, string remoteIp, string deviceName, bool requiresTwoFactor)
    {
        var title = "2FA Login Attempt";
        var message = $"2FA login attempt from {username} at {remoteIp} ({deviceName})";
        await SendToAllBackendsAsync(title, message).ConfigureAwait(false);
    }

    public async Task NotifyFailedAttemptsAsync(string username, string remoteIp, int attemptCount)
    {
        var title = "2FA Failed Attempts Warning";
        var message = $"Warning: {attemptCount} failed 2FA attempts for {username} from {remoteIp}";
        await SendToAllBackendsAsync(title, message).ConfigureAwait(false);
    }

    public async Task NotifyPairingRequestAsync(string username, string deviceName, string pairingCode)
    {
        var title = "TV Pairing Request";
        var message = $"TV pairing request from {username} ({deviceName}). Code: {pairingCode}";
        await SendToAllBackendsAsync(title, message).ConfigureAwait(false);
    }

    public async Task NotifyPairingCompletedAsync(string username, string deviceName, bool approved)
    {
        var title = approved ? "TV Pairing Approved" : "TV Pairing Denied";
        var message = approved
            ? $"TV pairing approved for {username} ({deviceName})"
            : $"TV pairing denied for {username} ({deviceName})";
        await SendToAllBackendsAsync(title, message).ConfigureAwait(false);
    }

    private async Task SendToAllBackendsAsync(string title, string message)
    {
        var config = Plugin.Instance!.Configuration;

        // Ntfy
        if (!string.IsNullOrWhiteSpace(config.NtfyUrl) && !string.IsNullOrWhiteSpace(config.NtfyTopic))
        {
            try
            {
                var client = _httpClientFactory.CreateClient("TwoFactorAuth");
                using var request = new HttpRequestMessage(HttpMethod.Post, config.NtfyUrl);
                request.Headers.TryAddWithoutValidation("X-Title", title);
                request.Headers.TryAddWithoutValidation("X-Topic", config.NtfyTopic);
                request.Content = new StringContent(message, Encoding.UTF8, "text/plain");
                using var response = await client.SendAsync(request).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                _logger.LogDebug("Ntfy notification sent: {Title}", title);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send Ntfy notification for '{Title}'", title);
            }
        }

        // Gotify
        if (!string.IsNullOrWhiteSpace(config.GotifyUrl) && !string.IsNullOrWhiteSpace(config.GotifyAppToken))
        {
            try
            {
                var client = _httpClientFactory.CreateClient("TwoFactorAuth");
                var url = $"{config.GotifyUrl.TrimEnd('/')}/message?token={config.GotifyAppToken}";
                var payload = new { title, message, priority = 5 };
                using var response = await client.PostAsJsonAsync(url, payload).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                _logger.LogDebug("Gotify notification sent: {Title}", title);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send Gotify notification for '{Title}'", title);
            }
        }

        // Email
        if (config.NotifyEmailAddresses.Length > 0)
        {
            _logger.LogInformation(
                "Email notification would be sent to {Count} address(es) for '{Title}': {Message}",
                config.NotifyEmailAddresses.Length,
                title,
                message);
        }
    }
}
