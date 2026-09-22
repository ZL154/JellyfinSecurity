using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Hands a completed sign-in to the GeoIP-backed detectors.
///
/// [#215] Both detectors shipped wired to nothing. SuspiciousLoginDetector and
/// ImpossibleTravelDetector were registered and fully implemented, but no code
/// path ever called ObserveAsync, so the databases loaded, Diagnostics
/// reported them Ok, the security score awarded the impossible-travel factor,
/// and no alert could fire. Routing both through one type keeps the wiring in
/// a single place instead of spreading the same fire-and-forget block over
/// every sign-in path.
///
/// Fire-and-forget by design: the notification I/O inside the detectors must
/// never sit in front of an authentication response, which is what the comment
/// on NotificationService.NotifySuspiciousLoginAsync already asked for. Each
/// detector guards its own preconditions (feature toggle, database loaded,
/// resolvable address), so this type only decides whether a sign-in is worth
/// observing at all, and it never lets a detector failure reach the caller.
/// </summary>
public class SignInObserver
{
    private readonly SuspiciousLoginDetector _suspicious;
    private readonly ImpossibleTravelDetector _travel;
    private readonly ILogger<SignInObserver> _logger;

    public SignInObserver(
        SuspiciousLoginDetector suspicious,
        ImpossibleTravelDetector travel,
        ILogger<SignInObserver> logger)
    {
        _suspicious = suspicious;
        _travel = travel;
        _logger = logger;
    }

    /// <summary>UTC time of the last sign-in handed to the detectors, or null
    /// when none has been. Lets Diagnostics show that the detectors are being
    /// reached, so "no alert" can be told apart from "never called" without
    /// reading the source.</summary>
    public DateTime? LastObservedAt { get; private set; }

    /// <summary>Whether this sign-in is worth resolving. Kept separate from
    /// the async work so the decision is directly testable.</summary>
    public static bool ShouldObserve(Guid userId, string? ip)
        => userId != Guid.Empty && !string.IsNullOrWhiteSpace(ip);

    /// <summary>Observe a completed sign-in. Returns immediately; the detectors
    /// run on a background task, in order, so the two writes to the same user
    /// record never race each other.</summary>
    /// <param name="userId">The user who signed in.</param>
    /// <param name="username">Display name for the notification text.</param>
    /// <param name="ip">The client address as resolved for this request, which
    /// behind a reverse proxy means the proxy-walked address and not the peer.
    /// Passing the peer here would make both detectors see one address for
    /// every remote user.</param>
    public void Observe(Guid userId, string? username, string? ip)
    {
        if (!ShouldObserve(userId, ip))
        {
            return;
        }

        LastObservedAt = DateTime.UtcNow;
        var name = username ?? string.Empty;
        var address = ip!;

        _ = Task.Run(async () =>
        {
            try
            {
                await _suspicious.ObserveAsync(userId, name, address).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Suspicious-login detector failed for {User}", name);
            }

            try
            {
                await _travel.ObserveAsync(userId, name, address).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[2FA] Impossible-travel detector failed for {User}", name);
            }
        });
    }
}
