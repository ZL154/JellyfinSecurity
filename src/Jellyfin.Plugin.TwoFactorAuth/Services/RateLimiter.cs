using System.Collections.Concurrent;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Per-IP sliding-window rate limiter. Used on /TwoFactorAuth/Verify and
/// /TwoFactorAuth/Authenticate to defend against brute force on the OTP code
/// space (a million 6-digit codes is small enough that an unrestricted attacker
/// could exhaust it in minutes without rate limiting).
/// </summary>
public class RateLimiter
{
    private readonly ConcurrentDictionary<string, List<DateTime>> _hits = new();

    /// <summary>
    /// Returns true if the request from this key (IP) should be allowed.
    /// Returns false (and the time until next allowed attempt) if rate-limited.
    /// </summary>
    public (bool allowed, int retryAfterSeconds) CheckAndRecord(string key, int maxRequests, TimeSpan window)
    {
        var now = DateTime.UtcNow;
        var cutoff = now - window;

        var bucket = _hits.GetOrAdd(key, _ => new List<DateTime>());
        lock (bucket)
        {
            bucket.RemoveAll(t => t < cutoff);

            if (bucket.Count >= maxRequests)
            {
                var oldest = bucket[0];
                var retryAfter = Math.Max(1, (int)((oldest + window) - now).TotalSeconds);
                return (false, retryAfter);
            }

            bucket.Add(now);
            return (true, 0);
        }
    }

    /// <summary>
    /// Reset the counter for a key (e.g., after a successful login).
    /// </summary>
    public void Reset(string key)
    {
        _hits.TryRemove(key, out _);
    }
}
