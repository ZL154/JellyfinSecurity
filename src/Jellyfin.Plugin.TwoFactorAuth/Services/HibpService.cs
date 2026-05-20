using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// v2.4: Have I Been Pwned password-breach check using the k-anonymity API.
///
/// Privacy model: only the first 5 hex chars of SHA-1(password) are sent over
/// the network (~1024 possible prefixes, so the API server sees no useful
/// information about the actual password). The API returns a list of all
/// known SHA-1 suffixes starting with that prefix; we look up the rest of
/// our hash locally to decide if the password is breached.
///
/// Fails open: any network / parse failure returns -1 ("unknown") rather
/// than blocking the user. We're an opt-in advisory layer, not gatekeeping.
/// </summary>
public class HibpService
{
    private const string HibpRangeBaseUrl = "https://api.pwnedpasswords.com/range/";

    private readonly HttpClient _http;
    private readonly ILogger<HibpService> _logger;

    public HibpService(HttpClient http, ILogger<HibpService> logger)
    {
        _http = http;
        _logger = logger;
        if (_http.Timeout == System.Threading.Timeout.InfiniteTimeSpan
            || _http.Timeout > TimeSpan.FromSeconds(5))
        {
            // Default Jellyfin HttpClient timeout is too long for a sign-in
            // fast-path. HIBP API is fast; if it's slow, fail open instead
            // of blocking the user's login on it.
            _http.Timeout = TimeSpan.FromSeconds(3);
        }
    }

    /// <summary>Returns: positive = breach count, 0 = clean, -1 = check failed.
    /// Never throws. Never blocks longer than the configured HttpClient timeout
    /// (3 seconds by default).</summary>
    public async Task<int> CheckPasswordAsync(string? password, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(password))
        {
            return 0;
        }

        string hash;
        try
        {
            hash = ComputeSha1Hex(password);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[HIBP] SHA-1 compute failed; treating as unknown");
            return -1;
        }

        var prefix = hash.Substring(0, 5);
        var suffix = hash.Substring(5);

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, HibpRangeBaseUrl + prefix);
            req.Headers.UserAgent.ParseAdd("JellyfinSecurity/2.4");
            // Add-Padding=true asks HIBP to pad the response with synthetic
            // entries so passive observers can't infer breach count from
            // response size. Costs ~1KB extra per request, well worth it.
            req.Headers.Add("Add-Padding", "true");

            using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                _logger.LogDebug("[HIBP] non-success HTTP {Status} from range API", (int)resp.StatusCode);
                return -1;
            }

            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            foreach (var rawLine in body.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.Length == 0) continue;
                var colonIdx = line.IndexOf(':');
                if (colonIdx <= 0 || colonIdx >= line.Length - 1) continue;
                var lineSuffix = line.Substring(0, colonIdx);
                if (!lineSuffix.Equals(suffix, StringComparison.OrdinalIgnoreCase)) continue;

                var countStr = line.Substring(colonIdx + 1).Trim();
                if (!int.TryParse(countStr, System.Globalization.NumberStyles.Integer,
                        System.Globalization.CultureInfo.InvariantCulture, out var count)) return 0;
                // Padding rows have count=0 — those are decoys, treat as no match.
                return count > 0 ? count : 0;
            }
            return 0;
        }
        catch (OperationCanceledException)
        {
            // Timeout — fail open.
            _logger.LogDebug("[HIBP] check timed out for prefix {Prefix}", prefix);
            return -1;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[HIBP] check failed for prefix {Prefix}", prefix);
            return -1;
        }
    }

    internal static string ComputeSha1Hex(string s)
    {
        var bytes = SHA1.HashData(Encoding.UTF8.GetBytes(s));
        return Convert.ToHexString(bytes); // uppercase, no separators
    }
}
