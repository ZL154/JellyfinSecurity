using System.IO;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using SharpFuzz;

namespace Jellyfin.Plugin.TwoFactorAuth.Fuzz;

/// <summary>
/// SharpFuzz harness for BypassEvaluator.PickRealClientIp — the parser
/// that walks a comma-separated X-Forwarded-For header right-to-left to
/// find the real client behind a chain of trusted proxies.
///
/// Attacker-controlled header value + non-trivial parsing (IPv6 bracket
/// stripping, ":port" suffix removal, comma-split, CIDR matching) makes
/// this the highest-value parser surface in the plugin. The harness
/// splits the libFuzzer input bytes into the header value and the CIDR
/// list so both arguments get fuzzed.
///
/// Run locally:
///   dotnet build -c Release
///   sharpfuzz Jellyfin.Plugin.TwoFactorAuth.dll BypassEvaluator
/// ClusterFuzzLite handles all of that automatically inside the
/// `.clusterfuzzlite/Dockerfile` build.
/// </summary>
internal static class Program
{
    public static void Main(string[] args)
    {
        // ClusterFuzzLite invokes the binary; libFuzzer drives Fuzzer.Run from
        // here. The Stream we receive contains the raw fuzzed bytes for one
        // iteration. We split them into "header" and "cidrList" parts at a
        // 0xFF separator so libFuzzer can mutate both halves independently.
        Fuzzer.Run((Stream stream) =>
        {
            using var ms = new MemoryStream();
            stream.CopyTo(ms);
            Fuzz(ms.ToArray());
        });
    }

    private static void Fuzz(byte[] input)
    {
        var sepIdx = System.Array.IndexOf(input, (byte)0xFF);
        byte[] headerBytes;
        byte[] cidrBytes;
        if (sepIdx >= 0)
        {
            headerBytes = input[..sepIdx];
            cidrBytes = input[(sepIdx + 1)..];
        }
        else
        {
            headerBytes = input;
            cidrBytes = System.Array.Empty<byte>();
        }

        string header;
        string[] cidrs;
        try
        {
            header = Encoding.UTF8.GetString(headerBytes);
            var cidrJoined = Encoding.UTF8.GetString(cidrBytes);
            cidrs = string.IsNullOrEmpty(cidrJoined)
                ? System.Array.Empty<string>()
                : cidrJoined.Split('\n', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        }
        catch (DecoderFallbackException)
        {
            // Invalid UTF-8 in the fuzz input — not the target's problem.
            return;
        }

        // The actual target: must not throw on any input. Null / empty /
        // malformed are all allowed return values, but uncaught exceptions
        // mean a real bug.
        _ = BypassEvaluator.PickRealClientIp(header, cidrs);
    }
}
