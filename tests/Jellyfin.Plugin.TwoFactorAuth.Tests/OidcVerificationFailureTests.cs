using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[v2.5.21] (#142, jmbenevise) Every id_token validation failure used
/// to collapse into one opaque "Sign-in token could not be verified.", so an
/// admin had no way to tell an expired IdP certificate from a client-ID typo.
/// These assert both halves of the contract: the message is actionable, and it
/// never leaks the raw Microsoft.IdentityModel detail (finding N-A9).</summary>
public class OidcVerificationFailureTests
{
    [Theory]
    [InlineData("Token verification failed: IDX10500: Signature validation failed. No security keys were provided.")]
    [InlineData("Token verification failed: IDX10501: Signature validation failed. Unable to match key: kid: 'abc'.")]
    [InlineData("Token verification failed: IDX10503: Signature validation failed. Token does not have a kid.")]
    [InlineData("Token verification failed: IDX10511: Signature validation failed. Keys tried: 'x'.")]
    public void Signing_key_mismatch_tells_the_admin_to_refresh_the_key_cache(string error)
    {
        var msg = OidcService.DescribeVerificationFailure(error);

        Assert.NotNull(msg);
        Assert.Contains("signing key", msg, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("restart Jellyfin", msg, System.StringComparison.OrdinalIgnoreCase);
        AssertNoInternals(msg, error);
    }

    [Fact]
    public void Expired_signing_certificate_points_at_the_idp()
    {
        // The real message from #98 (HumnResources): authentik's default
        // self-signed signing cert lapsed and every sign-in died.
        var msg = OidcService.DescribeVerificationFailure(
            "Token verification failed: IDX10249: X509SecurityKey validation failed. "
            + "The associated certificate has expired. ValidTo (UTC): '04/11/2025 06:03:09'.");

        Assert.NotNull(msg);
        Assert.Contains("certificate has expired", msg, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("authentik", msg, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Audience_mismatch_points_at_the_client_id()
    {
        var msg = OidcService.DescribeVerificationFailure(
            "Token verification failed: IDX10214: Audience validation failed.");

        Assert.NotNull(msg);
        Assert.Contains("Client ID", msg, System.StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Issuer_mismatch_points_at_the_discovery_url()
    {
        var msg = OidcService.DescribeVerificationFailure(
            "Token verification failed: IDX10205: Issuer validation failed.");

        Assert.NotNull(msg);
        Assert.Contains("issuer", msg, System.StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Token verification failed: IDX10223: Lifetime validation failed. The token is expired.")]
    [InlineData("Token verification failed: IDX10225: Lifetime validation failed. The token is missing an Expiration Time.")]
    [InlineData("Token verification failed: IDX10222: Lifetime validation failed. The token is not yet valid.")]
    [InlineData("id_token iat (2026-01-01T00:00:00.0000000Z) is older than 10 minutes.")]
    [InlineData("id_token iat (2030-01-01T00:00:00.0000000Z) is in the future beyond clock skew tolerance.")]
    public void Lifetime_failures_point_at_clock_drift(string error)
    {
        var msg = OidcService.DescribeVerificationFailure(error);

        Assert.NotNull(msg);
        Assert.Contains("clock drift", msg, System.StringComparison.OrdinalIgnoreCase);
        Assert.Contains("NTP", msg, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Disallowed_algorithm_tells_the_admin_to_set_an_rsa_signing_key()
    {
        // What an authentik provider with no Signing Key selected produces: it
        // falls back to HMAC (HS256) with the client secret, which our
        // asymmetric-only allowlist refuses.
        var msg = OidcService.DescribeVerificationFailure(
            "Token verification failed: Algorithm 'HS256' is not permitted. Only RS*, ES*, PS* are accepted.");

        Assert.NotNull(msg);
        Assert.Contains("RS256", msg, System.StringComparison.Ordinal);
        Assert.Contains("Signing Key", msg, System.StringComparison.Ordinal);
    }

    [Fact]
    public void Nonce_mismatch_tells_the_user_to_restart_the_sign_in()
    {
        var msg = OidcService.DescribeVerificationFailure("Token verification failed: Nonce mismatch");

        Assert.NotNull(msg);
        Assert.Contains("start the sign-in again", msg, System.StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Some entirely unrecognised failure")]
    public void Unrecognised_failures_return_null_so_the_caller_keeps_its_generic_message(string? error)
    {
        Assert.Null(OidcService.DescribeVerificationFailure(error));
    }

    /// <summary>The user-facing string must carry configuration advice only —
    /// no IDX codes, no issuer, no key ids, nothing that fingerprints the
    /// deployment or the library version.</summary>
    private static void AssertNoInternals(string message, string rawError)
    {
        Assert.DoesNotContain("IDX", message, System.StringComparison.Ordinal);
        Assert.DoesNotContain("kid:", message, System.StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(rawError, message, System.StringComparison.Ordinal);
    }
}
