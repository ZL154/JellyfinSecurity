using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

public class RecoveryCodeServiceTests
{
    private static readonly char[] ValidChars =
        "ABCDEFGHJKMNPQRSTUVWXYZ23456789".ToCharArray();

    [Fact]
    public void GenerateCodes_returns_ten_codes_and_records()
    {
        var svc = new RecoveryCodeService();
        var (plaintexts, records) = svc.GenerateCodes();

        Assert.Equal(10, plaintexts.Count);
        Assert.Equal(10, records.Count);
    }

    [Fact]
    public void GenerateCodes_plaintext_format_is_five_dash_five()
    {
        var svc = new RecoveryCodeService();
        var (plaintexts, _) = svc.GenerateCodes();

        foreach (var p in plaintexts)
        {
            Assert.Equal(11, p.Length);
            Assert.Equal('-', p[5]);
        }
    }

    [Fact]
    public void GenerateCodes_avoid_ambiguous_chars()
    {
        var svc = new RecoveryCodeService();
        var (plaintexts, _) = svc.GenerateCodes();

        foreach (var p in plaintexts)
        {
            var normalized = RecoveryCodeService.NormalizeForCompare(p);
            foreach (var c in normalized)
            {
                Assert.Contains(c, ValidChars);
            }
            // Confirm the ambiguous set is excluded.
            Assert.DoesNotContain('0', normalized);
            Assert.DoesNotContain('O', normalized);
            Assert.DoesNotContain('1', normalized);
            Assert.DoesNotContain('I', normalized);
            Assert.DoesNotContain('L', normalized);
        }
    }

    [Fact]
    public void GenerateCodes_records_are_unused()
    {
        var svc = new RecoveryCodeService();
        var (_, records) = svc.GenerateCodes();
        Assert.All(records, r => Assert.False(r.Used));
        Assert.All(records, r => Assert.Null(r.UsedAt));
    }

    [Fact]
    public void HashCodeV2_starts_with_v2_marker()
    {
        var hash = RecoveryCodeService.HashCodeV2("ABCDEFGHJK");
        Assert.StartsWith("v2$", hash);
        var parts = hash.Split('$');
        Assert.Equal(4, parts.Length);
        Assert.Equal("100000", parts[1]); // PbkdfIterations
    }

    [Fact]
    public void Verify_accepts_correct_v2_hash()
    {
        var code = RecoveryCodeService.NormalizeForCompare("ABCDE-FGHJK");
        var hash = RecoveryCodeService.HashCodeV2(code);
        Assert.True(RecoveryCodeService.Verify(code, hash));
    }

    [Fact]
    public void Verify_rejects_wrong_code_against_v2_hash()
    {
        var hash = RecoveryCodeService.HashCodeV2(RecoveryCodeService.NormalizeForCompare("ABCDE-FGHJK"));
        Assert.False(RecoveryCodeService.Verify("WRONGCODE2", hash));
    }

    [Fact]
    public void Verify_accepts_legacy_v1_hash()
    {
        // v1 legacy: bare base64(SHA-256(utf8(code))).
        var code = "ABCDE-FGHJK";
        var normalized = RecoveryCodeService.NormalizeForCompare(code);
        var sha = SHA256.HashData(Encoding.UTF8.GetBytes(normalized));
        var legacyHash = Convert.ToBase64String(sha);

        Assert.True(RecoveryCodeService.Verify(normalized, legacyHash));
    }

    [Fact]
    public void Verify_rejects_empty_hash()
    {
        Assert.False(RecoveryCodeService.Verify("any", string.Empty));
        Assert.False(RecoveryCodeService.Verify("any", null!));
    }

    [Theory]
    [InlineData("v2$bad")]
    [InlineData("v2$100000$invalid_base64$alsobad")]
    [InlineData("v2$0$AAAA$BBBB")]
    [InlineData("v2$abc$AAAA$BBBB")]
    public void Verify_rejects_malformed_v2_hash(string malformed)
    {
        Assert.False(RecoveryCodeService.Verify("ABCDEFGHJK", malformed));
    }

    [Fact]
    public void Verify_rejects_v2_hash_with_excessive_iterations()
    {
        // The parser caps iter at 10_000_000 to prevent a DoS via huge iter
        // values. Anything above must fail-fast.
        var bigIter = "v2$10000001$" + Convert.ToBase64String(new byte[16]) + "$" + Convert.ToBase64String(new byte[32]);
        Assert.False(RecoveryCodeService.Verify("ABCDEFGHJK", bigIter));
    }

    [Theory]
    [InlineData("abcde-fghjk", "ABCDEFGHJK")]
    [InlineData("ABCDE FGHJK", "ABCDEFGHJK")]
    public void NormalizeForCompare_uppercases_and_strips_separators(string input, string expected)
    {
        Assert.Equal(expected, RecoveryCodeService.NormalizeForCompare(input));
    }

    [Fact]
    public void HashCodeV2_uses_distinct_salts_for_repeated_hashes()
    {
        // Same plaintext, two hashes — salts differ, so ciphertexts differ.
        var a = RecoveryCodeService.HashCodeV2("ABCDEFGHJK");
        var b = RecoveryCodeService.HashCodeV2("ABCDEFGHJK");
        Assert.NotEqual(a, b);
        Assert.True(RecoveryCodeService.Verify("ABCDEFGHJK", a));
        Assert.True(RecoveryCodeService.Verify("ABCDEFGHJK", b));
    }

    [Fact]
    public void GenerateCodes_records_validate_against_their_plaintexts()
    {
        var svc = new RecoveryCodeService();
        var (plaintexts, records) = svc.GenerateCodes();
        Assert.Equal(plaintexts.Count, records.Count);

        for (var i = 0; i < plaintexts.Count; i++)
        {
            var normalized = RecoveryCodeService.NormalizeForCompare(plaintexts[i]);
            Assert.True(
                RecoveryCodeService.Verify(normalized, records[i].Hash),
                $"plaintext[{i}] should verify against records[{i}].Hash");
        }
    }
}
