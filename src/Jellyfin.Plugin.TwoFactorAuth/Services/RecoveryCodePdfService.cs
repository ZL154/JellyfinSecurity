using System.Collections.Generic;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Renders the freshly-generated recovery codes as a single-page A4 PDF the
/// user can print and stash. Codes are generation-time only: once dismissed
/// the server has no way to re-derive them, so this PDF is the user's last
/// chance to capture the plaintext.
///
/// QuestPDF community license is free for projects under USD 1M revenue,
/// which covers a self-hosted OSS plugin. License blurb is required in
/// distribution; included in README.
///
/// [#203] Nothing native happens until the first Render. QuestPDF's Settings
/// type runs SkNativeDependencyCompatibilityChecker from its own static
/// constructor, and FontManager.RegisterFont goes straight into Skia, so the
/// static constructor that used to live here loaded a 7 MB Skia build (and,
/// until v2.6.1, libsodium as well) on the first request to any plugin
/// endpoint, for a feature most requests never touch. It also depended on
/// copying the right-RID binaries over the plugin root with an in-place
/// overwrite; that job now belongs to NativeDependencyLayout, which runs at
/// plugin construction and renames instead of truncating. Fonts and the
/// license are registered lazily, once, the first time a PDF is rendered.
/// </summary>
public class RecoveryCodePdfService
{
    private static readonly object _initLock = new();
    private static bool _isReady;
    private static Exception? _initializationException;

    /// <summary>Registers the embedded fonts and the community license the
    /// first time a PDF is rendered. A failure is remembered rather than
    /// retried, matching what the static constructor used to do: QuestPDF's
    /// own message is the useful one, and repeating the attempt on every
    /// download would only repeat it.</summary>
    private static void EnsureReady()
    {
        if (_isReady || _initializationException is not null)
            return;

        lock (_initLock)
        {
            if (_isReady || _initializationException is not null)
                return;

            try
            {
                // Register embedded Lato fonts. Without this, on a Linux container
                // with no system fonts installed (the typical Jellyfin Docker
                // image), Skia falls back to "no glyphs" and the PDF renders as
                // empty boxes. QuestPDF only auto-loads fonts that are actually
                // registered; the constant string "Lato" by itself does nothing.
                RegisterEmbeddedFont("Jellyfin.Plugin.TwoFactorAuth.Fonts.Lato-Regular.ttf");
                RegisterEmbeddedFont("Jellyfin.Plugin.TwoFactorAuth.Fonts.Lato-Bold.ttf");

                // Required once per process, and before the first render.
                // Community license is free for projects with < $1M revenue.
                QuestPDF.Settings.License = LicenseType.Community;
                _isReady = true;
            }
            catch (Exception ex)
            {
                _initializationException = ex;
            }
        }
    }

    private static void RegisterEmbeddedFont(string resourceName)
    {
        var asm = typeof(RecoveryCodePdfService).Assembly;
        using var stream = asm.GetManifestResourceStream(resourceName);
        if (stream is null) return;
        QuestPDF.Drawing.FontManager.RegisterFont(stream);
    }

    public byte[] Render(string username, IReadOnlyList<string> codes, string serverName)
    {
        EnsureReady();

        if (!_isReady)
        {
            throw new InvalidOperationException(
                "Recovery PDF generation is unavailable on this runtime. " +
                "Verify QuestPDF native dependencies for the current architecture.",
                _initializationException);
        }

        var generated = System.DateTime.UtcNow.ToString("u");
        var doc = Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4);
                page.Margin(40);
                // QuestPDF bundles "Lato" — present on every platform without
                // needing system-installed fonts. Fonts.SegoeUI / Fonts.Consolas
                // were Windows-only and rendered as empty glyph boxes inside
                // Linux containers (Jellyfin Docker).
                page.DefaultTextStyle(t => t.FontSize(11).FontFamily("Lato"));

                page.Header().Column(col =>
                {
                    col.Item().Text(serverName).FontSize(20).Bold();
                    col.Item().Text($"Two-Factor Authentication — recovery codes for {username}")
                        .FontSize(13).FontColor(Colors.Grey.Darken1);
                    col.Item().PaddingTop(2).Text($"Generated {generated} UTC")
                        .FontSize(9).FontColor(Colors.Grey.Darken1);
                });

                page.Content().PaddingVertical(15).Column(col =>
                {
                    col.Item().PaddingBottom(10).Text(t =>
                    {
                        t.Span("KEEP THESE SECRET. ").Bold();
                        t.Span("Each code works ONCE. Use them to sign in if you lose access to your authenticator app.");
                    });

                    col.Item().Border(1).BorderColor(Colors.Grey.Lighten1).Padding(15).Column(box =>
                    {
                        var width = 3;
                        box.Item().Table(tab =>
                        {
                            tab.ColumnsDefinition(c =>
                            {
                                for (var i = 0; i < width; i++) c.RelativeColumn();
                            });
                            for (var i = 0; i < codes.Count; i++)
                            {
                                tab.Cell().PaddingVertical(6).Text($"{i + 1:D2}.  {codes[i]}")
                                    .FontFamily("Lato").FontSize(13);
                            }
                        });
                    });

                    col.Item().PaddingTop(20).Text(
                        "If you ever lose all of your recovery codes AND your authenticator, " +
                        "an admin must reset your 2FA from the server's admin panel.")
                        .FontSize(9).FontColor(Colors.Grey.Darken1);
                });

                page.Footer().AlignCenter().Text("Generated by Jellyfin Two-Factor Authentication plugin")
                    .FontSize(8).FontColor(Colors.Grey.Lighten1);
            });
        });

        return doc.GeneratePdf();
    }
}
