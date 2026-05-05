using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Renders the freshly-generated recovery codes as a single-page A4 PDF the
/// user can print and stash. Codes are generation-time only — once dismissed
/// the server has no way to re-derive them, so this PDF is the user's last
/// chance to capture the plaintext.
///
/// QuestPDF community license is free for projects under USD 1M revenue —
/// applies to a self-hosted OSS plugin. License blurb is required in
/// distribution; included in README.
/// </summary>
public class RecoveryCodePdfService
{
    private static bool _isReady;
    private static Exception? _initializationException;

    static RecoveryCodePdfService()
    {
        try
        {
            EnsureQuestPdfNativeDependenciesLoaded();

            // Required once per process — license must be set before first render.
            // Community license is free for projects with < $1M revenue.
            QuestPDF.Settings.License = LicenseType.Community;
            _isReady = true;
        }
        catch (Exception ex)
        {
            _isReady = false;
            _initializationException = ex;
        }
    }

    private static void EnsureQuestPdfNativeDependenciesLoaded()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var rid = GetCurrentLinuxRid();
        if (rid is null)
            return;

        var pluginDir = Path.GetDirectoryName(typeof(RecoveryCodePdfService).Assembly.Location);
        if (string.IsNullOrWhiteSpace(pluginDir))
            return;

        var nativeDir = Path.Combine(pluginDir, "runtimes", rid, "native");
        if (!Directory.Exists(nativeDir))
            return;

        // QuestPDF probes plugin root first on this hosting model.
        // Ensure root has the native binaries for the current architecture.
        TryCopyToRoot(nativeDir, pluginDir, "libsodium.so");
        TryCopyToRoot(nativeDir, pluginDir, "libqpdf.so");
        TryCopyToRoot(nativeDir, pluginDir, "libQuestPdfSkia.so");

        // Load dependencies before QuestPDF native.
        TryLoad(Path.Combine(nativeDir, "libsodium.so"));
        TryLoad(Path.Combine(nativeDir, "libqpdf.so"));
        TryLoad(Path.Combine(nativeDir, "libQuestPdfSkia.so"));
    }

    private static string? GetCurrentLinuxRid()
    {
        return RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "linux-arm64",
            Architecture.X64 => IsMusl() ? "linux-musl-x64" : "linux-x64",
            _ => null
        };
    }

    private static bool IsMusl()
    {
        return File.Exists("/lib/ld-musl-x86_64.so.1")
            || File.Exists("/lib/ld-musl-aarch64.so.1")
            || File.Exists("/lib64/ld-musl-x86_64.so.1")
            || File.Exists("/lib64/ld-musl-aarch64.so.1");
    }

    private static void TryLoad(string path)
    {
        if (!File.Exists(path))
            return;

        try
        {
            NativeLibrary.Load(path);
        }
        catch
        {
            // QuestPDF will throw a detailed compatibility error later if load fails.
        }
    }

    private static void TryCopyToRoot(string nativeDir, string pluginDir, string fileName)
    {
        var source = Path.Combine(nativeDir, fileName);
        var target = Path.Combine(pluginDir, fileName);
        if (!File.Exists(source))
            return;

        try
        {
            File.Copy(source, target, overwrite: true);
        }
        catch
        {
            // If copy fails, TryLoad still attempts absolute path from RID folder.
        }
    }

    public byte[] Render(string username, IReadOnlyList<string> codes, string serverName)
    {
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
                page.DefaultTextStyle(t => t.FontSize(11).FontFamily(Fonts.SegoeUI));

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
                                    .FontFamily(Fonts.Consolas).FontSize(13);
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
