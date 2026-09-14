using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// [#203] Makes the native libraries in the plugin root match the host's
/// runtime identifier before anything can load them. Nothing here calls
/// dlopen; it only moves files.
///
/// Why this exists. The plugin zip is built for three Linux RIDs and build.sh
/// copies every RID's *.so into the plugin root in turn, so the root ends up
/// holding whichever RID came last (linux-musl-x64). Two consumers look for
/// those files in the root and nowhere else. The .NET runtime probes a
/// P/Invoke library in the calling assembly's directory and never in
/// runtimes/{rid}/native unless a .deps.json says so, and the plugin ships
/// none. QuestPDF's own NativeDependencyProvider does know about
/// runtimes/{rid}/native, but it copies to the root with CopyFileIfNewer, and
/// every file in the zip carries the same timestamp, so the musl file is never
/// "older" and never replaced. On a glibc host the musl libsodium then fails to
/// dlopen (it needs libc.so), which is what v2.6.1 shipped for Ed25519
/// passkeys, and libQuestPdfSkia would fail the same way.
///
/// Why not copy in place. The previous version overwrote the root copies with
/// File.Copy(overwrite: true), which truncates and rewrites the target inode.
/// That is a path the runtime may already have mapped, and rewriting a mapped
/// shared object under the loader is undefined behaviour. Here the copy goes to
/// a temporary name in the same directory and is renamed over the target,
/// which on Linux is rename(2): the old inode stays intact for anyone who has
/// it mapped, and readers see either the old file or the new one, never a
/// half-written one.
///
/// Runs once from the Plugin constructor, before the server accepts requests,
/// and records what it did in <see cref="LastResult"/> so a diagnostics
/// surface can show it.
/// </summary>
internal static class NativeDependencyLayout
{
    /// <summary>Native libraries the plugin ships per RID. libsodium belongs to
    /// NSec (passkey Ed25519); the other two to QuestPDF (recovery-code PDF).</summary>
    internal static readonly string[] Libraries = { "libsodium.so", "libqpdf.so", "libQuestPdfSkia.so" };

    internal enum SyncOutcome
    {
        MissingSource,
        Unchanged,
        Replaced,
        Failed,
    }

    internal sealed record Result(
        string? Rid,
        IReadOnlyList<string> Replaced,
        IReadOnlyList<string> Unchanged,
        IReadOnlyList<string> Failed,
        string? Note);

    /// <summary>What the last <see cref="EnsureRidCorrectRootCopies"/> did, for
    /// diagnostics. Null until it has run.</summary>
    public static Result? LastResult { get; private set; }

    /// <summary>Brings the root copy of every shipped native library in line
    /// with runtimes/{rid}/native for this host. Never throws: the worst case
    /// is the pre-existing behaviour, a wrong-RID file at the root.</summary>
    public static Result EnsureRidCorrectRootCopies(string? pluginDir)
    {
        var replaced = new List<string>();
        var unchanged = new List<string>();
        var failed = new List<string>();
        string? rid = null;
        string? note = null;

        try
        {
            if (!OperatingSystem.IsLinux())
            {
                note = "not Linux; nothing to do";
            }
            else if (string.IsNullOrWhiteSpace(pluginDir))
            {
                note = "plugin directory unknown";
            }
            else if ((rid = GetCurrentLinuxRid()) is null)
            {
                note = "unsupported architecture " + RuntimeInformation.ProcessArchitecture;
            }
            else
            {
                var nativeDir = Path.Combine(pluginDir, "runtimes", rid, "native");
                if (!Directory.Exists(nativeDir))
                {
                    note = "no runtimes/" + rid + "/native folder";
                }
                else
                {
                    foreach (var lib in Libraries)
                    {
                        switch (SyncOne(Path.Combine(nativeDir, lib), Path.Combine(pluginDir, lib)))
                        {
                            case SyncOutcome.Replaced:
                                replaced.Add(lib);
                                break;
                            case SyncOutcome.Unchanged:
                                unchanged.Add(lib);
                                break;
                            case SyncOutcome.Failed:
                                failed.Add(lib);
                                break;
                            case SyncOutcome.MissingSource:
                                break;
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            note = "layout check failed: " + ex.GetType().Name;
        }

        var result = new Result(rid, replaced, unchanged, failed, note);
        LastResult = result;
        return result;
    }

    /// <summary>Copies source over target through a temporary file plus
    /// rename, but only when the bytes differ. Timestamps are deliberately
    /// ignored: equal timestamps are exactly the case that defeated
    /// CopyFileIfNewer.</summary>
    internal static SyncOutcome SyncOne(string source, string target)
    {
        if (!File.Exists(source))
            return SyncOutcome.MissingSource;

        try
        {
            if (File.Exists(target) && SameContent(source, target))
                return SyncOutcome.Unchanged;
        }
        catch (Exception)
        {
            // Unreadable target: fall through and replace it.
        }

        var tmp = target + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.Copy(source, tmp, overwrite: true);
            // rename(2) on Linux: atomic, and the old inode is left alone.
            File.Move(tmp, target, overwrite: true);
            return SyncOutcome.Replaced;
        }
        catch (Exception)
        {
            try
            {
                File.Delete(tmp);
            }
            catch (Exception)
            {
                // Best effort; a stray .tmp is harmless and visible.
            }

            return SyncOutcome.Failed;
        }
    }

    internal static bool SameContent(string a, string b)
    {
        var fa = new FileInfo(a);
        var fb = new FileInfo(b);
        if (fa.Length != fb.Length)
            return false;

        using var sa = fa.OpenRead();
        using var sb = fb.OpenRead();
        return SHA256.HashData(sa).AsSpan().SequenceEqual(SHA256.HashData(sb));
    }

    internal static string? GetCurrentLinuxRid()
    {
        return RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "linux-arm64",
            Architecture.X64 => IsMusl() ? "linux-musl-x64" : "linux-x64",
            _ => null
        };
    }

    internal static bool IsMusl()
    {
        return File.Exists("/lib/ld-musl-x86_64.so.1")
            || File.Exists("/lib/ld-musl-aarch64.so.1")
            || File.Exists("/lib64/ld-musl-x86_64.so.1")
            || File.Exists("/lib64/ld-musl-aarch64.so.1");
    }
}
