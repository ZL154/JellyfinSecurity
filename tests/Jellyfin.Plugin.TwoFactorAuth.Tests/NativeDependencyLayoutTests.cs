using System;
using System.IO;
using System.Linq;
using System.Text;
using Jellyfin.Plugin.TwoFactorAuth.Services;
using Xunit;

namespace Jellyfin.Plugin.TwoFactorAuth.Tests;

/// <summary>[#203] The plugin root must end up holding the host RID's native
/// libraries, and replacing them must never truncate a file the runtime may
/// already have mapped.</summary>
public class NativeDependencyLayoutTests : IDisposable
{
    private readonly string _root;

    public NativeDependencyLayoutTests()
    {
        _root = Path.Combine(Path.GetTempPath(), "tfa-native-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_root);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { /* best-effort cleanup */ }
        GC.SuppressFinalize(this);
    }

    private string Write(string relativePath, string content)
    {
        var full = Path.Combine(_root, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        File.WriteAllText(full, content, Encoding.ASCII);
        return full;
    }

    private static string Read(string path) => File.ReadAllText(path, Encoding.ASCII);

    private string[] TempFiles() => Directory.GetFiles(_root, "*.tmp", SearchOption.AllDirectories);

    [Fact]
    public void SyncOne_CopiesWhenTheTargetIsMissing()
    {
        var source = Write("runtimes/linux-x64/native/lib.so", "glibc build");
        var target = Path.Combine(_root, "lib.so");

        var outcome = NativeDependencyLayout.SyncOne(source, target);

        Assert.Equal(NativeDependencyLayout.SyncOutcome.Replaced, outcome);
        Assert.Equal("glibc build", Read(target));
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void SyncOne_ReplacesADifferentTarget_AndLeavesNoTempFileBehind()
    {
        // The shipped layout: a musl build at the root, the right one under runtimes/.
        var source = Write("runtimes/linux-x64/native/lib.so", "glibc build");
        var target = Write("lib.so", "musl build");

        var outcome = NativeDependencyLayout.SyncOne(source, target);

        Assert.Equal(NativeDependencyLayout.SyncOutcome.Replaced, outcome);
        Assert.Equal("glibc build", Read(target));
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void SyncOne_LeavesAnIdenticalTargetAlone_WhateverTheTimestampsSay()
    {
        // QuestPDF's CopyFileIfNewer decides by timestamp, and equal timestamps
        // in the zip are exactly what defeated it. Only the bytes matter here.
        var source = Write("runtimes/linux-x64/native/lib.so", "same bytes");
        var target = Write("lib.so", "same bytes");
        File.SetLastWriteTimeUtc(target, new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        var before = File.GetLastWriteTimeUtc(target);

        var outcome = NativeDependencyLayout.SyncOne(source, target);

        Assert.Equal(NativeDependencyLayout.SyncOutcome.Unchanged, outcome);
        Assert.Equal(before, File.GetLastWriteTimeUtc(target));
        Assert.Empty(TempFiles());
    }

    [Fact]
    public void SyncOne_MissingSource_TouchesNothing()
    {
        var target = Write("lib.so", "whatever shipped");

        var outcome = NativeDependencyLayout.SyncOne(Path.Combine(_root, "nope.so"), target);

        Assert.Equal(NativeDependencyLayout.SyncOutcome.MissingSource, outcome);
        Assert.Equal("whatever shipped", Read(target));
    }

    [Fact]
    public void EnsureRidCorrectRootCopies_WithoutARuntimesFolder_IsANoOp()
    {
        Write("libsodium.so", "as shipped");

        var result = NativeDependencyLayout.EnsureRidCorrectRootCopies(_root);

        Assert.Empty(result.Replaced);
        Assert.Empty(result.Failed);
        Assert.Equal("as shipped", Read(Path.Combine(_root, "libsodium.so")));
    }

    [Fact]
    public void EnsureRidCorrectRootCopies_NullDirectory_IsANoOp()
    {
        var result = NativeDependencyLayout.EnsureRidCorrectRootCopies(null);

        Assert.Empty(result.Replaced);
        Assert.Empty(result.Failed);
        Assert.NotNull(result.Note);
    }

    [Fact]
    public void EnsureRidCorrectRootCopies_ReplacesEveryShippedLibraryFromTheHostRid()
    {
        if (!OperatingSystem.IsLinux())
            return; // the layout is Linux-only by construction

        var rid = NativeDependencyLayout.GetCurrentLinuxRid();
        Assert.NotNull(rid);

        foreach (var lib in NativeDependencyLayout.Libraries)
        {
            Write(Path.Combine("runtimes", rid!, "native", lib), "correct " + lib);
            Write(lib, "musl " + lib);
        }

        var result = NativeDependencyLayout.EnsureRidCorrectRootCopies(_root);

        Assert.Equal(rid, result.Rid);
        Assert.Equal(
            NativeDependencyLayout.Libraries.OrderBy(x => x, StringComparer.Ordinal),
            result.Replaced.OrderBy(x => x, StringComparer.Ordinal));
        Assert.Empty(result.Failed);
        foreach (var lib in NativeDependencyLayout.Libraries)
        {
            Assert.Equal("correct " + lib, Read(Path.Combine(_root, lib)));
        }

        Assert.Empty(TempFiles());
        Assert.NotNull(NativeDependencyLayout.LastResult);
    }

    [Fact]
    public void EnsureRidCorrectRootCopies_IsIdempotent()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var rid = NativeDependencyLayout.GetCurrentLinuxRid()!;
        Write(Path.Combine("runtimes", rid, "native", "libsodium.so"), "correct");
        Write("libsodium.so", "musl");

        var first = NativeDependencyLayout.EnsureRidCorrectRootCopies(_root);
        var second = NativeDependencyLayout.EnsureRidCorrectRootCopies(_root);

        Assert.Contains("libsodium.so", first.Replaced);
        Assert.Contains("libsodium.so", second.Unchanged);
        Assert.Empty(second.Replaced);
    }

    [Fact]
    public void GetCurrentLinuxRid_OnLinux_NamesAKnownRid()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var rid = NativeDependencyLayout.GetCurrentLinuxRid();

        Assert.Contains(rid!, new[] { "linux-x64", "linux-musl-x64", "linux-arm64" });
    }
}
