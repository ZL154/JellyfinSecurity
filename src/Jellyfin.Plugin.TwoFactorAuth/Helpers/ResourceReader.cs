using System.IO;
using System.Reflection;

namespace Jellyfin.Plugin.TwoFactorAuth.Helpers;

/// <summary>Reads bytes / text out of the assembly's embedded resources.
/// Centralizes the GetManifestResourceStream + StreamReader dance.</summary>
public static class ResourceReader
{
    public static string? ReadEmbeddedText(string logicalName)
    {
        var asm = typeof(ResourceReader).Assembly;
        using var stream = asm.GetManifestResourceStream(logicalName);
        if (stream is null) return null;
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
