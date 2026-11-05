using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Jellyfin.Plugin.TwoFactorAuth.Helpers;

/// <summary>[#318] Server-side reader of the translation files the pages use
/// (Pages/translations/*.json), so text the server writes, such as an email,
/// comes from the same source as the UI. A language is supported when its file
/// is bundled; a key missing from it falls back to English.</summary>
internal static class ServerTranslations
{
    internal const string English = "en";

    private static readonly ConcurrentDictionary<string, IReadOnlyDictionary<string, string>> Bundles = new(StringComparer.Ordinal);

    private static readonly Regex Placeholder = new(@"\{([a-z]+)\}", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>The first of <paramref name="candidates"/> with a bundled
    /// translation file, else English.</summary>
    internal static string ResolveLanguage(params string?[] candidates)
        => candidates.FirstOrDefault(c => Bundle(c) is not null) ?? English;

    /// <summary>The text of <paramref name="key"/> in <paramref name="language"/>,
    /// else in English. Throws when English lacks it too: a missing key is a
    /// packaging bug, and sending the bare key would drop what the text carries
    /// (a reset link, a code).</summary>
    internal static string Get(string language, string key) => Pick(Bundle(language), Bundle(English), key);

    internal static string Pick(IReadOnlyDictionary<string, string>? localized, IReadOnlyDictionary<string, string>? english, string key)
    {
        if (localized is not null && localized.TryGetValue(key, out var text))
        {
            return text;
        }

        return english is not null && english.TryGetValue(key, out var fallback)
            ? fallback
            : throw new KeyNotFoundException("Translation key not bundled: " + key);
    }

    /// <summary>Replaces each {name} in <paramref name="template"/> with its
    /// value in one pass: text that comes in through a value is never scanned
    /// again, so a username such as "{link}" stays literal. Unknown names are
    /// left as they are.</summary>
    internal static string Format(string template, IReadOnlyDictionary<string, string> values)
        => Placeholder.Replace(template, m => values.TryGetValue(m.Groups[1].Value, out var value) ? value : m.Value);

    private static IReadOnlyDictionary<string, string>? Bundle(string? language)
    {
        // Only plain language codes reach the resource lookup.
        if (string.IsNullOrEmpty(language) || language.Length > 8 || !language.All(c => c is >= 'a' and <= 'z'))
        {
            return null;
        }

        if (Bundles.TryGetValue(language, out var cached))
        {
            return cached;
        }

        var json = ResourceReader.ReadEmbeddedText($"Jellyfin.Plugin.TwoFactorAuth.Pages.translations.{language}.json");
        if (json is null)
        {
            return null;
        }

        using var document = JsonDocument.Parse(json);
        var bundle = document.RootElement.EnumerateObject()
            .Where(p => p.Value.ValueKind == JsonValueKind.String)
            .ToDictionary(p => p.Name, p => p.Value.GetString()!, StringComparer.Ordinal);
        return Bundles.GetOrAdd(language, bundle);
    }
}
