using System;
using System.Collections.Generic;

namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class ScoreFactor
{
    public string Id { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public int Earned { get; set; }
    public int Possible { get; set; }

    /// <summary>"ok" / "partial" / "fail": drives the bar colour in the UI.
    /// [#258] "na" marks a factor left out of the total (Possible is 0), with
    /// the reason in <see cref="Note"/>.</summary>
    public string Status { get; set; } = "fail";

    /// <summary>[#258] Why a factor is not counted, shown in place of its
    /// points. Null for counted factors.</summary>
    public string? Note { get; set; }

    /// <summary>[#258] i18n key for <see cref="Note"/>.</summary>
    public string? NoteKey { get; set; }

    /// <summary>One-line user-facing hint shown when the factor is short of full credit.
    /// Null when fully earned or not counted ("na"). Drives the "+N pts available" nudge list.</summary>
    public string? NextAction { get; set; }

    /// <summary>v2.5.0: i18n key for <see cref="Label"/> so the admin UI can localize it.
    /// Frontend resolves <c>_tr(LabelKey, Label)</c> — Label stays as the English
    /// fallback when the bundle lacks the key.</summary>
    public string? LabelKey { get; set; }

    /// <summary>v2.5.0: i18n key for <see cref="NextAction"/>. Null when fully earned or not counted.</summary>
    public string? NextActionKey { get; set; }

    /// <summary>v2.5.0: interpolation data for <see cref="NextActionKey"/>. The frontend
    /// substitutes <c>{name}</c> placeholders in the translated string with values from
    /// this dictionary (e.g., <c>{ "count": 3 }</c> for the coverage / audit-chain hints).
    /// Null when the action has no dynamic data.</summary>
    public Dictionary<string, object>? NextActionData { get; set; }
}

public class SecurityScore
{
    public int Total { get; set; }
    public int Possible { get; set; }

    /// <summary>Letter grade: A (>=90), B+ (80-89), B (70-79), C (60-69), D (50-59), F (&lt;50).</summary>
    public string Grade { get; set; } = "F";

    public List<ScoreFactor> Factors { get; set; } = new();

    public DateTime ComputedAt { get; set; }
}

public class ScoreSnapshot
{
    /// <summary>Calendar date in YYYY-MM-DD (UTC). Used as the dedupe key — one row per UTC day.</summary>
    public string Date { get; set; } = string.Empty;

    public int Score { get; set; }
}
