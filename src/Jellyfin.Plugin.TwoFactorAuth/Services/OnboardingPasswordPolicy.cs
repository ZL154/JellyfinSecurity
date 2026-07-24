using Jellyfin.Plugin.TwoFactorAuth.Configuration;

namespace Jellyfin.Plugin.TwoFactorAuth.Services;

/// <summary>
/// Canonical OIDC onboarding-password policy. The same normalized values are
/// returned to the browser and enforced by the server.
/// </summary>
internal sealed record OnboardingPasswordPolicy(
    int MinLength,
    bool RequireUppercase,
    bool RequireLowercase,
    bool RequireDigit,
    bool RequireSymbol)
{
    internal static OnboardingPasswordPolicy FromConfiguration(PluginConfiguration? configuration)
        => new(
            Math.Clamp(configuration?.OnboardingPasswordMinLength ?? 16, 1, 256),
            configuration?.OnboardingPasswordRequireUppercase ?? false,
            configuration?.OnboardingPasswordRequireLowercase ?? false,
            configuration?.OnboardingPasswordRequireDigit ?? false,
            configuration?.OnboardingPasswordRequireSymbol ?? false);

    internal string? Validate(string? password)
    {
        var value = password ?? string.Empty;
        if (value.Length < MinLength)
        {
            return $"Password must be at least {MinLength} characters.";
        }

        if (RequireUppercase && !value.Any(char.IsUpper))
        {
            return "Password must contain an uppercase letter.";
        }

        if (RequireLowercase && !value.Any(char.IsLower))
        {
            return "Password must contain a lowercase letter.";
        }

        if (RequireDigit && !value.Any(char.IsDigit))
        {
            return "Password must contain a number.";
        }

        if (RequireSymbol && !value.Any(c => char.IsPunctuation(c) || char.IsSymbol(c)))
        {
            return "Password must contain a symbol.";
        }

        return null;
    }
}
