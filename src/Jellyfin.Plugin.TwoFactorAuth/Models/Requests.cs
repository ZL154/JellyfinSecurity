namespace Jellyfin.Plugin.TwoFactorAuth.Models;

public class VerifyRequest
{
    public string ChallengeToken { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;

    public string Method { get; set; } = "totp";

    public bool TrustDevice { get; set; }
}

public class ConfirmTotpRequest
{
    public string Code { get; set; } = string.Empty;
}

public class RegisterDeviceRequest
{
    public string DeviceId { get; set; } = string.Empty;

    public string DeviceName { get; set; } = string.Empty;
}

public class CreateApiKeyRequest
{
    public string Label { get; set; } = string.Empty;
}

public class SendEmailOtpRequest
{
    public string ChallengeToken { get; set; } = string.Empty;
}

public class ToggleUserRequest
{
    public bool Enabled { get; set; }
}

public class LoginWithCodeRequest
{
    public string Username { get; set; } = string.Empty;

    public string Password { get; set; } = string.Empty;

    public string Code { get; set; } = string.Empty;
}
