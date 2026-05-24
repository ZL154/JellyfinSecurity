# Build and package the Jellyfin 2FA plugin
param(
    [string]$Configuration = "Release",
    [switch]$Install
)

$ProjectDir = "$PSScriptRoot\src\Jellyfin.Plugin.TwoFactorAuth"
$OutputDir = "$PSScriptRoot\dist\TwoFactorAuth"

# Clean output
if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Build
Write-Host "Building plugin ($Configuration)..." -ForegroundColor Cyan
dotnet publish $ProjectDir -c $Configuration -o "$PSScriptRoot\dist\publish" --nologo
if ($LASTEXITCODE -ne 0) { exit 1 }

# Copy only the required files (matches build.sh fat-package list)
$RequiredFiles = @(
    "Jellyfin.Plugin.TwoFactorAuth.dll",
    "Otp.NET.dll",
    "QRCoder.dll",
    "Fido2.dll",
    "Fido2.Models.dll",
    "NSec.Cryptography.dll",
    "System.Formats.Cbor.dll",
    "Microsoft.Bcl.Memory.dll",
    "MaxMind.Db.dll",
    "QuestPDF.dll",
    "IdentityModel.OidcClient.dll",
    "IdentityModel.dll",
    "Microsoft.IdentityModel.Abstractions.dll",
    "Microsoft.IdentityModel.JsonWebTokens.dll",
    "Microsoft.IdentityModel.Logging.dll",
    "Microsoft.IdentityModel.Tokens.dll",
    "System.IdentityModel.Tokens.Jwt.dll",
    "MailKit.dll",
    "MimeKit.dll",
    "BouncyCastle.Cryptography.dll"
)

foreach ($file in $RequiredFiles) {
    $src = "$PSScriptRoot\dist\publish\$file"
    if (Test-Path $src) {
        Copy-Item $src $OutputDir
    }
}

# Copy meta.json
Copy-Item "$ProjectDir\meta.json" $OutputDir

Write-Host "`nPlugin built to: $OutputDir" -ForegroundColor Green
Write-Host "Files:" -ForegroundColor Gray
Get-ChildItem $OutputDir | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

# Install to Jellyfin if requested
if ($Install) {
    $JellyfinPlugins = "$env:LOCALAPPDATA\jellyfin\plugins\TwoFactorAuth"
    if (Test-Path $JellyfinPlugins) { Remove-Item -Recurse -Force $JellyfinPlugins }
    Copy-Item -Recurse $OutputDir $JellyfinPlugins
    Write-Host "`nInstalled to: $JellyfinPlugins" -ForegroundColor Green
    Write-Host "Restart Jellyfin to load the plugin." -ForegroundColor Yellow
}
