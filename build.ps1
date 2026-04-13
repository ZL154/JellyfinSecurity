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

# Copy only the required files
$RequiredFiles = @(
    "Jellyfin.Plugin.TwoFactorAuth.dll",
    "Otp.NET.dll",
    "QRCoder.dll"
)

foreach ($file in $RequiredFiles) {
    Copy-Item "$PSScriptRoot\dist\publish\$file" $OutputDir
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
