# Lantern Windows Installer (PowerShell)
# Usage:
#   irm https://raw.githubusercontent.com/DhyaanKanoja11/Lantern/main/install.ps1 | iex

$ErrorActionPreference = 'Stop'

$Repo = "DhyaanKanoja11/Lantern"
$FallbackVersion = "v0.3.0"
$InstallDir = "$env:LOCALAPPDATA\Programs\Lantern\bin"

function Write-Info($msg) { Write-Host "==> " -ForegroundColor Cyan -NoNewline; Write-Host $msg }
function Write-Success($msg) { Write-Host "==> " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Write-Warn($msg) { Write-Host "Warning: " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Write-Err($msg) { Write-Host "Error: " -ForegroundColor Red -NoNewline; Write-Host $msg }

# Determine Version
Write-Info "Resolving latest Lantern release..."
$Version = $env:LANTERN_VERSION
if (-not $Version) {
    try {
        $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ "Accept" = "application/vnd.github.v3+json" }
        $Version = $Release.tag_name
    } catch {
        Write-Warn "Could not query GitHub API for latest release; falling back to $FallbackVersion"
        $Version = $FallbackVersion
    }
}

$CleanVer = $Version.TrimStart('v')
$ArchiveName = "lantern_${CleanVer}_windows_amd64.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$ArchiveName"
$ChecksumsUrl = "https://github.com/$Repo/releases/download/$Version/checksums.txt"

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $TempDir -Force | Out-Null

try {
    Write-Info "Downloading Lantern $Version (windows/amd64)..."
    $ZipPath = Join-Path $TempDir $ArchiveName
    $ChecksumsPath = Join-Path $TempDir "checksums.txt"

    Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath
    try {
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath
    } catch {
        Write-Warn "Checksums file unavailable; proceeding with archive verification"
    }

    if (Test-Path $ChecksumsPath) {
        Write-Info "Verifying SHA-256 checksum..."
        $ExpectedHash = (Get-Content $ChecksumsPath | Where-Object { $_ -match $ArchiveName } | ForEach-Object { ($_ -split '\s+')[0] })
        if ($ExpectedHash) {
            $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLower()
            if ($ActualHash -ne $ExpectedHash.ToLower()) {
                Write-Err "Checksum verification failed! Expected: $ExpectedHash, Got: $ActualHash"
                exit 1
            }
            Write-Success "Checksum verified."
        }
    }

    Write-Info "Extracting binary..."
    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item -Path (Join-Path $ExtractDir "lantern.exe") -Destination (Join-Path $InstallDir "lantern.exe") -Force

    Write-Success "Installed Lantern to: $InstallDir\lantern.exe"

    # Verify and add to user PATH if not present
    $UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)
    if ($UserPath -notlike "*$InstallDir*") {
        Write-Info "Adding $InstallDir to user PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", [EnvironmentVariableTarget]::User)
        $env:Path = "$env:Path;$InstallDir"
        Write-Success "Added to user PATH."
    }

    Write-Host ""
    Write-Host "Lantern is ready to use!" -ForegroundColor Green
    Write-Host "Run 'lantern --help' or 'lantern scan' to get started." -ForegroundColor Cyan
} finally {
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
}
