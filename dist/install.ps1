#Requires -Version 5
$ErrorActionPreference = "Stop"

$repoOwner = "nuwainfo"
$repoName  = "ffl"
$app       = "ffl"
$releaseTag = "v3.8.2"  # Default release version

# Environment variables (overridable)
# FFL_VERSION: Version to install (e.g., v3.7.6)
# FFL_VARIANT: Variant to install (native|com)
# FFL_APE: APE binary name (ffl|fflo|ffl.com|fflo.com)
# FFL_PREFIX: Install prefix directory
# FFL_TARGET: Full install path (e.g., C:\abc\ffl_123.exe)
$tag     = if ([string]::IsNullOrWhiteSpace($env:FFL_VERSION)) { $releaseTag } else { $env:FFL_VERSION }
$variant = if ([string]::IsNullOrWhiteSpace($env:FFL_VARIANT)) { "native" } else { $env:FFL_VARIANT }
$apeName = if ([string]::IsNullOrWhiteSpace($env:FFL_APE)) { "ffl.com" } else { $env:FFL_APE }
if ($apeName -notmatch '\.com$') { $apeName = "$apeName.com" }
$target = $env:FFL_TARGET

# Platform detection
$arch = "amd64"
try {
  if ((Get-CimInstance Win32_Processor).Architecture -eq 12) {
    $arch = "arm64"
  }
} catch {
  # Default to amd64 if detection fails
}

# ============================================================================
# Utility Functions
# ============================================================================

function Get-ReleaseHtml($url) {
  (Invoke-WebRequest -UseBasicParsing -Uri $url).Content
}

function Test-PeExecutable($path) {
  try {
    $fileStream = [System.IO.File]::OpenRead($path)
    $bytes = New-Object byte[] 2
    $null = $fileStream.Read($bytes, 0, 2)
    $fileStream.Close()
    return ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) # MZ header
  } catch {
    return $false
  }
}

function Expand-ZipArchive($zipPath, $destination) {
  try {
    Expand-Archive -Path $zipPath -DestinationPath $destination -Force -ErrorAction Stop
    return
  } catch {
    Write-Warning "Expand-Archive failed: $($_.Exception.Message)"
  }

  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destination, $true)
    return
  } catch {
    Get-ChildItem -Path (Split-Path $zipPath) | Write-Host
    throw "Zip extract failed: $zipPath -> $destination. Error: $($_.Exception.Message)"
  }
}

function Find-BinaryInDir($searchDir, $binaryPattern) {
  Get-ChildItem -Path $searchDir -Filter $binaryPattern -Recurse -ErrorAction SilentlyContinue |
    Select-Object -First 1
}

function Add-ToPath($directory) {
  # Add to current session
  if (-not (($env:Path -split ";") -contains $directory)) {
    $env:Path = ($env:Path + ";" + $directory).Trim(";")
  }

  # Add to GitHub Actions PATH if running in CI
  if ($env:GITHUB_PATH) {
    Add-Content -Path $env:GITHUB_PATH -Value $directory
  }
}

function Add-ToUserPath($directory) {
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  if (-not (($userPath -split ";") -contains $directory)) {
    [Environment]::SetEnvironmentVariable("Path", ($userPath + ";" + $directory).Trim(";"), "User")
    Write-Host "PATH updated (user scope). Open a new terminal to use '$app'."
  }
}

function Install-Binary($sourcePath, $destPath) {
  Copy-Item $sourcePath $destPath -Force

  # Suppress install location messages during upgrade
  if ([string]::IsNullOrWhiteSpace($env:FFL_UPGRADE)) {
    Write-Host "Installed to $destPath"
  }
}

function Get-InstallDir() {
  if (-not [string]::IsNullOrWhiteSpace($target)) {
    Split-Path -Parent $target
  } elseif ($env:FFL_PREFIX) {
    Join-Path $env:FFL_PREFIX 'bin'
  } else {
    Join-Path $env:LOCALAPPDATA "Programs\$app"
  }
}

# ============================================================================
# Asset Selection
# ============================================================================

function Select-ApeAsset($assets) {
  $esc = [regex]::Escape($apeName)
  $asset = $assets | Where-Object { $_.name -match ("^" + $esc + '($|\.zip$|\.tar\.gz$)') } |
    Select-Object -First 1

  # Fallback to ffl.com if requested APE not found
  if (-not $asset -and $apeName -ne "ffl.com") {
    $asset = $assets | Where-Object { $_.name -match '^ffl\.com($|\.zip$|\.tar\.gz$)' } |
      Select-Object -First 1
  }

  return $asset
}

function Select-NativeAsset($assets) {
  $archRegex = '(amd64|x86_64|x64)'
  $assets | Where-Object {
    $_.name -match 'windows' -and
    $_.name -match $archRegex -and
    ($_.name -match '\.zip$' -or $_.name -match '\.exe$')
  } | Select-Object -First 1
}

# ============================================================================
# Installation Functions
# ============================================================================

function Install-ApeVariant($packagePath, $installDir) {
  $binaryPath = $null

  if ($assetName -match '\.com$') {
    # Direct .com file
    $destPath = if (-not [string]::IsNullOrWhiteSpace($target)) {
      $target
    } else {
      Join-Path $installDir "$app.com"
    }

    Install-Binary $packagePath $destPath
    $binaryPath = Get-Item $destPath

  } elseif ($assetName -match '\.zip$') {
    # Extract archive
    Expand-ZipArchive $packagePath $installDir

    $found = Find-BinaryInDir $installDir "$app.com"
    if (-not $found) {
      Get-ChildItem -Recurse $installDir | Write-Host
      throw "$app.com not found under $installDir"
    }

    if (-not [string]::IsNullOrWhiteSpace($target)) {
      Install-Binary $found.FullName $target
      $binaryPath = Get-Item $target
    } else {
      $binaryPath = $found
    }

  } else {
    throw "ffl.com packaged as tar.gz is not supported on Windows installer; please publish .com or .zip"
  }

  if (-not $binaryPath) {
    Get-ChildItem -Recurse $installDir | Write-Host
    throw "$app.com not found under $installDir"
  }

  # Create shim for easier invocation (unless using FFL_TARGET)
  if ([string]::IsNullOrWhiteSpace($target)) {
    $shimPath = Join-Path $installDir "$app.cmd"
    @"
@echo off
"%~dp0$app.com" %*
"@ | Out-File -Encoding ascii -FilePath $shimPath -Force

    # Suppress install location messages during upgrade
    if ([string]::IsNullOrWhiteSpace($env:FFL_UPGRADE)) {
      Write-Host "Installed (com) to $installDir"
    }
    Add-ToPath $installDir
  } elseif ([string]::IsNullOrWhiteSpace($env:FFL_UPGRADE)) {
    Write-Host "Installed (com) to $target"
  }

  return $binaryPath
}

function Install-NativeVariant($packagePath, $installDir) {
  $binaryPath = $null

  if (Test-PeExecutable $packagePath) {
    # Direct executable file
    $destPath = if (-not [string]::IsNullOrWhiteSpace($target)) {
      $target
    } else {
      Join-Path $installDir "$app.exe"
    }

    Install-Binary $packagePath $destPath
    $binaryPath = Get-Item $destPath

  } else {
    # Extract archive
    Expand-ZipArchive $packagePath $installDir

    $found = Find-BinaryInDir $installDir "$app.exe"
    if (-not $found) {
      Get-ChildItem -Recurse $installDir | Write-Host
      throw "$app.exe not found under $installDir"
    }

    if (-not [string]::IsNullOrWhiteSpace($target)) {
      Install-Binary $found.FullName $target
      $binaryPath = Get-Item $target
    } else {
      $binaryPath = $found
    }
  }

  # Suppress install location messages during upgrade
  if ([string]::IsNullOrWhiteSpace($target)) {
    if ([string]::IsNullOrWhiteSpace($env:FFL_UPGRADE)) {
      Write-Host "Installed (native) to $installDir"
    }
    Add-ToPath $installDir
  } elseif ([string]::IsNullOrWhiteSpace($env:FFL_UPGRADE)) {
    Write-Host "Installed (native) to $target"
  }

  return $binaryPath
}

# ============================================================================
# Main Execution
# ============================================================================

# Fetch release assets
$assetsUrl = "https://github.com/$repoOwner/$repoName/releases/expanded_assets/$tag"
Write-Host "Fetching release from: $assetsUrl"

$html = Get-ReleaseHtml $assetsUrl

# Extract download URLs
$downloadPattern = "/$repoOwner/$repoName/releases/download/$tag/([^"">< ]+)"
$matches = [regex]::Matches($html, $downloadPattern)

$assets = @()
foreach ($match in $matches) {
  $filename = $match.Groups[1].Value
  $url = "https://github.com/$repoOwner/$repoName/releases/download/$tag/$filename"
  $assets += [PSCustomObject]@{
    name = $filename
    browserDownloadUrl = $url
  }
}

# Select appropriate asset
$asset = if ($variant -eq "com") { Select-ApeAsset $assets } else { Select-NativeAsset $assets }

if (-not $asset) {
  $names = ($assets | ForEach-Object { $_.name }) -join ", "
  throw "No matching asset for variant=$variant in tag $tag. Available: $names"
}

Write-Host "Picked asset: $($asset.name)"
$assetName = $asset.name

# Download asset
$packagePath = Join-Path $env:TEMP $assetName
Write-Host "Downloading $assetName"
Invoke-WebRequest -UseBasicParsing -Uri $asset.browserDownloadUrl -OutFile $packagePath

# Install binary
$installDir = Get-InstallDir
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$binaryPath = if ($variant -eq "com") {
  Install-ApeVariant $packagePath $installDir
} else {
  Install-NativeVariant $packagePath $installDir
}

# Update user PATH (unless using FFL_TARGET)
if ([string]::IsNullOrWhiteSpace($target)) {
  Add-ToUserPath $installDir
}

# Verify installation
try {
  if (-not [string]::IsNullOrWhiteSpace($target)) {
    & $binaryPath.FullName --version | Out-Host
  } else {
    if ($variant -eq "com") {
      & (Join-Path $installDir "$app.com") --version | Out-Host
    } else {
      & $binaryPath.FullName --version | Out-Host
    }
  }
} catch {
  Write-Warning "Running version command failed: $($_.Exception.Message)"
}
