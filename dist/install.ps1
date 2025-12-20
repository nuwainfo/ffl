#Requires -Version 5
$ErrorActionPreference = "Stop"

$repoOwner = "nuwainfo"
$repoName  = "ffl"
$app       = "ffl"
$releaseTag = "v3.7.6"  # Default release version

# Overridables: FFL_VERSION, FFL_VARIANT(native|com), FFL_APE(ffl|fflo|ffl.com|fflo.com), FFL_PREFIX
$tag     = if ([string]::IsNullOrWhiteSpace($env:FFL_VERSION)) { $releaseTag } else { $env:FFL_VERSION }
$variant = if ([string]::IsNullOrWhiteSpace($env:FFL_VARIANT)) { "native" } else { $env:FFL_VARIANT }
$apeName = if ([string]::IsNullOrWhiteSpace($env:FFL_APE)) { "ffl.com" } else { $env:FFL_APE }
if ($apeName -notmatch '\.com$') { $apeName = "$apeName.com" }

# Architecture detection
$arch = "amd64"
try {
  if ((Get-CimInstance Win32_Processor).Architecture -eq 12) {
    $arch = "arm64"
  }
} catch {
  # Default to amd64 if detection fails
}

function getReleaseHtml($url) {
  Invoke-WebRequest -UseBasicParsing -Uri $url | Select-Object -ExpandProperty Content
}

function isPeExecutable($path) {
  try {
    $fileStream = [System.IO.File]::OpenRead($path)
    $bytes = New-Object byte[] 2
    $null = $fileStream.Read($bytes, 0, 2)
    $fileStream.Close()
    return ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) # MZ
  } catch {
    return $false
  }
}

function expandZipArchive($zipPath, $destination) {
  try {
    Expand-Archive -Path $zipPath -DestinationPath $destination -Force -ErrorAction Stop
    return
  } catch {
    Write-Warning ("Expand-Archive failed: " + $_.Exception.Message)
  }

  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $destination, $true)
    return
  } catch {
    Get-ChildItem -Path (Split-Path $zipPath) | Write-Host
    throw "Zip extract failed: $($zipPath) -> $destination. Error: $($_.Exception.Message)"
  }
}

# 1) Fetch expanded assets HTML fragment (GitHub loads assets via lazy-loaded fragment)
$assetsUrl = "https://github.com/$repoOwner/$repoName/releases/expanded_assets/$tag"
Write-Host "Fetching release from: $assetsUrl"

$html = getReleaseHtml $assetsUrl

# 2) Extract download URLs from HTML
# GitHub release pages have download links in format: href="/owner/repo/releases/download/tag/filename"
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

function pickComAsset {
  $esc = [regex]::Escape($apeName)
  $asset = $assets | Where-Object { $_.name -match ("^" + $esc + '($|\.zip$|\.tar\.gz$)') } | Select-Object -First 1
  if (-not $asset -and $apeName -ne "ffl.com") { $asset = $assets | Where-Object { $_.name -match '^ffl\.com($|\.zip$|\.tar\.gz$)' } | Select-Object -First 1 }
  $asset
}

function pickNativeAsset {
  $archRegex = '(amd64|x86_64|x64)'
  $assets | Where-Object {
    $_.name -match 'windows' -and $_.name -match $archRegex -and ($_.name -match '\.zip$' -or $_.name -match '\.exe$')
  } | Select-Object -First 1
}

$asset = if ($variant -eq "com") { pickComAsset } else { pickNativeAsset }
if (-not $asset) {
  $names = ($assets | ForEach-Object { $_.name }) -join ", "
  throw "No matching asset for variant=$variant in tag $tag. Available: $names"
}
Write-Host ("Picked asset: " + $asset.name)

# 3) Download
$packagePath = Join-Path $env:TEMP $asset.name
Invoke-WebRequest -UseBasicParsing -Uri $asset.browserDownloadUrl -OutFile $packagePath

# 4) Install directory
$installDir = if ($env:FFL_PREFIX) { Join-Path $env:FFL_PREFIX 'bin' } else { Join-Path $env:LOCALAPPDATA "Programs\$app" }
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

# 5) Deploy
if ($variant -eq "com") {
  if ($asset.name -match '\.com$') {
    Copy-Item $packagePath (Join-Path $installDir "$app.com") -Force
  } elseif ($asset.name -match '\.zip$') {
    expandZipArchive $packagePath $installDir
  } else {
    throw "ffl.com packaged as tar.gz is not supported on Windows installer; please publish .com or .zip"
  }

  $binaryPath = Get-ChildItem -Path $installDir -Filter "$app.com" -Recurse | Select-Object -First 1
  if (-not $binaryPath) {
    Get-ChildItem -Recurse $installDir | Write-Host
    throw "$app.com not found under $installDir"
  }

  # shim: ffl.cmd -> ffl.com (handy for Command Prompt / new shells)
  $shimPath = Join-Path $installDir "ffl.cmd"
@"
@echo off
"%~dp0ffl.com" %*
"@ | Out-File -Encoding ascii -FilePath $shimPath -Force

  Write-Host "Installed (com) to $installDir"

  # Make available immediately in current step
  if (-not (($env:Path -split ";") -contains $installDir)) {
    $env:Path = ($env:Path + ";" + $installDir).Trim(";")
  }
  # If running in GitHub Actions, also expose to subsequent steps
  if ($env:GITHUB_PATH) {
    Add-Content -Path $env:GITHUB_PATH -Value $installDir
  }

} else {
  if (isPeExecutable $packagePath) {
    $exePath = Join-Path $installDir "$app.exe"
    Copy-Item $packagePath $exePath -Force
  } else {
    expandZipArchive $packagePath $installDir
  }

  $binaryPath = Get-ChildItem -Path $installDir -Filter "$app.exe" -Recurse | Select-Object -First 1
  if (-not $binaryPath) {
    Get-ChildItem -Recurse $installDir | Write-Host
    throw "$app.exe not found under $installDir"
  }

  Write-Host "Installed (native) to $installDir"

  if (-not (($env:Path -split ";") -contains $installDir)) {
    $env:Path = ($env:Path + ";" + $installDir).Trim(";")
  }
  if ($env:GITHUB_PATH) {
    Add-Content -Path $env:GITHUB_PATH -Value $installDir
  }
}

# 6) PATH (user scope, for future shells)
$userPath = [Environment]::GetEnvironmentVariable("Path","User")
if (-not (($userPath -split ";") -contains $installDir)) {
  [Environment]::SetEnvironmentVariable("Path", ($userPath + ";" + $installDir).Trim(";"), "User")
  Write-Host "PATH updated (user scope). Open a new terminal to use 'ffl'."
}

# 7) Verify (use ffl.com when variant=com)
try {
  if ($variant -eq "com") {
    & (Join-Path $installDir "$app.com") --version | Out-Host
  } else {
    & $binaryPath.FullName --version | Out-Host
  }
} catch {
  Write-Warning "Running version command failed: $($_.Exception.Message)"
}
