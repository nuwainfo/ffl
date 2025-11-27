#Requires -Version 5
$ErrorActionPreference = "Stop"

$RepoOwner = "nuwainfo"
$RepoName  = "ffl"
$app       = "ffl"

# Overridables: FFL_VERSION, FFL_VARIANT(native|com), FFL_PREFIX
$tag     = $env:FFL_VERSION
$variant = if ([string]::IsNullOrWhiteSpace($env:FFL_VARIANT)) { "native" } else { $env:FFL_VARIANT }

# Architecture detection
$arch = "amd64"
try { if ((Get-CimInstance Win32_Processor).Architecture -eq 12) { $arch = "arm64" } } catch {}

function Get-Json($url) {
  # Plain request (no token, no extra headers)
  Invoke-RestMethod -UseBasicParsing -Uri $url
}

function Test-IsPE($path) {
  try {
    $fs = [System.IO.File]::OpenRead($path)
    $bytes = New-Object byte[] 2
    $null = $fs.Read($bytes, 0, 2)
    $fs.Close()
    return ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) # MZ
  } catch { return $false }
}

function Expand-Zip($zipPath, $dest) {
  try {
    Expand-Archive -Path $zipPath -DestinationPath $dest -Force -ErrorAction Stop
  } catch {
    Write-Warning ("Expand-Archive failed: " + $_.Exception.Message)
    try {
      Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
      [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $dest, $true)
    } catch {
      Get-ChildItem -Path (Split-Path $zipPath) | Write-Host
      throw "Zip extract failed: $($zipPath) -> $dest. Error: $($_.Exception.Message)"
    }
  }
}

# --- helpers for tag fetching with tolerance (v-prefix/no-prefix) ---
function Try-GetReleaseByTag([string]$t) {
  if ([string]::IsNullOrWhiteSpace($t)) { return $null }
  try { return Get-Json "https://api.github.com/repos/$RepoOwner/$RepoName/releases/tags/$t" } catch { return $null }
}
function Normalize-Tag-Candidates([string]$t) {
  # Yield candidates: as-is, add/remove 'v' prefix
  if ([string]::IsNullOrWhiteSpace($t)) { return @() }
  $cands = New-Object System.Collections.Generic.List[string]
  $cands.Add($t)
  if ($t -match '^[vV]\d') { $cands.Add(($t.TrimStart('v','V'))) } else { $cands.Add('v' + $t) }
  return $cands
}
# ---------------------------------------------------------------

# 1) Fetch release JSON
if ([string]::IsNullOrWhiteSpace($tag)) {
  $rel = Get-Json "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
} else {
  # Try the provided tag; if not found, try with/without 'v' prefix; then fallback to latest
  $rel = $null
  foreach ($cand in (Normalize-Tag-Candidates $tag)) {
    $rel = Try-GetReleaseByTag $cand
    if ($rel) { $tag = $cand; break }
  }
  if (-not $rel) {
    Write-Warning "Release tag '$tag' not found; falling back to latest"
    $rel = Get-Json "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
  }
}
$tag = $rel.tag_name
if ([string]::IsNullOrWhiteSpace($tag)) { throw "Cannot determine release tag" }
$assets = $rel.assets

function Pick-Com {
  $assets | Where-Object { $_.name -match 'ffl\.com($|\.zip$|\.tar\.gz$)' } | Select-Object -First 1
}
function Pick-Native {
  $archRe = '(amd64|x86_64|x64)'
  $assets | Where-Object {
    $_.name -match 'windows' -and $_.name -match $archRe -and ($_.name -match '\.zip$' -or $_.name -match '\.exe$')
  } | Select-Object -First 1
}

$asset = if ($variant -eq "com") { Pick-Com } else { Pick-Native }
if (-not $asset) {
  $names = ($assets | ForEach-Object { $_.name }) -join ", "
  throw "No matching asset for variant=$variant in tag $tag. Available: $names"
}
Write-Host ("Picked asset: " + $asset.name)

# 2) Download
$pkg = Join-Path $env:TEMP $asset.name
Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $pkg

# 3) Install directory
$dest = if ($env:FFL_PREFIX) { Join-Path $env:FFL_PREFIX 'bin' } else { Join-Path $env:LOCALAPPDATA "Programs\$app" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# 4) Deploy
if ($variant -eq "com") {
  if ($asset.name -match '\.com$') {
    Copy-Item $pkg (Join-Path $dest "$app.com") -Force
  } elseif ($asset.name -match '\.zip$') {
    Expand-Zip $pkg $dest
  } else {
    throw "ffl.com packaged as tar.gz is not supported on Windows installer; please publish .com or .zip"
  }

  $bin = Get-ChildItem -Path $dest -Filter "$app.com" -Recurse | Select-Object -First 1
  if (-not $bin) { Get-ChildItem -Recurse $dest | Write-Host; throw "$app.com not found under $dest" }

  # shim: ffl.cmd -> ffl.com (handy for Command Prompt / new shells)
  $shim = Join-Path $dest "ffl.cmd"
@"
@echo off
"%~dp0ffl.com" %*
"@ | Out-File -Encoding ascii -FilePath $shim -Force

  Write-Host "Installed (com) to $dest"

  # Make available immediately in current step
  if (-not (($env:Path -split ";") -contains $dest)) { $env:Path = ($env:Path + ";" + $dest).Trim(";") }
  # If running in GitHub Actions, also expose to subsequent steps
  if ($env:GITHUB_PATH) { Add-Content -Path $env:GITHUB_PATH -Value $dest }

} else {
  if (Test-IsPE $pkg) {
    $exePath = Join-Path $dest "$app.exe"
    Copy-Item $pkg $exePath -Force
  } else {
    Expand-Zip $pkg $dest
  }
  $bin = Get-ChildItem -Path $dest -Filter "$app.exe" -Recurse | Select-Object -First 1
  if (-not $bin) { Get-ChildItem -Recurse $dest | Write-Host; throw "$app.exe not found under $dest" }
  Write-Host "Installed (native) to $dest"
  if (-not (($env:Path -split ";") -contains $dest)) { $env:Path = ($env:Path + ";" + $dest).Trim(";") }
  if ($env:GITHUB_PATH) { Add-Content -Path $env:GITHUB_PATH -Value $dest }
}

# 5) PATH (user scope, for future shells)
$userPath = [Environment]::GetEnvironmentVariable("Path","User")
if (-not (($userPath -split ";") -contains $dest)) {
  [Environment]::SetEnvironmentVariable("Path", ($userPath + ";" + $dest).Trim(";"), "User")
  Write-Host "PATH updated (user scope). Open a new terminal to use 'ffl'."
}

# 6) Verify (use ffl.com when variant=com)
try {
  if ($variant -eq "com") {
    & (Join-Path $dest "$app.com") --version | Out-Host
  } else {
    & $bin.FullName --version | Out-Host
  }
} catch {
  Write-Warning "Running version command failed: $($_.Exception.Message)"
}
