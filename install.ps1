#Requires -Version 5
$ErrorActionPreference = "Stop"

$RepoOwner = "nuwainfo"
$RepoName  = "ffl"
$app       = "ffl"

# 可覆寫：FFL_VERSION、FFL_VARIANT(native|com)、FFL_PREFIX
$tag     = $env:FFL_VERSION
$variant = if ([string]::IsNullOrWhiteSpace($env:FFL_VARIANT)) { "native" } else { $env:FFL_VARIANT }

# 架構偵測（x64 / ARM64）
$arch = "amd64"
try { if ((Get-CimInstance Win32_Processor).Architecture -eq 12) { $arch = "arm64" } } catch {}

function Get-Json($url) {
  $headers = @{}
  if ($env:GITHUB_TOKEN) {
    $headers["Authorization"] = "Bearer $($env:GITHUB_TOKEN)"
    $headers["X-GitHub-Api-Version"] = "2022-11-28"
  }
  Invoke-RestMethod -UseBasicParsing -Headers $headers -Uri $url
}

# --- 讀取檔頭（辨識是否其實是 .exe 單檔） ---
function Test-IsPE($path) {
  try {
    $fs = [System.IO.File]::OpenRead($path)
    $bytes = New-Object byte[] 2
    $null = $fs.Read($bytes, 0, 2)
    $fs.Close()
    return ($bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) # 'M' 'Z'
  } catch { return $false }
}

# --- 解壓小工具（支援 Expand-Archive 失敗時的 fallback） ---
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

# 1) 取 release JSON
if ([string]::IsNullOrWhiteSpace($tag)) {
  $rel = Get-Json "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
} else {
  $rel = Get-Json "https://api.github.com/repos/$RepoOwner/$RepoName/releases/tags/$tag"
}
$tag = $rel.tag_name
if ([string]::IsNullOrWhiteSpace($tag)) { throw "Cannot determine release tag" }

$assets = $rel.assets

function Pick-Com {
  $assets | Where-Object { $_.name -match 'ffl\.com($|\.zip$|\.tar\.gz$)' } | Select-Object -First 1
}
function Pick-Native {
  # 接受 amd64 / x86_64 / x64
  $archRe = '(amd64|x86_64|x64)'
  $assets | Where-Object {
    $_.name -match 'windows' -and $_.name -match $archRe -and ($_.name -match '\.zip$' -or $_.name -match '\.exe$')
  } | Select-Object -First 1
}

$asset = if ($variant -eq "com") { Pick-Com }
