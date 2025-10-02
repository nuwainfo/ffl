#Requires -Version 5
$ErrorActionPreference = "Stop"

$RepoOwner = "nuwainfo"
$RepoName  = "ffl"
$app       = "ffl"

# 可覆寫：FFL_VERSION、FFL_VARIANT(native|com)、FFL_PREFIX
$tag     = $env:FFL_VERSION
$variant = if ([string]::IsNullOrWhiteSpace($env:FFL_VARIANT)) { "native" } else { $env:FFL_VARIANT }

# 架構偵測
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

# 2) 下載
$pkg = Join-Path $env:TEMP $asset.name
Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $pkg

# 3) 安裝目錄
$dest = if ($env:FFL_PREFIX) { Join-Path $env:FFL_PREFIX 'bin' } else { Join-Path $env:LOCALAPPDATA "Programs\$app" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# 4) 佈署
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

  # shim：ffl.cmd -> ffl.com（給 Command Prompt / 之後新開殼）
  $shim = Join-Path $dest "ffl.cmd"
@"
@echo off
"%~dp0ffl.com" %*
"@ | Out-File -Encoding ascii -FilePath $shim -Force

  Write-Host "Installed (com) to $dest"

  # 讓**當前步驟**可立即呼叫
  if (-not (($env:Path -split ";") -contains $dest)) { $env:Path = ($env:Path + ";" + $dest).Trim(";") }
  # 若在 GitHub Actions，讓**後續步驟**也吃得到
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

# 5) PATH（使用者層級，給未來新殼）
$userPath = [Environment]::GetEnvironmentVariable("Path","User")
if (-not (($userPath -split ";") -contains $dest)) {
  [Environment]::SetEnvironmentVariable("Path", ($userPath + ";" + $dest).Trim(";"), "User")
  Write-Host "PATH updated (user scope). Open a new terminal to use 'ffl'."
}

# 6) 驗證（variant=com 用 ffl.com）
try {
  if ($variant -eq "com") {
    & (Join-Path $dest "$app.com") --version | Out-Host
  } else {
    & $bin.FullName --version | Out-Host
  }
} catch {
  Write-Warning "Running version command failed: $($_.Exception.Message)"
}
