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

function GetJson($url) { Invoke-RestMethod -UseBasicParsing -Uri $url }

# 1) 取 release JSON
if ([string]::IsNullOrWhiteSpace($tag)) {
  $rel = GetJson "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
} else {
  $rel = GetJson "https://api.github.com/repos/$RepoOwner/$RepoName/releases/tags/$tag"
}
$tag = $rel.tag_name
if ([string]::IsNullOrWhiteSpace($tag)) { throw "Cannot determine release tag" }

$assets = $rel.assets

# 2) 照你命名挑檔：不改名，只用關鍵詞/正則
function Pick-Com {
  $assets | Where-Object { $_.name -match 'ffl\.com($|\.zip$|\.tar\.gz$)' } | Select-Object -First 1
}
function Pick-Native {
  param($arch)
  # 接受 amd64 / x86_64 / x64
  $archRe = '(amd64|x86_64|x64)'
  $assets | Where-Object {
    $_.name -match 'windows' -and $_.name -match $archRe -and $_.name -match '\.zip$'
  } | Select-Object -First 1
}

$asset = if ($variant -eq "com") { Pick-Com } else { Pick-Native -arch $arch }
Write-Host ("Picked asset: " + $asset.name)

if (-not $asset) {
  $names = ($assets | ForEach-Object { $_.name }) -join ", "
  throw "No matching asset for variant=$variant arch=$arch in tag $tag. Available: $names"
}

# 3) 下載與安裝
$pkg = Join-Path $env:TEMP $asset.name
Invoke-WebRequest -UseBasicParsing -Uri $asset.browser_download_url -OutFile $pkg

$dest = if ($env:FFL_PREFIX) { Join-Path $env:FFL_PREFIX 'bin' } else { Join-Path $env:LOCALAPPDATA "Programs\$app" }
New-Item -ItemType Directory -Force -Path $dest | Out-Null

if ($variant -eq "com") {
  if ($asset.name -match '\.com$') {
    Copy-Item $pkg (Join-Path $dest "$app.com") -Force
  } elseif ($asset.name -match '\.zip$') {
    Expand-Archive -Path $pkg -DestinationPath $dest -Force
  } else {
    throw "ffl.com packaged as tar.gz is not supported on Windows installer; please publish .com or .zip"
  }
  $com = Get-ChildItem -Path $dest -Filter "$app.com" -Recurse | Select-Object -First 1
  if (-not $com) { throw "ffl.com not found under $dest" }
  # shim：ffl.cmd 轉呼叫 ffl.com
  $shim = Join-Path $dest "ffl.cmd"
@"
@echo off
"%~dp0ffl.com" %*
"@ | Out-File -Encoding ascii -FilePath $shim -Force
  Write-Host "Installed (com) to $dest"
} else {
  Expand-Archive -Path $pkg -DestinationPath $dest -Force
  $exe = Get-ChildItem -Path $dest -Filter "$app.exe" -Recurse | Select-Object -First 1
  if (-not $exe) { throw "$app.exe not found under $dest" }
  & $exe.FullName --version | Out-Host
  Write-Host "Installed (native) to $dest"
}

# 4) PATH（使用者層級）
$userPath = [Environment]::GetEnvironmentVariable("Path","User")
if (-not (($userPath -split ";") -contains $dest)) {
  [Environment]::SetEnvironmentVariable("Path", ($userPath + ";" + $dest).Trim(";"), "User")
  Write-Host "PATH updated. Open a new terminal to use 'ffl'."
}
