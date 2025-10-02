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
    $_.name -match 'windows' -and $_.name -match $archRe -and $_.name -match '\.zip$'
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
    Expand-Archive -Path $pkg -DestinationPath $dest -Force
  } else {
    throw "ffl.com packaged as tar.gz is not supported on Windows installer; please publish .com or .zip"
  }
  $bin = Get-ChildItem -Path $dest -Filter "$app.com" -Recurse | Select-Object -First 1
  if (-not $bin) { Get-ChildItem -Recurse $dest | Write-Host; throw "ffl.com not found under $dest" }
  # shim：ffl.cmd 轉呼叫 ffl.com
  $shim = Join-Path $dest "ffl.cmd"
@"
@echo off
"%~dp0ffl.com" %*
"@ | Out-File -Encoding ascii -FilePath $shim -Force

  Write-Host "Installed (com) to $dest"
} else {
  Expand-Archive -Path $pkg -DestinationPath $dest -Force
  $bin = Get-ChildItem -Path $dest -Filter "$app.exe" -Recurse | Select-Object -First 1
  if (-not $bin) { Get-ChildItem -Recurse $dest | Write-Host; throw "$app.exe not found under $dest" }
  Write-Host "Installed (native) to $dest"
}

# 5) PATH（使用者層級）
$userPath = [Environment]::GetEnvironmentVariable("Path","User")
if (-not (($userPath -split ";") -contains $dest)) {
  [Environment]::SetEnvironmentVariable("Path", ($userPath + ";" + $dest).Trim(";"), "User")
  Write-Host "PATH updated (user scope). Open a new terminal to use 'ffl'."
}

# 6) 驗證（不讓非零版號退出碼導致整體 fail；只檢查可執行檔存在）
try {
  & $bin.FullName --version | Out-Host
} catch {
  Write-Warning "Running '$($bin.Name) --version' failed: $($_.Exception.Message)"
}
