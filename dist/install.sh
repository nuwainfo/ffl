#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="nuwainfo"
REPO_NAME="ffl"
APP="ffl"
RELEASE_TAG="v3.8.0"  # Default release version

# Environment variables (overridable)
# FFL_VERSION: Version to install (e.g., v3.7.6)
# FFL_VARIANT: Variant to install (native|glibc|manylinux|com)
# FFL_APE: APE binary name (ffl|fflo|ffl.com|fflo.com)
# FFL_GLIBC: Force specific glibc version (2.39, 2.28) for Linux native variant
# FFL_PREFIX: Install prefix directory
# FFL_TARGET: Full install path (e.g., /abc/ffl_123)
tag="${FFL_VERSION:-$RELEASE_TAG}"
variant="${FFL_VARIANT:-native}"
prefix="${FFL_PREFIX:-}"
target="${FFL_TARGET:-}"
ape="${FFL_APE:-ffl.com}"
glibc="${FFL_GLIBC:-}"
[[ "$ape" != *.com ]] && ape="${ape}.com"

# Platform detection
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
archRaw="$(uname -m)"
case "$archRaw" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported arch: $archRaw"; exit 1 ;;
esac

# ============================================================================
# Utility Functions
# ============================================================================

hasCommand() {
  command -v "$1" >/dev/null 2>&1
}

fetchHtml() {
  local url="$1"
  hasCommand curl && curl -fsSL "$url" || wget -qO- "$url"
}

getAssetUrlByName() {
  local want="$1"
  local escaped="${want//./\\.}"
  printf '%s\n' "$assetsData" | grep "/${escaped}$" | head -n1
}

isElf() {
  [ "$(head -c 4 "$1" | LC_ALL=C tr -d '\0')" = $'\x7f''ELF' ]
}

isPe() {
  head -c 2 "$1" | grep -q "^MZ$"
}

isMacho() {
  local magic="$(dd if="$1" bs=4 count=1 2>/dev/null | hexdump -v -e '1/1 "%02x"')"
  case "$magic" in
    cffaedfe|feedface|feeface|cafebabe) return 0 ;;
  esac
  return 1
}

isExecutable() {
  isElf "$1" || isMacho "$1" || isPe "$1"
}

# ============================================================================
# Glibc Detection (Linux only)
# ============================================================================

detectGlibcVersion() {
  [ "$os" != "linux" ] && return

  local version=""
  if hasCommand getconf; then
    version="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
  fi

  if [ -z "$version" ] && hasCommand ldd; then
    version="$(ldd --version 2>/dev/null | head -n1 | grep -Eo '([0-9]+\.){1,2}[0-9]+' | head -n1)"
  fi

  printf '%s' "$version"
}

isVersionGreaterOrEqual() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

pickGlibcBaseline() {
  # Check if FFL_GLIBC is explicitly set (for upgrades)
  if [ -n "${glibc:-}" ]; then
    echo "$glibc"
    return
  fi

  local systemVersion="$(detectGlibcVersion)"
  local glibcTargets=("2.39" "2.28")

  [ -z "$systemVersion" ] && { echo "fallback"; return; }

  for baseline in "${glibcTargets[@]}"; do
    isVersionGreaterOrEqual "$systemVersion" "$baseline" && { echo "$baseline"; return; }
  done

  echo "2.28"  # Fallback to lowest
}

# ============================================================================
# Asset Selection
# ============================================================================

chooseAsset() {
  local targetOs="$1" targetArch="$2" targetVariant="$3"
  local archRegex=""

  case "$targetArch" in
    amd64) archRegex='(amd64|x86_64|x64)' ;;
    arm64) archRegex='(arm64|aarch64|aarch)' ;;
    *) archRegex="$targetArch" ;;
  esac

  shopt -s nocasematch
  local selectedAsset=""

  while IFS= read -r name; do
    [ -z "$name" ] && continue

    case "$targetVariant" in
      com)
        local apeRe="${ape//./\\.}"
        [[ "$name" =~ ${apeRe}($|\.zip$|\.tar\.gz$) ]] && { selectedAsset="$name"; break; }
        ;;

      glibc|manylinux|native)
        if [ "$targetOs" = "linux" ]; then
          [[ "$name" =~ linux && "$name" =~ $archRegex && "$name" =~ \.(tar\.gz|tgz)$ ]] || continue

          [ -z "${_fflGlibcBaseline:-}" ] && _fflGlibcBaseline="$(pickGlibcBaseline)"

          case "$_fflGlibcBaseline" in
            "2.39") [[ "$name" =~ glibc2\.39 ]] && { selectedAsset="$name"; break; } ;;
            "2.28") [[ "$name" =~ glibc2\.28 ]] && { selectedAsset="$name"; break; } ;;
            "fallback") continue ;;
          esac

        elif [ "$targetOs" = "darwin" ]; then
          [[ ("$name" =~ mac || "$name" =~ (darwin|macos)) && "$name" =~ $archRegex && "$name" =~ \.(zip|tar\.gz|tgz)$ ]] && { selectedAsset="$name"; break; }
        fi
        ;;
    esac
  done <<< "$namesList"

  echo "$selectedAsset"
}

# ============================================================================
# Archive Extraction
# ============================================================================

extractArchive() {
  local archivePath="$1" outputDir="$2"
  mkdir -p "$outputDir"

  # Try multiple extraction methods
  hasCommand bsdtar && bsdtar -tf "$archivePath" >/dev/null 2>&1 && bsdtar -xf "$archivePath" -C "$outputDir" && return 0
  tar -tzf "$archivePath" >/dev/null 2>&1 && tar -xzf "$archivePath" -C "$outputDir" && return 0
  tar -tJf "$archivePath" >/dev/null 2>&1 && tar -xJf "$archivePath" -C "$outputDir" && return 0
  tar --help 2>/dev/null | grep -q -- '--zstd' && tar --zstd -tf "$archivePath" >/dev/null 2>&1 && tar --zstd -xf "$archivePath" -C "$outputDir" && return 0
  tar -tf "$archivePath" >/dev/null 2>&1 && tar -xf "$archivePath" -C "$outputDir" && return 0
  hasCommand unzip && unzip -tq "$archivePath" >/dev/null 2>&1 && unzip -q "$archivePath" -d "$outputDir" && return 0

  # Fallback: if file is executable, copy directly
  isExecutable "$archivePath" && cp "$archivePath" "$outputDir/" && return 0

  echo "Cannot extract archive: $archivePath"
  return 1
}

findBinaryInDir() {
  local searchDir="$1" binaryName="$2"
  local binaryPath=""

  # Try exact name first
  binaryPath="$(find "$searchDir" -maxdepth 6 -type f -name "$binaryName" | head -n1)"
  [ -n "$binaryPath" ] && { echo "$binaryPath"; return; }

  # Try pattern match
  binaryPath="$(find "$searchDir" -maxdepth 6 -type f -regex ".*/${binaryName}[_-].*" | head -n1)"
  [ -n "$binaryPath" ] && { echo "$binaryPath"; return; }

  # Try any executable with name
  binaryPath="$(find "$searchDir" -maxdepth 6 -type f -perm -111 -iname "*${binaryName}*" | head -n1)"
  echo "$binaryPath"
}

# ============================================================================
# Installation
# ============================================================================

determineInstallDir() {
  if [ -n "$target" ]; then
    dirname "$target"
  elif [ -n "$prefix" ]; then
    echo "$prefix/bin"
  elif [ -w /usr/local/bin ]; then
    echo "/usr/local/bin"
  else
    echo "$HOME/.local/bin"
  fi
}

installBinary() {
  local sourcePath="$1" destPath="$2"
  install -m 0755 "$sourcePath" "$destPath"

  # Suppress install location messages during upgrade
  if [ -z "${FFL_UPGRADE:-}" ]; then
    echo "Installed to $destPath"

    case ":$PATH:" in
      *":$(dirname "$destPath"):"*) ;;
      *) echo "Note: add $(dirname "$destPath") to PATH" ;;
    esac
  fi

  "$destPath" --version || true
}

installApeVariant() {
  local downloadFile="$1" installDir="$2"
  local binaryPath=""

  if [[ "$assetName" =~ \.com$ ]]; then
    # Direct .com file
    local destPath="${target:-$installDir/$APP.com}"
    installBinary "$downloadFile" "$destPath"
    binaryPath="$destPath"
  else
    # Archive containing .com file
    local unpackDir="$tmpDir/unpack"
    extractArchive "$downloadFile" "$unpackDir"

    binaryPath="$(find "$unpackDir" -type f \( -name "$APP.com" -o -name "$APP" -o -name "$APP.exe" \) | head -n1)"
    [ -z "$binaryPath" ] && { echo "$APP.com not found in archive"; exit 1; }

    case "$binaryPath" in
      *.com)
        local destPath="${target:-$installDir/$APP.com}"
        installBinary "$binaryPath" "$destPath"
        [ -z "$target" ] && ln -sf "$APP.com" "$installDir/$APP"
        ;;
      *.exe|*)
        installBinary "$binaryPath" "${target:-$installDir/$APP}"
        ;;
    esac
  fi

  [ -z "$target" ] && ln -sf "$APP.com" "$installDir/$APP" 2>/dev/null || true
}

installNativeVariant() {
  local downloadFile="$1" installDir="$2"
  local unpackDir="$tmpDir/unpack"

  extractArchive "$downloadFile" "$unpackDir"

  local binaryPath="$(findBinaryInDir "$unpackDir" "$APP")"

  # If not found in archive, check if download itself is executable
  [ -z "$binaryPath" ] && isExecutable "$downloadFile" && binaryPath="$downloadFile"

  [ -z "$binaryPath" ] && { echo "Executable '$APP' not found in archive"; exit 1; }

  chmod +x "$binaryPath" || true
  local destPath="${target:-$installDir/$APP}"
  installBinary "$binaryPath" "$destPath"
}

# ============================================================================
# Main Execution
# ============================================================================

# Fetch release assets
assetsUrl="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/expanded_assets/${tag}"
echo "Fetching release from: $assetsUrl"

assetsHtml="$(fetchHtml "$assetsUrl")"
assetsData="$(printf '%s\n' "$assetsHtml" | grep -oE "/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/[^\">< ]+" | sed 's|^|https://github.com|')"
namesList="$(printf '%s\n' "$assetsData" | sed "s|.*/||")"

# Choose appropriate asset
assetName="$(chooseAsset "$os" "$arch" "$variant")"

# Linux: fallback to APE if no glibc match
if [ -z "$assetName" ] && [ "$os" = "linux" ]; then
  local apeEsc="${ape//./\\.}"
  if printf '%s\n' "$namesList" | grep -qiE "^${apeEsc}$|/${apeEsc}$"; then
    assetName="$ape"
    variant="com"
    echo "No compatible glibc archive; falling back to APE ($ape)"
  elif [ "$ape" != "ffl.com" ] && printf '%s\n' "$namesList" | grep -qiE '^ffl\.com$|/ffl\.com$'; then
    assetName="ffl.com"
    variant="com"
    echo "No compatible glibc archive; requested APE ($ape) not found; falling back to APE (ffl.com)"
  fi
fi

echo "Picked asset: ${assetName:-<none>}"

[ -z "$assetName" ] && {
  echo "No matching asset for OS=$os ARCH=$arch VARIANT=$variant in tag $tag."
  echo "Available assets:"; IFS=$'\n'; for x in $namesList; do [ -n "$x" ] && printf '  - %s\n' "$x"; done
  exit 1
}

# Download asset
downloadUrl="$(getAssetUrlByName "$assetName")"
[ -z "$downloadUrl" ] && { echo "Download URL not found for $assetName"; exit 1; }

tmpDir="$(mktemp -d)"; trap 'rm -rf "$tmpDir"' EXIT
downloadFile="$tmpDir/$assetName"

echo "Downloading $assetName"
hasCommand curl && curl -fL --retry 3 -o "$downloadFile" "$downloadUrl" || wget -O "$downloadFile" "$downloadUrl"

# Install binary
installDir="$(determineInstallDir)"
mkdir -p "$installDir"

if [ "$variant" = "com" ]; then
  installApeVariant "$downloadFile" "$installDir"
else
  installNativeVariant "$downloadFile" "$installDir"
fi
