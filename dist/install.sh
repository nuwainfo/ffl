#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="nuwainfo"
REPO_NAME="ffl"
APP="ffl"
RELEASE_TAG="v3.7.6"  # Default release version

# Overridables: FFL_VERSION (e.g. v3.6.2), FFL_VARIANT (native|glibc|manylinux|com), FFL_APE (ffl|fflo|ffl.com|fflo.com), FFL_PREFIX (install prefix)
tag="${FFL_VERSION:-$RELEASE_TAG}"
variant="${FFL_VARIANT:-native}"
prefix="${FFL_PREFIX:-}"
ape="${FFL_APE:-ffl.com}"
if [[ "$ape" != *.com ]]; then ape="${ape}.com"; fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"   # linux/darwin
archRaw="$(uname -m)"
case "$archRaw" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) echo "Unsupported arch: $archRaw"; exit 1 ;;
esac

hasCommand() { command -v "$1" >/dev/null 2>&1; }

fetchHtml() {
  local url="$1"
  if hasCommand curl; then
    curl -fsSL "$url"
  else
    wget -qO- "$url"
  fi
}

# 1) Fetch expanded assets HTML fragment (GitHub loads assets via lazy-loaded fragment)
assetsUrl="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/expanded_assets/${tag}"
echo "Fetching release from: $assetsUrl"

assetsHtml="$(fetchHtml "$assetsUrl")"

# 2) Extract asset names and URLs from HTML
# GitHub release pages have download links in format: href="/owner/repo/releases/download/tag/filename"
assetsData="$(printf '%s\n' "$assetsHtml" | grep -oE "/${REPO_OWNER}/${REPO_NAME}/releases/download/${tag}/[^\">< ]+" | sed 's|^|https://github.com|')"

# Extract just the filenames for matching
namesList="$(printf '%s\n' "$assetsData" | sed "s|.*/||")"

getAssetUrlByName() {
  local want="$1"
  # Escape dots in filename for regex matching
  local escaped="${want//./\\.}"
  printf '%s\n' "$assetsData" | grep "/${escaped}$" | head -n1
}

# ---------- Linux glibc detection & baseline selection ----------
# Returns detected glibc version like "2.39"; empty if not glibc (e.g., musl/Alpine).
detectGlibcVersion() {
  local version=""
  if command -v getconf >/dev/null 2>&1; then
    version="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
  fi
  if [ -z "$version" ] && command -v ldd >/dev/null 2>&1; then
    # e.g. first line: "ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35"
    version="$(ldd --version 2>/dev/null | head -n1 | grep -Eo '([0-9]+\.){1,2}[0-9]+' | head -n1)"
  fi
  printf '%s' "$version"
}

# Compare versions: returns true if $1 >= $2 (with sort -V)
isVersionGreaterOrEqual() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# Pick the glibc baseline we should use among known targets (highest not exceeding system)
pickGlibcBaseline() {
  local systemVersion glibcTargets=("2.39" "2.28")
  systemVersion="$(detectGlibcVersion)"

  if [ -z "$systemVersion" ]; then
    echo "fallback"  # not glibc; will use APE (ffl.com)
    return
  fi

  for baseline in "${glibcTargets[@]}"; do
    if isVersionGreaterOrEqual "$systemVersion" "$baseline"; then
      echo "$baseline"
      return
    fi
  done

  # System glibc lower than our lowest target (2.28): still return 2.28 (may fail; outer logic can fallback to com)
  echo "2.28"
}
# ----------------------------------------------------------------

chooseAsset() {
  # Params: os, arch, variant
  local targetOs="$1" targetArch="$2" targetVariant="$3"
  shopt -s nocasematch

  # Arch alias regex
  local archRegex=""
  case "$targetArch" in
    amd64)  archRegex='(amd64|x86_64|x64)';;
    arm64)  archRegex='(arm64|aarch64|aarch)';;
    *)      archRegex="$targetArch";;
  esac

  local selectedAsset=""
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    case "$targetVariant" in
      com)
        apeRe="${ape//./\\.}"
        if [[ "$name" =~ ${apeRe}($|\.zip$|\.tar\.gz$) ]]; then
          selectedAsset="$name"
          break
        fi
        ;;
      glibc|manylinux|native)
        if [[ "$targetOs" == "linux" ]]; then
          [[ "$name" =~ linux ]] || continue
          [[ "$name" =~ $archRegex ]] || continue
          [[ "$name" =~ \.(tar\.gz|tgz)$ ]] || continue

          # Auto-select Linux glibc baseline between glibc2.39 and glibc2.28
          if [ -z "${_fflGlibcBaseline:-}" ]; then
            _fflGlibcBaseline="$(pickGlibcBaseline)"
          fi

          case "$_fflGlibcBaseline" in
            "2.39")
              # Prefer 2.39; if absent we may fall back to 2.28 later
              if [[ "$name" =~ glibc2\.39 ]]; then
                selectedAsset="$name"
                break
              fi
              ;;
            "2.28")
              if [[ "$name" =~ glibc2\.28 ]]; then
                selectedAsset="$name"
                break
              fi
              ;;
            "fallback")
              # Non-glibc (musl/unknown): skip Linux archives; outer logic will try APE (ffl.com)
              continue
              ;;
          esac

        elif [[ "$targetOs" == "darwin" ]]; then
          # mac assets use "mac"; also accept darwin/macos; support .zip/.tar.gz
          if   [[ "$name" =~ mac ]] && [[ "$name" =~ $archRegex ]] && [[ "$name" =~ \.(zip|tar\.gz|tgz)$ ]]; then
            selectedAsset="$name"
            break
          elif [[ "$name" =~ (darwin|macos) ]] && [[ "$name" =~ $archRegex ]] && [[ "$name" =~ \.(zip|tar\.gz|tgz)$ ]]; then
            selectedAsset="$name"
            break
          fi
        fi
        ;;
    esac
  done <<< "$namesList"

  echo "$selectedAsset"
}

assetName="$(chooseAsset "$os" "$arch" "$variant")"

# Linux: if no matching glibc archive (e.g., musl), fallback to APE automatically
if [ -z "$assetName" ] && [ "$os" = "linux" ]; then
  apeEsc="${ape//./\\.}"
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

if [ -z "$assetName" ]; then
  echo "No matching asset for OS=$os ARCH=$arch VARIANT=$variant in tag $tag."
  echo "Available assets:"; IFS=$'\n'; for x in $namesList; do [ -n "$x" ] && printf '  - %s\n' "$x"; done
  exit 1
fi

downloadUrl="$(getAssetUrlByName "$assetName")"
if [ -z "$downloadUrl" ]; then
  echo "Download URL not found for $assetName"
  exit 1
fi

# 3) Download
tmpDir="$(mktemp -d)"; trap 'rm -rf "$tmpDir"' EXIT
downloadFile="$tmpDir/$assetName"

echo "Downloading $assetName"
if hasCommand curl; then
  curl -fL --retry 3 -o "$downloadFile" "$downloadUrl"
else
  wget -O "$downloadFile" "$downloadUrl"
fi

# 4) Install location
if [ -n "$prefix" ]; then
  installDir="$prefix/bin"
elif [ -w /usr/local/bin ]; then
  installDir="/usr/local/bin"
else
  installDir="$HOME/.local/bin"
fi
mkdir -p "$installDir"

installBinary() {
  local sourcePath="$1" destPath="$2"
  install -m 0755 "$sourcePath" "$destPath"
  echo "Installed to $destPath"
  case ":$PATH:" in
    *":$installDir:"*) ;;
    *) echo "Note: add $installDir to PATH";;
  esac
  "$destPath" --version || true
}

# --- File header detection: ELF / Mach-O / PE ---
isElf() {
  [ "$(head -c 4 "$1" | LC_ALL=C tr -d '\0')" = $'\x7f''ELF' ]
}

isPe() {
  head -c 2 "$1" | grep -q "^MZ$"
}

isMacho() {
  # Use hexdump (available on macOS by default)
  local magic
  magic="$(dd if="$1" bs=4 count=1 2>/dev/null | hexdump -v -e '1/1 "%02x"')"
  case "$magic" in
    cffaedfe|feedface|feeface|cafebabe) return 0;;
  esac
  return 1
}

extractArchive() {
  # Try several formats: bsdtar(auto) -> tar.gz -> tar.xz -> tar.zstd -> tar -> zip.
  # If all fail but the file itself is an executable (mislabelled), treat as single-file install.
  local archivePath="$1" outputDir="$2"
  mkdir -p "$outputDir"

  if hasCommand bsdtar && bsdtar -tf "$archivePath" >/dev/null 2>&1; then
    bsdtar -xf "$archivePath" -C "$outputDir" && return 0
  fi
  if tar -tzf "$archivePath" >/dev/null 2>&1; then
    tar -xzf "$archivePath" -C "$outputDir" && return 0
  fi
  if tar -tJf "$archivePath" >/dev/null 2>&1; then
    tar -xJf "$archivePath" -C "$outputDir" && return 0
  fi
  if tar --help 2>/dev/null | grep -q -- '--zstd' && tar --zstd -tf "$archivePath" >/dev/null 2>&1; then
    tar --zstd -xf "$archivePath" -C "$outputDir" && return 0
  fi
  if tar -tf "$archivePath" >/dev/null 2>&1; then
    tar -xf "$archivePath" -C "$outputDir" && return 0
  fi
  if hasCommand unzip && unzip -tq "$archivePath" >/dev/null 2>&1; then
    unzip -q "$archivePath" -d "$outputDir" && return 0
  fi
  if hasCommand bsdtar; then
    bsdtar -xf "$archivePath" -C "$outputDir" && return 0
  fi

  if isElf "$archivePath" || isMacho "$archivePath" || isPe "$archivePath"; then
    cp "$archivePath" "$outputDir/" && return 0
  fi

  echo "Cannot extract archive: $archivePath"
  return 1
}

# 5) Install
if [[ "$variant" == "com" ]]; then
  if [[ "$assetName" =~ \.com$ ]]; then
    installBinary "$downloadFile" "$installDir/$APP.com"
  else
    unpackDir="$tmpDir/unpack"
    extractArchive "$downloadFile" "$unpackDir"
    binaryPath="$(find "$unpackDir" -type f -name "$APP.com" -o -name "$APP" -o -name "$APP.exe" | head -n1)"

    if [ -z "$binaryPath" ]; then
      echo "ffl.com not found in archive"
      exit 1
    fi

    case "$binaryPath" in
      *.com)
        installBinary "$binaryPath" "$installDir/$APP.com"
        ln -sf "$APP.com" "$installDir/$APP"
        ;;
      *.exe)
        installBinary "$binaryPath" "$installDir/$APP"
        ;;
      *)
        installBinary "$binaryPath" "$installDir/$APP"
        ;;
    esac
  fi
  ln -sf "$APP.com" "$installDir/$APP" 2>/dev/null || true
else
  unpackDir="$tmpDir/unpack"
  extractArchive "$downloadFile" "$unpackDir"

  # Prefer exact name, then ffl_*, then any executable containing "ffl"
  binaryPath="$(find "$unpackDir" -maxdepth 6 -type f -name "$APP" | head -n1)"
  if [ -z "$binaryPath" ]; then
    binaryPath="$(find "$unpackDir" -maxdepth 6 -type f -regex ".*/${APP}[_-].*" | head -n1)"
  fi
  if [ -z "$binaryPath" ]; then
    binaryPath="$(find "$unpackDir" -maxdepth 6 -type f -perm -111 -iname "*$APP*" | head -n1)"
  fi
  if [ -z "$binaryPath" ]; then
    # If the downloaded file is actually a single binary (mislabelled), use it.
    if isElf "$downloadFile" || isMacho "$downloadFile" || isPe "$downloadFile"; then
      binaryPath="$downloadFile"
    fi
  fi

  if [ -z "$binaryPath" ]; then
    echo "Executable '$APP' not found in archive"
    exit 1
  fi

  chmod +x "$binaryPath" || true
  # Always install as unified name "ffl"
  installBinary "$binaryPath" "$installDir/$APP"
fi
