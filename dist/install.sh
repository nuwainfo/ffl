#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="nuwainfo"
REPO_NAME="ffl"
APP="ffl"

# Overridables: FFL_VERSION (e.g. v3.6.2), FFL_VARIANT (native|glibc|manylinux|com), FFL_PREFIX (install prefix)
TAG="${FFL_VERSION:-}"
VARIANT="${FFL_VARIANT:-native}"
PREFIX="${FFL_PREFIX:-}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"   # linux/darwin
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported arch: $ARCH_RAW"; exit 1 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }

gh_api() {
  # No token: plain curl/wget to GitHub API
  local url="$1"
  if have curl; then
    curl -fsSL "$url"
  else
    wget -qO- "$url"
  fi
}

# 1) Fetch release JSON
if [ -z "$TAG" ]; then
  REL_JSON="$(gh_api "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest")"
else
  REL_JSON="$(gh_api "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${TAG}")"
fi
TAG="$(printf '%s' "$REL_JSON" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
[ -z "$TAG" ] && { echo "Cannot determine release tag"; exit 1; }

# 2) Collect asset names (bash 3.2-compatible; do not use mapfile)
NAMES_LIST="$(printf '%s\n' "$REL_JSON" | sed -n 's/.*"name":[[:space:]]*"\([^"]*\)".*/\1/p')"

asset_url_by_name() {
  local want="$1"
  # Pair "name" with "browser_download_url" in order of appearance
  awk -v n="$want" '
    BEGIN{FS="\""; name=""}
    /"name":/ {name=$4}
    /"browser_download_url":/ {url=$4; if(name==n){print url; exit}}
  ' <<<"$REL_JSON"
}

# ---------- Linux glibc detection & baseline selection ----------
# Returns detected glibc version like "2.39"; empty if not glibc (e.g., musl/Alpine).
detect_glibc_version() {
  local v=""
  if command -v getconf >/dev/null 2>&1; then
    v="$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{print $2}')"
  fi
  if [ -z "$v" ] && command -v ldd >/dev/null 2>&1; then
    # e.g. first line: "ldd (Ubuntu GLIBC 2.35-0ubuntu3.1) 2.35"
    v="$(ldd --version 2>/dev/null | head -n1 | grep -Eo '([0-9]+\.){1,2}[0-9]+' | head -n1)"
  fi
  printf '%s' "$v"
}

# Compare versions: returns true if $1 >= $2 (with sort -V)
version_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# Pick the glibc baseline we should use among known targets (highest not exceeding system)
pick_glibc_baseline() {
  local sys glibc_targets=("2.39" "2.28")
  sys="$(detect_glibc_version)"
  if [ -z "$sys" ]; then
    echo "fallback"  # not glibc; will use APE (ffl.com)
    return
  fi
  for base in "${glibc_targets[@]}"; do
    if version_ge "$sys" "$base"; then
      echo "$base"
      return
    fi
  done
  # System glibc lower than our lowest target (2.28): still return 2.28 (may fail; outer logic can fallback to com)
  echo "2.28"
}
# ----------------------------------------------------------------

choose_asset() {
  # Params: OS, ARCH, VARIANT
  local os="$1" arch="$2" variant="$3"
  shopt -s nocasematch

  # Arch alias regex
  local ARCH_RE=""
  case "$arch" in
    amd64)  ARCH_RE='(amd64|x86_64|x64)';;
    arm64)  ARCH_RE='(arm64|aarch64|aarch)';; 
    *)      ARCH_RE="$arch";;
  esac

  local pick=""
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    case "$variant" in
      com)
        if [[ "$name" =~ ffl\.com($|\.zip$|\.tar\.gz$) ]]; then pick="$name"; break; fi
        ;;
      glibc|manylinux|native)
        if [[ "$os" == "linux" ]]; then
          [[ "$name" =~ linux ]] || continue
          [[ "$name" =~ $ARCH_RE ]] || continue
          [[ "$name" =~ \.(tar\.gz|tgz)$ ]] || continue

          # Auto-select Linux glibc baseline between glibc2.39 and glibc2.28
          if [ -z "${_FFL_GLIBC_BASELINE:-}" ]; then
            _FFL_GLIBC_BASELINE="$(pick_glibc_baseline)"
          fi

          case "$_FFL_GLIBC_BASELINE" in
            "2.39")
              # Prefer 2.39; if absent we may fall back to 2.28 later
              if [[ "$name" =~ glibc2\.39 ]]; then pick="$name"; break; fi
              ;;
            "2.28")
              if [[ "$name" =~ glibc2\.28 ]]; then pick="$name"; break; fi
              ;;
            "fallback")
              # Non-glibc (musl/unknown): skip Linux archives; outer logic will try APE (ffl.com)
              continue
              ;;
          esac

        elif [[ "$os" == "darwin" ]]; then
          # mac assets use "mac"; also accept darwin/macos; support .zip/.tar.gz
          if   [[ "$name" =~ mac ]] && [[ "$name" =~ $ARCH_RE ]] && [[ "$name" =~ \.(zip|tar\.gz|tgz)$ ]]; then pick="$name"; break
          elif [[ "$name" =~ (darwin|macos) ]] && [[ "$name" =~ $ARCH_RE ]] && [[ "$name" =~ \.(zip|tar\.gz|tgz)$ ]]; then pick="$name"; break
          fi
        fi
        ;;
    esac
  done <<< "$NAMES_LIST"

  echo "$pick"
}

ASSET_NAME="$(choose_asset "$OS" "$ARCH" "$VARIANT")"

# Linux: if no matching glibc archive (e.g., musl), fallback to APE ffl.com automatically
if [ -z "$ASSET_NAME" ] && [ "$OS" = "linux" ]; then
  if printf '%s\n' "$NAMES_LIST" | grep -qiE '^ffl\.com$|/ffl\.com$'; then
    ASSET_NAME="ffl.com"
    VARIANT="com"
    echo "No compatible glibc archive; falling back to APE (ffl.com)"
  fi
fi

echo "Picked asset: ${ASSET_NAME:-<none>}"

if [ -z "$ASSET_NAME" ]; then
  echo "No matching asset for OS=$OS ARCH=$ARCH VARIANT=$VARIANT in tag $TAG."
  echo "Available assets:"; IFS=$'\n'; for x in $NAMES_LIST; do [ -n "$x" ] && printf '  - %s\n' "$x"; done
  exit 1
fi

DL_URL="$(asset_url_by_name "$ASSET_NAME")"
[ -z "$DL_URL" ] && { echo "Download URL not found for $ASSET_NAME"; exit 1; }

# 3) Download
TMPDIR="$(mktemp -d)"; trap 'rm -rf "$TMPDIR"' EXIT
FILE="$TMPDIR/$ASSET_NAME"

echo "Downloading $ASSET_NAME"
if have curl; then curl -fL --retry 3 -o "$FILE" "$DL_URL"; else wget -O "$FILE" "$DL_URL"; fi

# 4) Install location
if [ -n "$PREFIX" ]; then
  INSTALL_DIR="$PREFIX/bin"
elif [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="$HOME/.local/bin"
fi
mkdir -p "$INSTALL_DIR"

install_bin() {
  local src="$1" dst="$2"
  install -m 0755 "$src" "$dst"
  echo "Installed to $dst"
  case ":$PATH:" in *":$INSTALL_DIR:"*) ;; *) echo "Note: add $INSTALL_DIR to PATH";; esac
  "$dst" --version || true
}

# --- File header detection: ELF / Mach-O / PE ---
is_elf()  { [ "$(head -c 4 "$1" | LC_ALL=C tr -d '\0')" = $'\x7f''ELF' ]; }
is_pe()   { head -c 2 "$1" | grep -q "^MZ$"; }
is_macho(){
  # Use hexdump (available on macOS by default)
  local m; m="$(dd if="$1" bs=4 count=1 2>/dev/null | hexdump -v -e '1/1 "%02x"')"
  case "$m" in cffaedfe|feedface|feeface|cafebabe) return 0;; esac
  return 1
}

extract_into() {
  # Try several formats: bsdtar(auto) -> tar.gz -> tar.xz -> tar.zstd -> tar -> zip.
  # If all fail but the file itself is an executable (mislabelled), treat as single-file install.
  local archive="$1" outdir="$2"
  mkdir -p "$outdir"

  if have bsdtar && bsdtar -tf "$archive" >/dev/null 2>&1; then bsdtar -xf "$archive" -C "$outdir" && return 0; fi
  if tar -tzf "$archive" >/dev/null 2>&1; then tar -xzf "$archive" -C "$outdir" && return 0; fi
  if tar -tJf "$archive" >/dev/null 2>&1; then tar -xJf "$archive" -C "$outdir" && return 0; fi
  if tar --help 2>/dev/null | grep -q -- '--zstd' && tar --zstd -tf "$archive" >/dev/null 2>&1; then tar --zstd -xf "$archive" -C "$outdir" && return 0; fi
  if tar -tf "$archive" >/dev/null 2>&1; then tar -xf "$archive" -C "$outdir" && return 0; fi
  if have unzip && unzip -tq "$archive" >/dev/null 2>&1; then unzip -q "$archive" -d "$outdir" && return 0; fi
  if have bsdtar; then bsdtar -xf "$archive" -C "$outdir" && return 0; fi

  if is_elf "$archive" || is_macho "$archive" || is_pe "$archive"; then
    cp "$archive" "$outdir/" && return 0
  fi

  echo "Cannot extract archive: $archive"
  return 1
}

# 5) Install
if [[ "$VARIANT" == "com" ]]; then
  if [[ "$ASSET_NAME" =~ \.com$ ]]; then
    install_bin "$FILE" "$INSTALL_DIR/$APP.com"
  else
    UNPACK="$TMPDIR/unpack"; extract_into "$FILE" "$UNPACK"
    BIN="$(find "$UNPACK" -type f -name "$APP.com" -o -name "$APP" -o -name "$APP.exe" | head -n1)"
    [ -z "$BIN" ] && { echo "ffl.com not found in archive"; exit 1; }
    case "$BIN" in
      *.com) install_bin "$BIN" "$INSTALL_DIR/$APP.com"; ln -sf "$APP.com" "$INSTALL_DIR/$APP" ;;
      *.exe) install_bin "$BIN" "$INSTALL_DIR/$APP" ;;
      *)     install_bin "$BIN" "$INSTALL_DIR/$APP" ;;
    esac
  fi
  ln -sf "$APP.com" "$INSTALL_DIR/$APP" 2>/dev/null || true
else
  UNPACK="$TMPDIR/unpack"; extract_into "$FILE" "$UNPACK"
  # Prefer exact name, then ffl_*, then any executable containing "ffl"
  BIN="$(find "$UNPACK" -maxdepth 6 -type f -name "$APP" | head -n1)"
  if [ -z "$BIN" ]; then
    BIN="$(find "$UNPACK" -maxdepth 6 -type f -regex ".*/${APP}[_-].*" | head -n1)"
  fi
  if [ -z "$BIN" ]; then
    BIN="$(find "$UNPACK" -maxdepth 6 -type f -perm -111 -iname "*$APP*" | head -n1)"
  fi
  if [ -z "$BIN" ]; then
    # If the downloaded file is actually a single binary (mislabelled), use it.
    if is_elf "$FILE" || is_macho "$FILE" || is_pe "$FILE"; then
      BIN="$FILE"
    fi
  fi
  [ -z "$BIN" ] && { echo "Executable '$APP' not found in archive"; exit 1; }
  chmod +x "$BIN" || true
  # Always install as unified name "ffl"
  install_bin "$BIN" "$INSTALL_DIR/$APP"
fi
