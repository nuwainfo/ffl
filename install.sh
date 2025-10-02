#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="nuwainfo"
REPO_NAME="ffl"
APP="ffl"

# 可覆寫：FFL_VERSION(如 v3.6.2)、FFL_VARIANT(native|glibc|manylinux|com)、FFL_PREFIX(安裝前綴)
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
  # 支援可選 GITHUB_TOKEN，避免 CI rate limit
  local url="$1"
  if have curl; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: Bearer $GITHUB_TOKEN" -H "X-GitHub-Api-Version: 2022-11-28" "$url"
    else
      curl -fsSL "$url"
    fi
  else
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      wget -qO- --header="Authorization: Bearer $GITHUB_TOKEN" --header="X-GitHub-Api-Version: 2022-11-28" "$url"
    else
      wget -qO- "$url"
    fi
  fi
}

# 1) 取 release JSON
if [ -z "$TAG" ]; then
  REL_JSON="$(gh_api "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest")"
else
  REL_JSON="$(gh_api "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${TAG}")"
fi
TAG="$(printf '%s' "$REL_JSON" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
[ -z "$TAG" ] && { echo "Cannot determine release tag"; exit 1; }

# 2) 取資產清單（相容 bash 3.2）
NAMES_LIST="$(printf '%s\n' "$REL_JSON" | sed -n 's/.*"name":[[:space:]]*"\([^"]*\)".*/\1/p')"

asset_url_by_name() {
  local want="$1"
  awk -v n="$want" '
    BEGIN{FS="\""; name=""}
    /"name":/ {name=$4}
    /"browser_download_url":/ {url=$4; if(name==n){print url; exit}}
  ' <<<"$REL_JSON"
}

choose_asset() {
  # 參數：OS、ARCH、VARIANT
  local os="$1" arch="$2" variant="$3"
  shopt -s nocasematch

  # 架構別名正則
  local ARCH_RE=""
  case "$arch" in
    amd64)  ARCH_RE='(amd64|x86_64|x64)';;
    arm64)  ARCH_RE='(arm64|aarch64)';;
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
          [[ "$name" =~ \.(tar\.gz|tgz|tar|zip|xz|zst)$ ]] || continue
          if [[ "$variant" == "glibc"     ]] && ! [[ "$name" =~ glibc ]];     then continue; fi
          if [[ "$variant" == "manylinux" ]] && ! [[ "$name" =~ manylinux ]]; then continue; fi
          pick="$name"; break
        elif [[ "$os" == "darwin" ]]; then
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
echo "Picked asset: ${ASSET_NAME:-<none>}"

if [ -z "$ASSET_NAME" ]; then
  echo "No matching asset for OS=$OS ARCH=$ARCH VARIANT=$VARIANT in tag $TAG."
  echo "Available assets:"
  IFS=$'\n'; for x in $NAMES_LIST; do [ -n "$x" ] && printf '  - %s\n' "$x"; done
  exit 1
fi

DL_URL="$(asset_url_by_name "$ASSET_NAME")"
[ -z "$DL_URL" ] && { echo "Download URL not found for $ASSET_NAME"; exit 1; }

# 3) 下載
TMPDIR="$(mktemp -d)"; trap 'rm -rf "$TMPDIR"' EXIT
FILE="$TMPDIR/$ASSET_NAME"

echo "Downloading $ASSET_NAME"
if have curl; then curl -fL --retry 3 -o "$FILE" "$DL_URL"; else wget -O "$FILE" "$DL_URL"; fi

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

# --- 檔頭偵測：ELF/Mach-O/PE ---
is_elf()  { [ "$(head -c 4 "$1" | LC_ALL=C tr -d '\0')" = $'\x7f''ELF' ]; }
is_pe()   { head -c 2 "$1" | grep -q "^MZ$"; }
is_macho(){
  local m; m="$(xxd -l 4 -p "$1" 2>/dev/null || true)"
  case "$m" in cffaedfe|feedface|feeface|cafebabe) return 0;; esac
  return 1
}

extract_into() {
  # 嘗試多種格式：bsdtar(自動偵測) -> tar.gz -> tar.xz -> tar.zstd -> tar -> zip -> (單檔二進位)
  local archive="$1" outdir="$2"
  mkdir -p "$outdir"

  if have bsdtar && bsdtar -tf "$archive" >/dev/null 2>&1; then bsdtar -xf "$archive" -C "$outdir" && return 0; fi
  if tar -tzf "$archive" >/dev/null 2>&1; then tar -xzf "$archive" -C "$outdir" && return 0; fi
  if tar -tJf "$archive" >/dev/null 2>&1; then tar -xJf "$archive" -C "$outdir" && return 0; fi
  if tar --help 2>/dev/null | grep -q -- '--zstd' && tar --zstd -tf "$archive" >/dev/null 2>&1; then tar --zstd -xf "$archive" -C "$outdir" && return 0; fi
  if tar -tf "$archive" >/dev/null 2>&1; then tar -xf "$archive" -C "$outdir" && return 0; fi
  if have unzip && unzip -tq "$archive" >/dev/null 2>&1; then unzip -q "$archive" -d "$outdir" && return 0; fi
  if have bsdtar; then bsdtar -xf "$archive" -C "$outdir" && return 0; fi

  # 單檔二進位（誤用壓縮副檔名的情況）
  if is_elf "$archive" || is_macho "$archive" || is_pe "$archive"; then
    cp "$archive" "$outdir/" && return 0
  fi

  echo "Cannot extract archive: $archive"
  return 1
}

# 4) 安裝
if [[ "$VARIANT" == "com" ]]; then
  if [[ "$ASSET_NAME" =~ \.com$ ]]; then
    install_bin "$FILE" "$INSTALL_DIR/$APP.com"
  else
    UNPACK="$TMPDIR/unpack"; extract_into "$FILE" "$UNPACK"
    BIN="$(find "$UNPACK" -type f -name "$APP.com" -o -name "$APP" -o -name "$APP.exe" | head -n1)"
    [ -z "$BIN" ] && { echo "ffl.com not found in archive"; exit 1; }
    # 若拿到的是單檔也行
    case "$BIN" in
      *.com) install_bin "$BIN" "$INSTALL_DIR/$APP.com"; ln -sf "$APP.com" "$INSTALL_DIR/$APP" ;;
      *.exe) install_bin "$BIN" "$INSTALL_DIR/$APP" ;;
      *)     install_bin "$BIN" "$INSTALL_DIR/$APP" ;;
    esac
  fi
  ln -sf "$APP.com" "$INSTALL_DIR/$APP" 2>/dev/null || true
else
  UNPACK="$TMPDIR/unpack"; extract_into "$FILE" "$UNPACK"
  # 找到可執行檔：先精準名，其次任何可執行檔
  BIN="$(find "$UNPACK" -maxdepth 6 -type f \( -name "$APP" -o -name "$APP.exe" \) | head -n1)"
  if [ -z "$BIN" ]; then
    # 如果根本就是單檔下載（誤標 .tar.gz），直接把 FILE 當成可執行
    if is_elf "$FILE" || is_macho "$FILE" || is_pe "$FILE"; then
      BIN="$FILE"
    fi
  fi
  [ -z "$BIN" ] && { echo "Executable '$APP' not found in archive"; exit 1; }
  chmod +x "$BIN" || true
  install_bin "$BIN" "$INSTALL_DIR/$APP"
fi
