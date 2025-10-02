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
gh_api() { if have curl; then curl -fsSL "$1"; else wget -qO- "$1"; fi; }

# 1) 取 release JSON
if [ -z "$TAG" ]; then
  REL_JSON="$(gh_api "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest")"
else
  REL_JSON="$(gh_api "https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/tags/${TAG}")"
fi
TAG="$(printf '%s' "$REL_JSON" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
[ -z "$TAG" ] && { echo "Cannot determine release tag"; exit 1; }

# 2) 取全部資產名稱與 URL（不假設命名，靠關鍵字/正則挑）
mapfile -t NAMES < <(printf '%s' "$REL_JSON" | sed -n 's/.*"name":[[:space:]]*"\([^"]*\)".*/\1/p')
mapfile -t URLS  < <(printf '%s' "$REL_JSON" | sed -n 's/.*"browser_download_url":[[:space:]]*"\([^"]*\)".*/\1/p')

asset_url_by_name() {
  local want="$1"
  # 按出現順序配對 name/URL
  awk -v n="$want" '
    BEGIN{FS="\""; name=""}
    /"name":/ {name=$4}
    /"browser_download_url":/ {url=$4; if(name==n){print url; exit}}
  ' <<<"$REL_JSON"
}

choose_asset() {
  # 規則：
  # - com：名稱含 "ffl.com"（可為裸檔或打包 .zip/.tar.gz）
  # - native:
  #   - linux: 名稱含 linux、ARCH；若 VARIANT=glibc/manylinux 則再含該字；副檔 .tar.gz
  #   - darwin: 名稱含 (darwin|mac|macos)、ARCH、.tar.gz
  #   - （Windows 交由 install.ps1）
  local os="$1" arch="$2" variant="$3"
  shopt -s nocasematch
  local pick=""
  for name in "${NAMES[@]}"; do
    if [[ "$variant" == "com" ]]; then
      if [[ "$name" =~ ffl\.com($|\.zip$|\.tar\.gz$) ]]; then pick="$name"; break; fi
    else
      if [[ "$os" == "linux" ]]; then
        [[ "$name" =~ linux ]] || continue
        [[ "$name" =~ $arch ]] || continue
        [[ "$name" =~ \.tar\.gz$ ]] || continue
        if [[ "$variant" == "glibc" ]]; then [[ "$name" =~ glibc ]] || continue; fi
        if [[ "$variant" == "manylinux" ]]; then [[ "$name" =~ manylinux ]] || continue; fi
        pick="$name"; break
      elif [[ "$os" == "darwin" ]]; then
        if [[ "$name" =~ (darwin|mac|macos) ]] && [[ "$name" =~ $arch ]] && [[ "$name" =~ \.tar\.gz$ ]]; then
          pick="$name"; break
        fi
      fi
    fi
  done
  echo "$pick"
}

ASSET_NAME="$(choose_asset "$OS" "$ARCH" "$VARIANT")"
if [ -z "$ASSET_NAME" ]; then
  echo "No matching asset for OS=$OS ARCH=$ARCH VARIANT=$VARIANT in tag $TAG."
  echo "Available assets:"; printf '  - %s\n' "${NAMES[@]}"; exit 1
fi
DL_URL="$(asset_url_by_name "$ASSET_NAME")"
[ -z "$DL_URL" ] && { echo "Download URL not found for $ASSET_NAME"; exit 1; }

# 3) 下載與安裝
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

if [[ "$VARIANT" == "com" ]]; then
  if [[ "$ASSET_NAME" =~ \.com$ ]]; then
    install_bin "$FILE" "$INSTALL_DIR/$APP.com"
  elif [[ "$ASSET_NAME" =~ \.zip$ ]]; then
    UNZIP_DIR="$TMPDIR/unzip"; mkdir -p "$UNZIP_DIR"
    if have unzip; then unzip -q "$FILE" -d "$UNZIP_DIR"; else bsdtar -xf "$FILE" -C "$UNZIP_DIR"; fi
    BIN="$(find "$UNZIP_DIR" -type f -name "$APP.com" | head -n1)"
    [ -z "$BIN" ] && { echo "ffl.com not found in archive"; exit 1; }
    install_bin "$BIN" "$INSTALL_DIR/$APP.com"
  else
    tar -xzf "$FILE" -C "$TMPDIR"
    BIN="$(find "$TMPDIR" -type f -name "$APP.com" | head -n1)"
    [ -z "$BIN" ] && { echo "ffl.com not found in archive"; exit 1; }
    install_bin "$BIN" "$INSTALL_DIR/$APP.com"
  fi
  ln -sf "$APP.com" "$INSTALL_DIR/$APP"
else
  tar -xzf "$FILE" -C "$TMPDIR"
  BIN="$(find "$TMPDIR" -maxdepth 3 -type f -name "$APP" | head -n1)"
  [ -z "$BIN" ] && { echo "Executable '$APP' not found in archive"; exit 1; }
  install_bin "$BIN" "$INSTALL_DIR/$APP"
fi
