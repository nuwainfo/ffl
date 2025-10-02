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

NAMES_LIST="$(printf '%s\n' "$REL_JSON" | sed -n 's/.*"name":[[:space:]]*"\([^"]*\)".*/\1/p')"
# asset_url_by_name 仍從 REL_JSON 對應，不需 URLS 陣列


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

  # 逐行掃描 NAMES_LIST（相容 bash 3.2，避免 mapfile）
  local pick=""
  while IFS= read -r name; do
    # 跳過像 "Release v3.6.2" 的 release title
    [ -z "$name" ] && continue
    case "$variant" in
      com)
        if [[ "$name" =~ ffl\.com($|\.zip$|\.tar\.gz$) ]]; then
          pick="$name"; break
        fi
        ;;
      glibc|manylinux|native)
        if [[ "$os" == "linux" ]]; then
          [[ "$name" =~ linux ]] || continue
          [[ "$name" =~ $ARCH_RE ]] || continue
          [[ "$name" =~ \.tar\.gz$ ]] || continue
          if [[ "$variant" == "glibc"     ]] && ! [[ "$name" =~ glibc ]];     then continue; fi
          if [[ "$variant" == "manylinux" ]] && ! [[ "$name" =~ manylinux ]]; then continue; fi
          pick="$name"; break
        elif [[ "$os" == "darwin" ]]; then
          # 你的命名用 mac；優先 mac，其次 darwin/macos
          if   [[ "$name" =~ mac    ]] && [[ "$name" =~ $ARCH_RE ]] && [[ "$name" =~ \.tar\.gz$ ]]; then pick="$name"; break
          elif [[ "$name" =~ (darwin|macos) ]] && [[ "$name" =~ $ARCH_RE ]] && [[ "$name" =~ \.tar\.gz$ ]]; then pick="$name"; break
          fi
        fi
        ;;
      *)
        : # 其他 variant 不處理
        ;;
    esac
  done <<< "$NAMES_LIST"

  echo "$pick"
}


ASSET_NAME="$(choose_asset "$OS" "$ARCH" "$VARIANT")"
echo "Picked asset: $ASSET_NAME"

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
