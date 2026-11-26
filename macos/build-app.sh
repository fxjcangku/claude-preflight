#!/bin/bash
set -euo pipefail

if [[ $# -gt 1 || (${1:-} != "" && ${1:-} != "--zip") ]]; then
    echo "用法：macos/build-app.sh [--zip]" >&2
    exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd -P)
dist="$root/dist"
swiftc=$(/usr/bin/xcrun --sdk macosx --find swiftc)
sdk=$(/usr/bin/xcrun --sdk macosx --show-sdk-path)
if [[ ! -x "$swiftc" || ! -d "$sdk" ]]; then
    echo "未找到可用的 macOS SDK 和 Swift 编译器。" >&2
    exit 1
fi

mkdir -p "$dist"
stage=$(mktemp -d "${TMPDIR:-/tmp}/preflight-build.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT
app="$stage/Preflight.app"
resources="$app/Contents/Resources"
backend="$resources/backend"
mkdir -p "$app/Contents/MacOS" "$backend/preflight/static" "$backend/docs" "$backend/config"

for arch in arm64 x86_64; do
    "$swiftc" -parse-as-library -O -sdk "$sdk" -target "$arch-apple-macosx13.0" \
        -framework Cocoa -framework WebKit -framework ApplicationServices "$root/macos/Preflight.swift" \
        -o "$stage/Preflight-$arch"
done
/usr/bin/lipo -create "$stage/Preflight-arm64" "$stage/Preflight-x86_64" \
    -output "$app/Contents/MacOS/Preflight"
install -m 644 "$root/macos/Info.plist" "$app/Contents/Info.plist"
/usr/bin/plutil -lint "$app/Contents/Info.plist" >/dev/null

install -m 644 "$root"/preflight/*.py "$backend/preflight/"
/usr/bin/rsync -r --exclude='.*' --exclude='__pycache__' --exclude='*.pyc' \
    "$root/preflight/static/" "$backend/preflight/static/"
install -m 644 "$root"/docs/{index.html,intro.js,intro.css,logo.svg,preview.png} "$backend/docs/"
install -m 644 "$root/config/Claude-Preflight.mobileconfig" "$backend/config/"
install -m 644 "$root/LICENSE" "$resources/"
# Isolated Python omits the script directory from sys.path. All backend children
# use this entry point; keep bytecode writes out of the signed app.
cat > "$backend/claude-preflight" <<'PY'
#!/usr/bin/python3 -I
import os
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from preflight.__main__ import main

raise SystemExit(main())
PY
chmod 755 "$backend/claude-preflight"

icons="$stage/AppIcon.iconset"
mkdir "$icons"
/usr/bin/sips -s format png -z 1024 1024 "$root/docs/logo.svg" --out "$stage/logo.png" >/dev/null
for size in 16 32 128 256 512; do
    /usr/bin/sips -z "$size" "$size" "$stage/logo.png" --out "$icons/icon_${size}x${size}.png" >/dev/null
    pixels=$((size * 2))
    /usr/bin/sips -z "$pixels" "$pixels" "$stage/logo.png" --out "$icons/icon_${size}x${size}@2x.png" >/dev/null
done
/usr/bin/iconutil -c icns "$icons" -o "$resources/AppIcon.icns"

/usr/bin/python3 -I -B "$backend/claude-preflight" --help >/dev/null
# The source artwork or iCloud File Provider can attach Finder metadata, which is invalid on a sealed bundle.
strip_detritus() {
    for attribute in com.apple.FinderInfo com.apple.ResourceFork com.apple.quarantine 'com.apple.fileprovider.fpfs#P'; do
        /usr/bin/xattr -dr "$attribute" "$1" 2>/dev/null || true
    done
}
strip_detritus "$app"
/usr/bin/codesign --force --sign - --timestamp=none "$app"
/usr/bin/codesign --verify --strict "$app"

if [[ ${1:-} == "--zip" ]]; then
    version=$(/usr/libexec/PlistBuddy -c 'Print CFBundleShortVersionString' "$app/Contents/Info.plist")
    archive="Preflight-$version-macOS.zip"
    /usr/bin/ditto -c -k --norsrc --noextattr --noqtn --keepParent "$app" "$stage/$archive"
fi

# Publish the signed bundle cleanly into dist/ (which may reside on iCloud-backed Documents).
if [[ -e "$dist/Preflight.app" ]]; then
    if [[ -L "$dist/Preflight.app" || ! -d "$dist/Preflight.app" ]]; then
        echo "dist/Preflight.app 不是普通应用目录" >&2
        exit 1
    fi
    rm -rf "$dist/Preflight.app"
fi
/usr/bin/ditto --norsrc --noextattr --noqtn "$app" "$dist/Preflight.app"
strip_detritus "$dist/Preflight.app"
/usr/bin/codesign --verify --strict "$dist/Preflight.app"
printf '%s\n' "$dist/Preflight.app"
if [[ ${1:-} == "--zip" ]]; then
    mv -f "$stage/$archive" "$dist/$archive"
    printf '%s\n' "$dist/$archive"
fi
