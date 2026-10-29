#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
VER=$(grep '^Version:' layout/DEBIAN/control | awk '{print $2}')
OUT=build
rm -rf "$OUT" && mkdir -p "$OUT"
cp -R layout "$OUT/pkg"
APP="$OUT/pkg/Applications/EnvScan.app"

xcrun --sdk iphoneos clang -fobjc-arc -O1 \
  -arch arm64 -miphoneos-version-min=15.0 \
  -framework Foundation -framework UIKit \
  src/main.m -o "$APP/EnvScan"

# sign with entitlements (no-sandbox) so the scan can read system paths on a jailbroken device
ldid -Sents.plist "$APP/EnvScan"

chmod 755 "$APP/EnvScan" "$OUT/pkg/DEBIAN/postinst" "$OUT/pkg/DEBIAN/postrm"
export COPYFILE_DISABLE=1
dpkg-deb -Zgzip --root-owner-group -b "$OUT/pkg" "$OUT/com.ganbi.envscan_${VER}_iphoneos-arm64e.deb"
ls -l "$OUT"/*.deb
