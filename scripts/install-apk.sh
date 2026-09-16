#!/usr/bin/env bash
# Build the debug APK and install it on a connected device.
#
#   ./scripts/install-apk.sh            # build, then install on the only device
#   ./scripts/install-apk.sh -s SERIAL  # target a specific device
#   ./scripts/install-apk.sh --skip-build
#
# The debug APK is signed with the standard Android debug key, so it installs
# without any keystore setup. Release builds need app/keystore.properties.
set -euo pipefail

cd "$(dirname "$0")/.."

SERIAL=""
SKIP_BUILD=0
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--serial)   SERIAL="$2"; shift 2 ;;
        --skip-build)  SKIP_BUILD=1; shift ;;
        -h|--help)     sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

APK=app/build/outputs/apk/debug/app-debug.apk

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "==> Building debug APK (first run also compiles Capstone — expect a few minutes)"
    ./gradlew assembleDebug
fi

[ -f "$APK" ] || { echo "APK not found at $APK — run without --skip-build" >&2; exit 1; }

command -v adb >/dev/null || { echo "adb not on PATH — install Android platform-tools" >&2; exit 1; }

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

# Portable across bash 3.2 (still /bin/bash on macOS), so no mapfile/readarray.
DEVICES=""
while IFS= read -r line; do
    DEVICES="${DEVICES}${line}
"
done <<EOF
$("${ADB[@]}" devices | awk 'NR>1 && $2=="device" {print $1}')
EOF
DEVICES=$(printf '%s' "$DEVICES" | sed '/^$/d')
COUNT=$(printf '%s' "$DEVICES" | grep -c . || true)

if [ "$COUNT" -eq 0 ]; then
    echo "No device connected. Enable USB debugging and accept the RSA prompt." >&2
    exit 1
fi
if [ "$COUNT" -gt 1 ] && [ -z "$SERIAL" ]; then
    echo "Several devices connected — pick one with -s SERIAL:" >&2
    printf '  %s\n' $DEVICES >&2
    exit 1
fi
FIRST=$(printf '%s' "$DEVICES" | head -n1)

ABI=$("${ADB[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')
case "$ABI" in
    arm64-v8a|x86_64) ;;
    *) echo "Warning: device ABI is '$ABI'; this build only ships arm64-v8a and x86_64." >&2 ;;
esac

echo "==> Installing $(du -h "$APK" | cut -f1) on $FIRST ($ABI)"
"${ADB[@]}" install -r "$APK"
"${ADB[@]}" shell monkey -p com.trickhook -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
echo "==> Done — Sako RE Studio launched."
