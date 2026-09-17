#!/usr/bin/env bash
# verify_roundtrip.sh — the measured, end-to-end proof that library-function
# recognition works on real code on THIS host.
#
# What it does, all from the checked-in sources under tools/ and the engine
# matcher under app/src/main/cpp/sako:
#   1. build the generator (siggen) and the host matcher harness (sigmatch)
#   2. generate a signature DB from a real static library (default: libc.a)
#   3. compile tools/sigtest.c against that library, statically, and STRIP it
#   4. run the matcher over the stripped binary
#   5. score it against the unstripped binary's symbols: how many library
#      functions were present, named, named CORRECTLY (precision), missed
#      (recall), and named WRONG (must be ~0), plus the in-binary guard
#   6. run the false-positive guard: a DB from a DIFFERENT library (libcrypto.a)
#      over the same binary must name (almost) nothing
#
# IMPORTANT: this host is x86-64 glibc. This proves the MACHINERY — relocation
# masking, the signature format, matching, collision handling — on real code. It
# does NOT prove Android/bionic coverage; the shipped DB must be generated from
# the NDK's bionic + libc++ static libs at CI (phase 2).
#
# Usage: tools/verify_roundtrip.sh [libc.a path] [libcrypto.a path]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAKO="$HERE/../app/src/main/cpp/sako"
OUT="${TMPDIR:-/tmp}/nocturne-sigverify"
mkdir -p "$OUT"

LIBC="${1:-/usr/lib/x86_64-linux-gnu/libc.a}"
LIBCRYPTO="${2:-/usr/lib/x86_64-linux-gnu/libcrypto.a}"

echo "== building siggen and sigmatch =="
g++ -std=c++17 -O2 "$HERE/siggen.cpp" -o "$OUT/siggen"
g++ -std=c++17 -O2 -I"$SAKO" "$HERE/sigmatch.cpp" \
    "$SAKO/Types.cpp" "$SAKO/Binary.cpp" "$SAKO/ElfLoader.cpp" \
    "$SAKO/PeLoader.cpp" "$SAKO/Analyzer.cpp" -o "$OUT/sigmatch"

echo "== generating signature DB from $(basename "$LIBC") =="
"$OUT/siggen" "$OUT/libc.nsig" "$LIBC"

echo "== compiling + stripping the test subject =="
gcc -O2 -static -fno-plt "$HERE/sigtest.c" -lm -o "$OUT/sigtest.unstripped"
cp "$OUT/sigtest.unstripped" "$OUT/sigtest.stripped"
strip "$OUT/sigtest.stripped"

echo "== matching =="
"$OUT/sigmatch" "$OUT/sigtest.stripped" "$OUT/libc.nsig" > "$OUT/matched.txt" 2> "$OUT/match.err"
cat "$OUT/match.err"

echo "== scoring =="
python3 "$HERE/score_roundtrip.py" "$OUT/sigtest.unstripped" "$OUT/libc.nsig" \
    "$OUT/matched.txt" secret_mix,business_logic,main

echo
echo "== false-positive guard: a DB from a DIFFERENT library over the same binary =="
if [ -f "$LIBCRYPTO" ]; then
    "$OUT/siggen" "$OUT/crypto.nsig" "$LIBCRYPTO" 2>/dev/null
    "$OUT/sigmatch" "$OUT/sigtest.stripped" "$OUT/crypto.nsig" > "$OUT/guard.txt" 2> "$OUT/guard.err"
    grep -o "NAMED=[0-9]* collisions=[0-9]*" "$OUT/guard.err"
    echo "  (a DB of $(basename "$LIBCRYPTO") should name ~0 of a libc-only binary; named $(wc -l < "$OUT/guard.txt"))"
else
    echo "  (skipped: $LIBCRYPTO not present)"
fi
echo
echo "artifacts in $OUT"
