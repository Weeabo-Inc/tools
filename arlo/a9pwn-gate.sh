#!/usr/bin/env bash
# a9pwn test gate (Linux port of a9pwn-gate.ps1)
#
# THE PROPERTY THIS GATE EXISTS FOR: the SHA-256 manifest is taken at BOTH ends
# of the run, and any difference is a FAILURE. "The tests passed" is worthless
# if the bytes changed while they ran.
#
# Read-only with respect to the working tree: no checkout, no reset, no clean,
# no formatting. The only writes are its own result/log files and whatever cargo
# writes under target/.
#
# Usage:
#   tools/arlo/a9pwn-gate.sh [--repo DIR] [--out FILE] [--offline] [--quiet]
# Exit: 0 PASS · 1 FAIL · 2 gate could not run
set -u -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$HERE/../../a9pwn"
OUT="$HERE/out/a9pwn-gate-linux.json"
OFFLINE=0
QUIET=0

while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --out)  OUT="$2";  shift 2 ;;
    --offline) OFFLINE=1; shift ;;
    --quiet) QUIET=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

REPO="$(cd "$REPO" 2>/dev/null && pwd)" || { echo "bad repo" >&2; exit 2; }
command -v cargo >/dev/null || { echo "cargo not found" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")" || exit 2

# Context files that change what the tests MEAN, not just src/.
mapfile -t FILES < <(
  {
    find "$REPO/src" -type f 2>/dev/null
    [ -f "$REPO/Cargo.toml" ] && echo "$REPO/Cargo.toml"
    [ -f "$REPO/Cargo.lock" ] && echo "$REPO/Cargo.lock"
    [ -f "$REPO/build.rs" ]   && echo "$REPO/build.rs"
    find "$REPO/payloads" -type f 2>/dev/null
  } | sort -u
)
[ "${#FILES[@]}" -gt 0 ] || { echo "no files to hash under $REPO" >&2; exit 2; }

manifest() { ( cd "$REPO" && sha256sum "${FILES[@]}" ) ; }

BEFORE="$(manifest)"
BEFORE_N="$(printf '%s\n' "$BEFORE" | wc -l)"

LOG="$(dirname "$OUT")/a9pwn-gate-linux.log"
: > "$LOG"

CARGO_FLAGS=(--release)
[ "$OFFLINE" = 1 ] && CARGO_FLAGS+=(--offline)

echo "== a9pwn gate: $REPO  (${BEFORE_N} files pinned)" | tee -a "$LOG"
echo "$BEFORE" | tee -a "$LOG" >/dev/null

echo "== cargo build ${CARGO_FLAGS[*]}" | tee -a "$LOG"
BUILD_OUT="$(cd "$REPO" && cargo build "${CARGO_FLAGS[@]}" 2>&1)"
BUILD_RC=$?
printf '%s\n' "$BUILD_OUT" >> "$LOG"
[ "$QUIET" = 0 ] && printf '%s\n' "$BUILD_OUT"

echo "== cargo test ${CARGO_FLAGS[*]}" | tee -a "$LOG"
TEST_OUT="$(cd "$REPO" && cargo test "${CARGO_FLAGS[@]}" 2>&1)"
TEST_RC=$?
printf '%s\n' "$TEST_OUT" >> "$LOG"
[ "$QUIET" = 0 ] && printf '%s\n' "$TEST_OUT"

# Parse every "test result:" line: sum passes/failures, flag any failed suite.
PASSED=0; FAILED=0; IGNORED=0; SUITES=0; PARSE_OK=0
while read -r line; do
  if [[ "$line" =~ ^test\ result:\ (ok|FAILED)\.\ ([0-9]+)\ passed\;\ ([0-9]+)\ failed\;\ ([0-9]+)\ ignored ]]; then
    PARSE_OK=1; SUITES=$((SUITES+1))
    PASSED=$((PASSED+${BASH_REMATCH[2]}))
    FAILED=$((FAILED+${BASH_REMATCH[3]}))
    IGNORED=$((IGNORED+${BASH_REMATCH[4]}))
  fi
done <<< "$TEST_OUT"

AFTER="$(manifest)"
AFTER_N="$(printf '%s\n' "$AFTER" | wc -l)"

REASON=""
if [ "$BUILD_RC" -ne 0 ]; then REASON="build_failed"
elif [ "$TEST_RC" -ne 0 ]; then REASON="tests_failed"
elif [ "$PARSE_OK" -eq 0 ]; then REASON="no_test_result"
elif [ "$BEFORE" != "$AFTER" ]; then REASON="source_changed_during_run"
fi

if [ -z "$REASON" ]; then VERDICT=PASS; RC=0; else VERDICT=FAIL; RC=1; fi

GIT_REV="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo none)"
GIT_DIRTY="$(git -C "$REPO" status --porcelain 2>/dev/null | wc -l)"
BIN="$REPO/target/release/a9pwn"
BIN_HASH=""; BIN_SIZE=0
if [ -f "$BIN" ]; then
  BIN_HASH="$(sha256sum "$BIN" | cut -d' ' -f1 | tr 'a-f' 'A-F')"
  BIN_SIZE="$(stat -c%s "$BIN")"
fi

# NEVER ERASE ANOTHER WRITER'S EVIDENCE. Archive any existing artifact before
# writing this run's, so a later run cannot destroy an earlier PASS record.
#
# MEASURED 2026-10-03: three independent reviewers hit the same overwritten
# tools/arlo/out/a9pwn-gate-linux.json. One teammate's PASS artifact was replaced
# by another's FAIL (a legitimate `source_changed_during_run` that straddled an
# unrelated edit), which left the PASS unquotable and forced a re-run with a
# writer freeze. A shared output path is a single point of evidence loss; this
# keeps every run's record next to the canonical one.
if [ -f "$OUT" ]; then
  cp -p "$OUT" "${OUT%.json}.$(date -u +%Y%m%dT%H%M%SZ).$$.json" 2>/dev/null || true
fi

cat > "$OUT" <<JSON
{
  "gate": "a9pwn-gate-linux",
  "verdict": "$VERDICT",
  "reason": "${REASON:-none}",
  "repo": "$REPO",
  "git_rev": "$GIT_REV",
  "git_dirty_files": $GIT_DIRTY,
  "files_pinned": $BEFORE_N,
  "suites": $SUITES,
  "tests_passed": $PASSED,
  "tests_failed": $FAILED,
  "tests_ignored": $IGNORED,
  "build_rc": $BUILD_RC,
  "test_rc": $TEST_RC,
  "manifest_before_sha256": "$(printf '%s\n' "$BEFORE" | sha256sum | cut -d' ' -f1)",
  "manifest_after_sha256": "$(printf '%s\n' "$AFTER" | sha256sum | cut -d' ' -f1)",
  "binary": "$BIN",
  "binary_sha256": "$BIN_HASH",
  "binary_size": $BIN_SIZE,
  "manifest": [
$(printf '%s\n' "$AFTER" | awk '{printf "    {\"sha256\": \"%s\", \"path\": \"%s\"}%s\n", toupper($1), $2, (NR==n?"":",")}' n="$AFTER_N")
  ]
}
JSON

echo | tee -a "$LOG"
echo "  VERDICT      $VERDICT   (${REASON:-clean})" | tee -a "$LOG"
echo "  tests        $PASSED passed / $FAILED failed / $IGNORED ignored  over $SUITES suite(s)" | tee -a "$LOG"
echo "  manifest     ${BEFORE_N} files pinned, before == after: $([ "$BEFORE" = "$AFTER" ] && echo yes || echo NO)" | tee -a "$LOG"
echo "  binary       $BIN_SIZE bytes  $BIN_HASH" | tee -a "$LOG"
echo "  result       $OUT" | tee -a "$LOG"
exit $RC
