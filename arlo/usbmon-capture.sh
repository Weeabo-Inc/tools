#!/usr/bin/env bash
# usbmon-capture.sh — orchestration glue around the Linux kernel's usbmon.
#
# WHAT IT IS FOR: "the observer must be outside the tool". gaster prints nothing
# during SETUP, and a9pwn's own counters are the tool's opinion of itself. usbmon
# is the kernel's URB-level record and is the only instrument that shows what the
# device actually did with a request.
#
# It captures, runs one command, stops the capture, and leaves three files:
#   OUT              raw usbmon text (bus N, "u" format = setup packets included)
#   OUT.stdout.txt   the command's own stdout+stderr
#   OUT.meta         exit code, timings, byte/line counts, sha256 of the capture
#
# usbmon's debugfs nodes are root-only (the whole of /sys/kernel/debug is 0700),
# so run this under sudo. It chowns its outputs back to SUDO_USER.
#
# Usage:  usbmon-capture.sh --bus N --out FILE [--settle-ms N] -- CMD [ARGS...]
# Exit:   the wrapped command's exit code, or 2 if the capture could not start.
set -u

BUS=; OUT=; SETTLE=250; CMD=()
while [ $# -gt 0 ]; do
  case "$1" in
    --bus) BUS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --settle-ms) SETTLE="$2"; shift 2 ;;
    --) shift; CMD=("$@"); break ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -n "$BUS" ] && [ -n "$OUT" ] && [ "${#CMD[@]}" -gt 0 ] || {
  echo "usage: usbmon-capture.sh --bus N --out FILE [--settle-ms N] -- CMD [ARGS...]" >&2; exit 2; }

NODE="/sys/kernel/debug/usb/usbmon/${BUS}u"
[ -r "$NODE" ] || { echo "cannot read $NODE (run under sudo; is usbmon loaded?)" >&2; exit 2; }
mkdir -p "$(dirname "$OUT")" || exit 2
STDOUT="$OUT.stdout.txt"
META="$OUT.meta"

# Start the capture first: opening the node is what arms the buffer, and a
# capture that starts after the first transfer has already missed it.
#
# Two traps here, both MEASURED the hard way:
#   * stderr MUST be redirected. A background child inherits this shell's stdout
#     pipe, so a surviving `cat` holds the caller's pipeline open forever even
#     after this script exits.
#   * `cmd &` in a non-interactive shell without job control sets SIGINT/SIGQUIT
#     to SIG_IGN in the child, so `kill -INT` does nothing. Use SIGTERM, then
#     SIGKILL. (Cost of learning this: the first version hung the whole call.)
cat "$NODE" 2>/dev/null > "$OUT" &
CAP_PID=$!
disown "$CAP_PID" 2>/dev/null || true

cleanup() {
  kill -TERM "$CAP_PID" 2>/dev/null || true
  sleep 0.2
  kill -KILL "$CAP_PID" 2>/dev/null || true
  wait "$CAP_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
sleep "$(awk -v ms="$SETTLE" 'BEGIN{printf "%.3f", ms/1000}')"
if ! kill -0 "$CAP_PID" 2>/dev/null; then
  echo "usbmon capture died immediately; nothing was recorded" >&2; exit 2
fi

START_NS=$(date +%s%N)
"${CMD[@]}" > "$STDOUT" 2>&1
RC=$?
END_NS=$(date +%s%N)

# Give the reader a moment to drain the last URBs, then stop it.
sleep 0.15
cleanup

BYTES=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
LINES=$(wc -l < "$OUT" 2>/dev/null || echo 0)
SHA=$(sha256sum "$OUT" 2>/dev/null | cut -d' ' -f1)

{
  echo "node          : $NODE"
  echo "command       : ${CMD[*]}"
  echo "exit_code     : $RC"
  echo "wall_ms       : $(( (END_NS - START_NS) / 1000000 ))"
  echo "capture_bytes : $BYTES"
  echo "capture_lines : $LINES"
  echo "capture_sha256: $SHA"
  echo "stdout        : $STDOUT"
} > "$META"

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  chown "$SUDO_USER":"$(id -gn "$SUDO_USER")" "$OUT" "$STDOUT" "$META" 2>/dev/null || true
fi

cat "$META"
exit $RC
