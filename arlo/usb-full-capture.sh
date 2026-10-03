#!/usr/bin/env bash
# Full-payload USB capture via tcpdump on usbmon.
#
# WHY THIS EXISTS: the usbmon *text* interface (/sys/kernel/debug/usb/usbmon/<bus>u)
# truncates the data display at 32 bytes. MEASURED 2026-10-03 (round 36/39): the EXEC
# trigger's reply is 64 bytes and carries DONE_MAGIC + retval + the payload's
# abi::Reply{command, status, current_el, scr_el3, sctlr_el3, ttbr0_el3, ...}.
# The text dump shows only command/status; bytes 32..64 are exactly the registers
# that answer whether the ROM runs with translation disabled (SCTLR_EL3.M) and
# carry the LOADER-FILL §12 step-1 CPU-state anchor.
#
# This captures the whole URB so those bytes are recoverable even while the tool
# itself discards them on a cancelled transfer (U-19, a9boot/UNVERIFIED.md).
#
# Usage:
#   tools/arlo/usb-full-capture.sh --bus 1 --out /tmp/exec.pcap -- <command to run>
# Then read it back:
#   tcpdump -r /tmp/exec.pcap -XX | less
#   tcpdump -r /tmp/exec.pcap -XX | grep -A2 'a1 02 ffff'   # the EXEC trigger

set -u

BUS=1
OUT=""
CMD=()

while [ $# -gt 0 ]; do
  case "$1" in
    --bus) BUS="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --)    shift; CMD=("$@"); break ;;
    *)     echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$OUT" ] || { echo "usage: $0 --bus N --out FILE -- CMD..." >&2; exit 2; }
[ ${#CMD[@]} -gt 0 ] || { echo "no command given after --" >&2; exit 2; }

IFACE="usbmon${BUS}"

# Fail loudly if the interface is not there: a silent no-capture would look exactly
# like "the device never answered", which is the inference this tool exists to protect.
if ! tcpdump -D 2>/dev/null | grep -q "usbmon${BUS}"; then
  echo "$0: no ${IFACE} interface; is usbmon loaded?" >&2
  exit 3
fi

# -U writes each packet as it arrives, so a later wedge still leaves a readable file.
# -s 0 = full snap length (the whole point; the default snaplen would truncate).
tcpdump -i "$IFACE" -s 0 -U -w "$OUT" >/dev/null 2>"${OUT}.err" &
TD=$!

# Give tcpdump time to attach and set up the ring before anything is sent.
sleep 1.5

"${CMD[@]}"
RC=$?

sleep 0.5
kill -TERM "$TD" 2>/dev/null
wait "$TD" 2>/dev/null

PACKETS=$(tcpdump -r "$OUT" 2>/dev/null | wc -l)
echo "usb-full-capture: rc=$RC packets=$PACKETS pcap=$OUT"
[ "$PACKETS" -gt 0 ] || echo "usb-full-capture: WARNING no packets captured — do not read this as 'the device was silent'" >&2
exit "$RC"
