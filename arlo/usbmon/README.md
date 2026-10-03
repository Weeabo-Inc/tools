# `usbmon` — read a Linux usbmon capture and report what the kernel recorded

Rust, no clap, two dependencies (`serde_json`, `sha2`) — the same two
`tools/arlo/traceview` already uses, so both are cached and `--offline` works.

**It reads a file. It opens no device, needs no root, and links no libusb.** The
usbmon debugfs node is root-only, so `tools/arlo/usbmon-capture.sh` reads it
under `sudo` and leaves a text file plus a `.meta` sidecar (command, exit code,
sha256 of the capture). This crate is what turns that text into an instrument.

## Build and run

```sh
cd tools/arlo/usbmon
cargo build --release          # 0 warnings
cargo test  --release          # 68 unit + 54 integration = 122 tests

B=./target/release/usbmon            # from tools/arlo/usbmon, the repo root is ../../..
R=../../../a9pwn-traces/linux
$B $R/e0-ident.txt summary --expect-sha256 f5318147…e0f8    # exit 0
$B $R/neg-selftest.txt summary                              # exit 5: 0 URBs
$B $R/e4-gaster-1.txt report                                # the reference pwn
$B $R/our-run1.txt report                                   # our winning run
$B $R/our-run1.txt attempts --device 1:008                  # + the host-log join
$B $R/e4-gaster-1.txt attempts --device 1:005
$B $R/e4-gaster-1.txt json | jq .parse
$B --help
```

`--host-log FILE` joins a9pwn's own JSONL trace, and by default a sibling
`<capture>.jsonl` is picked up automatically (stated in the header, suppressed by
`--no-host-log`). Everything from it is labelled `[MEASURED host log]` and kept
apart from wire values, because the two instruments time different intervals: the
host times `libusb` submit→callback, the kernel times URB submit→callback. The
wire **cannot** show an abort window that never fired — a 4 ms window whose
transfer completed in 935 us leaves no trace — so `abort_after_ms` only ever
comes from the host trace, and the report says so.

The join is by **full setup packet in submit order**, and it is gated:

- If it fails, `host log join FAILED` is printed and **no host value is attached
  to anything** — no window, no per-transfer label, `host_log: null` in JSON.
- Each matched pair is then checked against the other instrument. Where they
  disagree the report says so and `--strict` fails: a permuted host trace (two
  identical setup packets swapped) shows up as `host says CANCELLED … the wire
  says 0 OK`; and the known `abort_xfer` defect shows up as `host says TIMEOUT
  with 0 B, the wire shows 528 B moved` for PATCH's upload chunk — the wire is the
  authority on what the device took, the host log is the authority on what the
  host asked for.
- The join matches the **first** wire transfer (in submit order) whose full setup
  packet agrees, so a decoy elsewhere on the bus carrying the same setup could
  steal a match; the contradiction check is what exposes that.
- What the join does **not** prove: a9pwn's JSONL carries no run id, so a trace
  from a *different* run with the same request sequence would also join. Pass
  `--host-log` deliberately, and treat the `[INFERRED] host minus wire` delta line
  as the sanity check it is.

## Commands

| command | answers |
|---|---|
| `summary` | pairing, per-device/per-request/per-status counts, bytes moved, control-OUT data stages, `GET_DESCRIPTOR` lengths, decoded device descriptors, non-OK completions |
| `list` | one line per transfer, in submit order (`list --gaps-ms 100` = the device-absence view) |
| `attempts` | the SETUP tick: 0x800 DNLOAD → pad → drain, grouped contiguously |
| `report` | `summary` + `attempts` — the whole capture in one command |
| `json` | everything above as one JSON object (stdout is JSON and nothing else) |

Filters: `--device BUS:ADDR`, `--request NAME|NUM`, `--endpoint EP`,
`--status OK|STALL|TIMEOUT|CANCELLED|PENDING|ECONNRESET|ESHUTDOWN|EREMOTEIO|code`,
`--dir`, `--type`.

`--status STALL` expands to **-32 EPIPE and -71 EPROTO** and prints that
expansion: on Linux a device STALL on a control transfer reaches the host as
`-EPIPE`, while `-71 EPROTO` is a transaction/protocol error. They are not
synonyms, and `-121 EREMOTEIO` is a third thing. The tool never collapses them.

**Counts are keyed on the FULL setup packet** (`bm b wValue wIndex wLength`), and
the output says so. Grouping by `(bm, b)` merges requests that differ only in
`wLength`, and on this wire that is exactly SPRAY's stall primitive
`02 03 0000 0080 0000` versus PATCH's 48-byte overflow `02 03 0000 0080 0030` —
one merged row with one misleading count instead of two requests with two
latencies. There is a fixture for that pair in the test suite.

## Exit codes

| code | meaning |
|---|---|
| 0 | read, parsed clean, at least one URB matched |
| 2 | usage error |
| 3 | the file could not be read |
| 4 | structural errors: not usbmon `u` output the tool can trust |
| 5 | parsed clean but **nothing matched** — empty file, or a filter that selected nothing |
| 6 | `--strict` and the file carried warnings (including a boundary completion) |
| 7 | `--expect-sha256` mismatch |

Exit 5 is the negative-control pass condition: *an offline command must produce
zero URBs*, and "zero URBs" must never read as success. It covers an empty file
**and any filter that selected nothing** — `--request SET_ADDRESS`,
`--status ETIMEDOUT`, `--device 1:099` — so a gate reading `$?` can never be told
the capture contains a request it does not. `--force` prints the analysis despite
structural errors, and the exit code stays 4 (a file with structural errors is
never reported as "parsed clean", and never as 5).

## The grammar it enforces (and why each rejection is legitimate)

Read off `drivers/usb/mon/mon_text.c`, not guessed from samples:

```
<tag> <ts-us> <S|C|E> <type><dir>:<bus>:<dev>:<ep> ...
  control/bulk S : " s <bm> <b> <wValue> <wIndex> <wLength>" <len> <datatag>
  control S, no setup captured : " Z __ __ ____ ____ ____" <len> <datatag>
  control/bulk C : <status> <len> <datatag>
  bulk/int S     : <status> <len> <datatag>        (status is always -115 EINPROGRESS)
  interrupt      : <status>:<interval> <len> <datatag>
  E              : <status> 0                      (always exactly these)
  datatag        : '<' IN submit | '>' OUT callback | Z/D unavailable
                 | " =" then up to 32 bytes, 4-byte groups, last group partial
```

Structural **errors** (exit 4) are things the kernel's formatter cannot emit:
a callback with no submit in the file is *not* one of them (see below), but a
callback whose transferred length exceeds the submit's request is, because
`actual_length <= transfer_buffer_length` always. Also errors: malformed or
truncated fields, a callback carrying a setup packet, a control submit without
one, an `E` line with a nonzero length, more than 32 printed data bytes
(`DATA_MAX`), printed bytes exceeding the declared length, a data tag on a
zero-length transfer or a missing tag on a nonzero one, a data tag in a
direction/event combination the kernel never produces, a duplicate submit for a
tag still outstanding, a completion whose address/type/direction differs from its
submit, isochronous lines (a different layout — refused, not mis-read), and `t`
-node lines (no bus field).

Warnings (exit 0, or 6 under `--strict`) are things that *are* possible but a
reader must see: a completion whose submit is not in the file, timestamps that go
backwards (reported as a negative elapsed, never silently abs'd), setup `wLength`
disagreeing with `transfer_buffer_length`, a non-control submit not carrying
`-115`, a hex field written in **upper case** (the kernel prints `%lx`/`%02x`/
`%04x`, so something rewrote the line — case does not change meaning, so this is
not an error), and a data section **shorter than `min(length, 32)`**, which the
32-byte display cap cannot explain (a short scatter-gather first segment can, and
so can a capture truncated at a group boundary — the note says both instead of
inventing one).

## The serial descriptor: the index moves, so nothing may hardcode it

The PWND marker is a **length signature**, not a fixed index. On this phone the
declared `iSerialNumber` has been observed as 4 and as 6 on different
enumerations, and the marker follows it (index 4 → 228 B on one enumeration,
index 6 → 228 B on another). `summary` therefore reports, per device:

* the index the **device descriptor on the wire declares** (`iSerialNumber`), and
  every value seen for that address;
* what a read **at that declared index** returned, and whether it is in the file
  at all;
* the longest STRING read per device, compared against **this capture's own**
  shortest such read — not against a hardcoded 198 — with `+30 B` named as the
  length of ` PWND:[checkm8]` (15 UTF-16 units) when it appears.

The marker *text* is never claimed: usbmon prints at most 32 bytes of a
descriptor and the marker sits past that window. Two fixtures,
`synthetic-marker-idx4.txt` and `synthetic-marker-idx6.txt`, put the marker at
index 4 and at index 6 respectively, each with a 198-byte read as the negative
control; a test proves the tool reports the marker in **both** and never calls the
198-byte string marker-length in either.

## Two properties that make it honest

**The 32-byte cap.** usbmon's text interface copies at most `DATA_MAX = 32` bytes
per line. A 198-byte descriptor read shows 32 bytes, and the tool says
`data 32 of 198 B shown; usbmon's text interface caps display at 32 B` rather
than letting 32 bytes stand for the payload.

**Boundary completions.** A completion with no submit line means the capture is
incomplete for that URB — the URB was submitted before the reader opened, or an
event was lost from usbmon's ring. The E4 gold capture contains one (the root
hub's interrupt URB). It is printed as `[BOUNDARY]`, counted in the header, and
**excluded from paired analysis**; it is never an error (that would reject real
captures) and never silent (that would be the wrong-value failure this project
keeps paying for). `--strict` fails on it.

## What it proves, and what it cannot

- Bounds: the listed problem list is capped at 1000 entries so a corrupt
  gigabyte cannot exhaust memory; the header and JSON counts stay exact, and the
  report states how many were counted but not listed. A line with no newline is
  drained to at most 64 MiB and then reported as `line-unterminated` rather than
  reading forever. A FIFO with no writer still blocks in `open(2)` — POSIX
  behaviour, not something this tool controls.
- Proves: what a given capture contains — the setup packets, the completion
  statuses, the transferred lengths, the timings in microseconds, which device
  address each URB belongs to, and the descriptor lengths per device.
- Proves the artifact identity with `--expect-sha256`, so a report cannot drift
  onto other bytes.
- **Cannot** say anything the file does not: a submit without a callback is "not
  in this file", never "the device refused". A missing line and a line that was
  never written look identical.
- `usbmon` timestamps are 32-bit microseconds that wrap every 4096 s; a
  backwards step is reported, and the wrap is named as a possibility, not
  applied silently.
- Request *names* are tables (`USB 2.0` table 9.4, `DFU 1.1` table 3) selected by
  `bmRequestType` bits 6:5, so `GET_DESCRIPTOR(6)` and `DFU_ABORT(6)` are never
  confused. The grouping in `attempts` is labelled `[INFERRED]`: it is a rule
  over wLengths (`--setup-len`, `--pad-len`, `--drain-len`), not a device fact.

## Validation against the gold capture

Two real captures are pinned by hash in the tests:

* `a9pwn-traces/linux/our-run1.txt` (sha256 `366e5c63…27cc`) — **our winning
  run**, with `our-run1.jsonl` joined: 3 SETUP attempts, abort windows `4, 5, 0` ms
  from the host trace, abort elapsed `935 / 974 / 70` us on the wire (`946 / 981 /
  87` us host), pad `00 00 0000 0000 0500` STALL at **736 us**, drains at 79/72 us,
  the device moving `1:008 → 1:009 → 1:010`, and the marker-length read in *that
  file* at `idx 6` (228 B) while its stock read is `idx 4` (198 B). The index is
  derived per file — it moves between enumerations — see the serial-descriptor
  section below.
* `a9pwn-traces/linux/e4-gaster-1.txt` (sha256 `d66021f4…4926fa`) — the reference
  `gaster pwn` run, same shape, **different latencies** (pad 889 us, abort 117 us,
  `1:005 → 1:006 → 1:007`). A test asserts the two captures do *not* report the
  same numbers, so a tool reading the wrong file or hardcoding cannot pass.

The integration tests pin both by hash and reproduce the wire story exactly — the pad STALL (`00 00 0000 0000 0500`
at 177811285 → `-32` at 177812174 = **889 us**), the aborted 2048-byte DNLOAD
(177811111 → `-2` at 177811228 = **117 us**), the two windows that completed
2048/2048 (992 us, 974 us) each followed by a 64-byte drain, the two SET_FEATURE(EP0) requests
that differ only in wLength — SPRAY's stall `02 03 0000 0080 0000` → `-32` at 158 us
and PATCH's 48-byte overflow `02 03 0000 0080 0030` → `-32` at 167 us — the two leak reads (`80 06 0304 000a`,
cancelled at 1191/1250 us), `21 04 … 00c1` → `-71 EPROTO` with 64 of 193 bytes,
the re-enumeration `1:005 → 1:006 → 1:007`, and the serial-string length change
(198 B at `idx 4` on the stock device, 228 B at `idx 6` on the pwned one, with
`iSerialNumber` 4 → 6 in the device descriptor).

## Negative controls

Every rejection rule has a test that shows it failing, and the tests that use the
gold capture have a doctored counterpart (`gold_predicates_are_falsified_by_a_doctored_pad_status`)
so the predicates themselves are shown to be falsifiable. `cargo test` covers:
wrong byte count, >32 printed bytes, printed bytes over the declared length,
truncated line, unmatched callback, callback before its submit, duplicate submit,
callback on the wrong device, binary garbage, a 3 MiB line, backwards timestamps,
iso and `t`-node lines, blank line, empty file, under-printed data, upper-case hex, a
request filter that matches nothing, `--force` with structural errors, an
unterminated 70 MiB line, 2500-problem counting, and every filter/gate exit code.
The SPRAY-stall/PATCH-overflow pair has its own fixture, and two tests fail if the
tool ever reports the same latency for `our-run1.txt` and `e4-gaster-1.txt`.
