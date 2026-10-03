# ep0cut — runbook for the wLength × latency ladder (task-9)

**Owner of this tool: `stages-analyst`. The Lead runs every device command.**

The tool has two modes. `--mode cut` (default) is the µs-deadline instrument that answered the
`sz` question; `--mode sweep` is the new wLength × latency ladder. **`--mode sweep` never cancels
anything** — it submits each request with a generous libusb timeout and reports what happens.

## The one command

```sh
# from the repo root; wraps the capture so the wire and the tool's own numbers land together
sudo tools/arlo/usbmon-capture.sh --bus 1 --out a9pwn-traces/linux/e3-sweep.txt -- \
  tools/arlo/ep0cut/target/release/ep0cut --mode sweep --json \
  > a9pwn-traces/linux/e3-sweep.json 2> a9pwn-traces/linux/e3-sweep.table.txt
```

That is 90 rows (3 shapes × 10 lengths × 3 repeats), round-robin, each completing in well under a
millisecond unless something times out. Budget ~10 s including the capture settle.

**With `--json`, the JSON document is the ONLY thing on stdout; the human table goes to stderr.**
The redirect above therefore leaves `e3-sweep.json` clean and `e3-sweep.table.txt` readable.

`--dry-run` prints the identical ladder and opens nothing — review it first:

```sh
tools/arlo/ep0cut/target/release/ep0cut --mode sweep --dry-run
```

**Always keep `getdesc` in `--shape`.** It is the calibration and the C1/C2 controls; a ladder
without it (e.g. `--shape dnload` alone) fails its own controls by design and reports
`INVALID LADDER`. To add the served-OUT calibration, name it explicitly and keep the control:

```sh
sudo tools/arlo/usbmon-capture.sh --bus 1 --out a9pwn-traces/linux/e3b-sweep-dnload.txt -- \
  tools/arlo/ep0cut/target/release/ep0cut --mode sweep \
    --shape pad,overflow,getdesc,dnload --json \
  > a9pwn-traces/linux/e3b-sweep-dnload.json 2> a9pwn-traces/linux/e3b-sweep-dnload.table.txt
```

## What it sends

| shape | setup packet | what it is |
|---|---|---|
| `pad` | `00 00 0000 0000 <len>` | checkm8 SETUP's pad (`gaster.c:853`); exploit length **1280** |
| `overflow` | `02 03 0000 0080 <len>` | PATCH's callback overflow (`gaster.c:1211`); exploit length **48** |
| `getdesc` | `80 06 0304 0409 <len>` | **the control** — a request this device provably answers (198 B stock / 228 B pwned) |
| `dnload` | `21 01 0000 0000 <len>` | opt-in only, **STATE-CHANGING**; a served-OUT calibration if you want one |

Default lengths: `0 16 48 64 128 256 512 1024 1280 2048`. OUT data stages are **zeros**, exactly
gaster's own `memset` (`gaster.c:475`) — the probe differs from the reference in nothing but the
length.

## Safety (why this one is safe to leave running)

* **It never calls `libusb_cancel_transfer`.** `--deadline-ms` (default 250) is libusb's own
  timeout. A row that exceeds it ends `TIMED_OUT`, the ladder **stops**, and `--reset-between`
  (default on) issues the measured recovery before the tool exits.
* A `TIMED_OUT` row means the device did not answer within 250 ms — much more likely at the long
  pad lengths than the short ones. If that happens, the printed partial ladder is still readable,
  and a re-run with `--lengths 0,16,48,64,128,256,512` separates the consumption question from the
  never-answered tail.
* `dnload` is never in the default set: it advances the ROM's DFU state.
* A reset does **not** clear a pwn (MEASURED), so a pwned device is a fine subject — and it is the
  right one, because PATCH's 48-byte overflow only exists on that path.

## The next run: `--mode abort-pad` (specified by the task-9 knee)

The sweep answered "does a **cold** pad consume its `wLength`?" — **no**: flat `-32/0` at ≤64 B
(171-187 µs on the wire), then a knee at 128 B where one 64-byte packet is consumed and the request
never answers (`-2 / 64` at libusb's 250 ms deadline; `e3-sweep.txt:1-10`). The exploit's pad is not
cold — it is issued immediately after an aborted 2048-byte DNLOAD. `abort-pad` measures that, with
a genuinely cold baseline in the same run:

```sh
sudo tools/arlo/usbmon-capture.sh --bus 1 --out a9pwn-traces/linux/e4-abort-pad.txt --   tools/arlo/ep0cut/target/release/ep0cut --mode abort-pad --json --continue-after-timeout   > a9pwn-traces/linux/e4-abort-pad.json 2> a9pwn-traces/linux/e4-abort-pad.table.txt
```

Per length (**1280 first**, then 256/128/64/0) it takes the pad at L **cold ×3** (the only
non-state-changing arm; its median, n and spread are printed per point and the spread widens that
point's tolerance), **resets between the arms** so the treatment arm does not inherit the cold
arm's history, then sends **aborted DNLOAD 2048 → pad at L with no reset between those two** (the exploit's own adjacency — the pad
immediately following is what keeps the abort's EP0 wedge recoverable). Any wedged **pad** row,
cold included, triggers a reset; the *abort* row is expected to end `CANCELLED` — that is the
cut, not a wedge — so it is not treated as one. `--abort-us N` moves the abort window from the
winning runs' 0 µs.

**Scope, stated in the tool's own header too.** This is the **isolated** abort→pad: the real
attempt-3 pad was preceded by two *completed* 2048-byte DNLOADs and two drains, and on a **pwned**
device it measures the **pwned EP0 path** — attribute a result to the SecureROM only with a stock
(power-cycled) control. `--continue-after-timeout` is in the recipe because the 128 B cold pad is
known to wedge; without it the run stops there.

**Is the reset prefix actually reproducing state? (T3-R's check, no new instrument.)** Run the same
mode with a repeated length:

```sh
tools/arlo/ep0cut/target/release/ep0cut --mode abort-pad --lengths 64,1280,64 --repeats 3 --json
```

The two `64` points are independent samples of the same "reset + abort + pad" treatment. If their
cold rows and their `after` rows agree within the run's own printed spreads, the reset prefix
reproduces the state; a systematic drift in the second says it does not. (`--lengths 1280,1280` is
the single-number version.) The residual asymmetry the code cannot remove: the between-arms reset is
preceded by the cold repeats, the point-start reset by the previous point's `after` row, and a port
reset refreshes ROM/heap state but does **not** clear the pwn.

**What its verdict means, and what it does not.** It classifies each point
(same / CHANGED / wedges-even-cold / wedged-after-cold-answered) and fits the after-arm's slope.
**`CHANGED` proves the pad is state-dependent, not that it consumed data** — the abort's cancel also
leaves an EP0-recovery cost a post-abort pad can absorb. Only a **rising after-slope at the
served-transfer per-packet cost** supports consumption; flat supports refusal.

## What the output will say, and what I need back

The tool prints, per point: N, median/min/max µs, spread, libusb's `sz`, and the status mix; then
the three controls; then, per malformed shape, a claim line and the **falsification**:

```
  pad (bm=00 b=00 ... ) — DATA CONSUMPTION (a) SUPPORTED
      served calibration = 25.1 us per 64-byte packet (n=6 GET_DESCRIPTOR points)
      noise floor = 12 us (largest same-status repeat spread)
      pad slope over all lengths = 28.4 us/packet (n=10)
      sub-ranges: <=512 B 27.9 us/packet, >=1024 B 29.1 us/packet
      exploit length 1280 B: median 890 us vs 158 us at wLength 0 (36.6 us per 64-byte packet over 20.00 packets)
      FALSIFIED IF: a repeat of the Pad row at its longest length lands within the noise floor (12 us)
      of the wLength-0 row (that is explanation (b)), or if the GET_DESCRIPTOR rows that return the
      SAME byte count at different asked lengths show the same slope (then the slope is a host
      artifact, not the device).
```

Thresholds, stated so they can be argued with: consumption needs `slope ≥ 0.5 × calibration` **and**
`slope > 2 × noise`; deliberation is `|slope| ≤ noise`; a knee is a flat low half (≤512 B) plus a
rising high half (≥1024 B) at ≥ half the calibration. Anything between is `INDETERMINATE`, and the
tool says so rather than picking a side.

Hand me: the tool's stdout (the `--json` file if you used it), the usbmon capture, and the `ident`
output before and after. I will do the fitting and write the analysis against the same
MEASURED / INSPECTED / INFERRED rules as `a9pwn/docs/LINUX-REFERENCE-NOTES.md`.

## The instrument's own controls, which are part of the result

* **C1** — at least one `getdesc` row must COMPLETE with > 0 bytes, or the device is not answering
  and every other row is meaningless.
* **C2** — the `getdesc` rows that return the **same** byte count at **different** asked lengths
  must be flat within 2× the noise floor. If they are not, a slope measured on the malformed shapes
  is host drift, not the device, and the tool fails the ladder on purpose.
* **C3** — the `wLength = 0` rows are the baseline every per-packet number is measured from.

## Offline evidence that this build is the one described here

`tools/arlo/ep0cut/evidence/task9-offline.txt` — `cargo test` (**24 passed**), `cargo build`, and the
`--dry-run` ladders for all three modes with the exact setup bytes. The setup-byte unit test pins
them against the bytes MEASURED on the wire in `our-run1.txt` / `e4-gaster-1.txt`.
