//! ep0cut — two instruments on one EP0.
//!
//! `--mode cut` (default)
//!   Cut a control IN transfer the device is ACTUALLY ANSWERING at a chosen
//!   **microsecond** deadline and report libusb's own `actual_length`. This is the
//!   instrument for the `sz` question: does libusb on Linux report a real partial
//!   count for a cancelled control transfer? (Answer, MEASURED 2026-10-03: yes —
//!   graded 64/128/192/198 on `GET_DESCRIPTOR(3,4)`.)
//!
//! `--mode sweep`
//!   The **wLength x latency** ladder. It sends the malformed request shapes the
//!   checkm8 stages use — the pad shape (`bm=00 b=00`, `gaster.c:853`) and the
//!   PATCH-overflow shape (`bm=02 b=03 wIndex=0x80`, `gaster.c:1211`) — at a swept
//!   `wLength`, and reports per point: status, libusb's byte count, elapsed µs.
//!   It answers one question: is a STALL that follows one of these requests
//!   **data consumption** (the ROM moved the bytes, then refused) or
//!   **deliberation** (a fixed delay unrelated to length)?
//!
//!   `GET_DESCRIPTOR(3,<declared index>)` is the control: a request this device
//!   provably ANSWERS (198 bytes stock / 228 bytes pwned, ~150-200 us). Its rows
//!   calibrate what a *served* transfer costs per packet on this host, and its
//!   rows that return the SAME number of bytes at DIFFERENT asked lengths must
//!   show a flat latency — if they do not, a slope in the malformed shapes is a
//!   host artifact, not a device property.
//!
//! `--mode sweep` **never cancels anything**. A row is submitted with a generous
//! libusb timeout (`--deadline-ms`, default 250) and reported as it lands. If a
//! row exceeds it, libusb itself times the URB out (which internally cancels it);
//! that is recorded, the ladder stops (a cancel can wedge EP0 on this bootrom:
//! the device stays enumerated and NAKs control requests until a port reset —
//! MEASURED), and `--reset-between` (default on) performs the measured recovery
//! before the tool exits. `--continue-after-timeout` overrides the stop.
//!
//! LEAD-ONLY: this opens the USB device. `--dry-run` never does — it prints the
//! exact ladder for review and exits 0.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use libusb1_sys as sys;
use libusb1_sys::constants::*;

const VID: u16 = 0x05ac;
const PID: u16 = 0x1227;
const IDENT_INDEX_FALLBACK: u8 = 4;
const EN_US: u16 = 0x0409;

/// The ladder required by task-9 (`0 64 128 256 512 1024 1280 2048`) plus the two
/// lengths the exploit actually uses: **48** (`sizeof(checkm8_overwrite_t)`,
/// gaster.c:111-113) for the PATCH shape, 16 (`DFU_FILE_SUFFIX_LEN`) and **1280**
/// (`config_overwrite_pad` for CPID 0x8003, gaster.c:626) for the pad shape.
/// Asked lengths, not returned bytes: for `getdesc` the device returns
/// `min(descriptor_len, wLength)`, which is what the calibration uses.
const DEFAULT_LENGTHS: [u16; 10] = [0, 16, 48, 64, 128, 256, 512, 1024, 1280, 2048];
const DEFAULT_REPEATS: u32 = 3;
const DEFAULT_SWEEP_DEADLINE_MS: u32 = 250;

/// libusb calls this from `libusb_handle_events_*`. One transfer is in flight at a
/// time in both modes, so a single flag is the completion signal.
static COMPLETED: AtomicBool = AtomicBool::new(false);

extern "system" fn on_complete(_t: *mut sys::libusb_transfer) {
    COMPLETED.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Request shapes
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Cut,
    Sweep,
    /// The exploit's own order: aborted 2048-byte DNLOAD, then the pad, with NO
    /// reset in between. For each length the same run also takes a COLD pad at
    /// that length, so the state effect is measured internally rather than
    /// compared across runs.
    AbortPad,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub enum Shape {
    /// `bm=0x00, b=0x00, wValue=0, wIndex=0` — the malformed pad request whose
    /// STALL is checkm8 SETUP's pass condition (`gaster.c:853`).
    Pad,
    /// `bm=0x02, b=0x03, wValue=0, wIndex=0x80` — PATCH's 48-byte callback
    /// overflow (`gaster.c:1211`).
    Overflow,
    /// `GET_DESCRIPTOR(3, index)` — the CONTROL. A served transfer.
    GetDesc,
    /// `bm=0x21, b=0x01, wValue=0, wIndex=0` — DFU_DNLOAD, an opt-in served-OUT
    /// control. STATE-CHANGING: it advances the ROM's DFU state (and on a pwned
    /// device it is the same class request the payload watches), so it is only
    /// ever sent when asked for by name.
    Dnload,
}

impl Shape {
    pub fn label(self) -> &'static str {
        match self {
            Shape::Pad => "pad",
            Shape::Overflow => "overflow",
            Shape::GetDesc => "getdesc",
            Shape::Dnload => "dnload",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Shape::Pad => "bm=00 b=00 wValue=0 wIndex=0 (pad, gaster.c:853)",
            Shape::Overflow => "bm=02 b=03 wValue=0 wIndex=0x80 (overflow, gaster.c:1211)",
            Shape::GetDesc => "bm=80 b=06 wValue=(3<<8)|index wIndex=0x0409 (control)",
            Shape::Dnload => "bm=21 b=01 wValue=0 wIndex=0 (DFU_DNLOAD, STATE-CHANGING)",
        }
    }

    pub fn is_in(self) -> bool {
        matches!(self, Shape::GetDesc)
    }

    pub fn is_state_changing(self) -> bool {
        matches!(self, Shape::Dnload)
    }

    /// The 8-byte setup packet exactly as it goes on the wire. Pure, so the
    /// reference's own bytes are pinned by a test rather than by inspection.
    pub fn setup(self, length: u16, index: u8) -> [u8; 8] {
        let [lo, hi] = length.to_le_bytes();
        match self {
            Shape::Pad => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, lo, hi],
            Shape::Overflow => [0x02, 0x03, 0x00, 0x00, 0x80, 0x00, lo, hi],
            Shape::GetDesc => {
                let [vl, vh] = ((3u16 << 8) | index as u16).to_le_bytes();
                let [il, ih] = EN_US.to_le_bytes();
                [0x80, 0x06, vl, vh, il, ih, lo, hi]
            }
            Shape::Dnload => [0x21, 0x01, 0x00, 0x00, 0x00, 0x00, lo, hi],
        }
    }

    pub fn default_set() -> Vec<Shape> {
        vec![Shape::Pad, Shape::Overflow, Shape::GetDesc]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pattern {
    /// All zeros — exactly what gaster sends (`memset(p_data, '\0', w_len)`,
    /// `gaster.c:475`). The default, because a latency probe should differ from
    /// the reference in NOTHING but the length.
    Zeros,
    /// `00 01 02 ... ff 00 ...` — for correlating a row with a usbmon capture.
    Ramp,
    /// `0xa5` everywhere.
    A5,
}

pub fn fill_pattern(buf: &mut [u8], p: Pattern) {
    match p {
        Pattern::Zeros => buf.fill(0),
        Pattern::Ramp => {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i & 0xff) as u8;
            }
        }
        Pattern::A5 => buf.fill(0xa5),
    }
}

// ---------------------------------------------------------------------------
// Arguments (pure parser — testable without a device)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Args {
    pub mode: Mode,
    pub index: Option<u8>,
    pub fallback_index: u8,
    pub cut_length: u16,
    pub cut_deadlines_us: Vec<u64>,
    pub shapes: Vec<Shape>,
    pub lengths: Vec<u16>,
    /// True when the operator passed `--lengths`; `abort-pad` uses its own
    /// default ladder when they did not.
    pub lengths_explicit: bool,
    pub repeats: u32,
    pub sweep_deadline_ms: u32,
    /// `abort-pad` mode: how long the 2048-byte DNLOAD runs before it is cancelled.
    /// 0 reproduces the winning runs' window-0 cut (`abort_window_ms=0`).
    pub abort_us: u64,
    pub reset_between: bool,
    pub continue_after_timeout: bool,
    pub pattern: Pattern,
    pub json: bool,
    pub dry_run: bool,
}

impl Default for Args {
    fn default() -> Self {
        Args {
            mode: Mode::Cut,
            index: None,
            fallback_index: IDENT_INDEX_FALLBACK,
            cut_length: 255,
            // Dense on purpose around the ~150 us answer latency this device
            // MEASURED for a 198-byte descriptor read: a ladder that only samples
            // 0 and 2 ms cannot land mid-data at all.
            cut_deadlines_us: Vec::new(),
            shapes: Shape::default_set(),
            lengths: DEFAULT_LENGTHS.to_vec(),
            lengths_explicit: false,
            repeats: DEFAULT_REPEATS,
            sweep_deadline_ms: DEFAULT_SWEEP_DEADLINE_MS,
            abort_us: 0,
            reset_between: true,
            continue_after_timeout: false,
            pattern: Pattern::Zeros,
            json: false,
            dry_run: false,
        }
    }
}

impl Args {
    pub fn effective_deadlines(&self) -> Vec<u64> {
        if self.cut_deadlines_us.is_empty() {
            vec![0, 25, 50, 75, 100, 125, 150, 300, 2_000]
        } else {
            self.cut_deadlines_us.clone()
        }
    }
}

fn parse_shapes(s: &str) -> Result<Vec<Shape>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        let sh = match p {
            "pad" => Shape::Pad,
            "overflow" => Shape::Overflow,
            "getdesc" => Shape::GetDesc,
            "dnload" => Shape::Dnload,
            other => return Err(format!("unknown --shape {other:?} (pad|overflow|getdesc|dnload)")),
        };
        if !out.contains(&sh) {
            out.push(sh);
        }
    }
    if out.is_empty() {
        return Err("--shape was empty".to_string());
    }
    Ok(out)
}

fn parse_lengths(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let p = part.trim();
        let n: u16 = p.parse().map_err(|_| format!("bad --lengths value {p:?}"))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    if out.is_empty() {
        return Err("--lengths was empty".to_string());
    }
    Ok(out)
}

pub fn parse_args_from(argv: &[String]) -> Result<Args, String> {
    let mut a = Args::default();
    let mut lengths: Option<Vec<u16>> = None;
    let mut shapes: Option<Vec<Shape>> = None;
    let mut i = 0;
    while i < argv.len() {
        let next = |i: usize| -> Result<String, String> {
            argv.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} needs a value", argv[i]))
        };
        match argv[i].as_str() {
            "--mode" => {
                let v = next(i)?;
                a.mode = match v.as_str() {
                    "cut" => Mode::Cut,
                    "sweep" => Mode::Sweep,
                    "abort-pad" => Mode::AbortPad,
                    other => {
                        return Err(format!("unknown --mode {other:?} (cut|sweep|abort-pad)"))
                    }
                };
                i += 2;
            }
            "--index" => {
                a.index = Some(next(i)?.parse().map_err(|_| "--index needs 0..255".to_string())?);
                i += 2;
            }
            "--length" => {
                a.cut_length =
                    next(i)?.parse().map_err(|_| "--length needs 0..65535".to_string())?;
                i += 2;
            }
            "--deadline-us" => {
                let v: u64 =
                    next(i)?.parse().map_err(|_| "--deadline-us needs a number".to_string())?;
                a.cut_deadlines_us.push(v);
                i += 2;
            }
            "--deadline-ms" => {
                let v: u32 =
                    next(i)?.parse().map_err(|_| "--deadline-ms needs a number".to_string())?;
                if v == 0 {
                    return Err("--deadline-ms 0 is refused: sweep mode must not cancel".to_string());
                }
                a.sweep_deadline_ms = v;
                i += 2;
            }
            "--abort-us" => {
                a.abort_us =
                    next(i)?.parse().map_err(|_| "--abort-us needs a number".to_string())?;
                i += 2;
            }
            "--lengths" => {
                let v = parse_lengths(&next(i)?)?;
                lengths = Some(match lengths {
                    Some(mut have) => {
                        for n in v {
                            if !have.contains(&n) {
                                have.push(n);
                            }
                        }
                        have
                    }
                    None => v,
                });
                i += 2;
            }
            "--shape" => {
                let v = parse_shapes(&next(i)?)?;
                shapes = Some(match shapes {
                    Some(mut have) => {
                        for s in v {
                            if !have.contains(&s) {
                                have.push(s);
                            }
                        }
                        have
                    }
                    None => v,
                });
                i += 2;
            }
            "--repeats" => {
                let v: u32 =
                    next(i)?.parse().map_err(|_| "--repeats needs a number".to_string())?;
                if v == 0 {
                    return Err("--repeats 0 gives no measurement".to_string());
                }
                a.repeats = v;
                i += 2;
            }
            "--pattern" => {
                let v = next(i)?;
                a.pattern = match v.as_str() {
                    "zeros" => Pattern::Zeros,
                    "ramp" => Pattern::Ramp,
                    "a5" => Pattern::A5,
                    other => return Err(format!("unknown --pattern {other:?} (zeros|ramp|a5)")),
                };
                i += 2;
            }
            "--no-reset-between" => {
                a.reset_between = false;
                i += 1;
            }
            "--continue-after-timeout" => {
                a.continue_after_timeout = true;
                i += 1;
            }
            "--dry-run" => {
                a.dry_run = true;
                i += 1;
            }
            "--json" => {
                a.json = true;
                i += 1;
            }
            "--help" | "-h" => return Err(usage_text()),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if let Some(l) = lengths {
        a.lengths = l;
        a.lengths_explicit = true;
    }
    if let Some(s) = shapes {
        a.shapes = s;
    }
    Ok(a)
}

pub fn usage_text() -> String {
    format!(
        "ep0cut — two instruments on one EP0 (LEAD-ONLY: opens the USB device)\n\
         \n\
         USAGE: ep0cut [--mode cut|sweep|abort-pad] [options]\n\
         \n\
         MODE cut (default) — cut GET_DESCRIPTOR at a MICROSECOND deadline:\n\
           --index N            string-descriptor index (default: the DECLARED\n\
                                iSerialNumber from the device descriptor, then {fallback})\n\
           --length N           wLength of the read (default 255)\n\
           --deadline-us N      repeatable; the ladder to run\n\
                                default: 0 25 50 75 100 125 150 300 2000\n\
           --no-reset-between   do NOT reset after a cancelled row (read the safety note)\n\
         \n\
         MODE sweep — the wLength x latency ladder. THIS MODE CANCELS NOTHING:\n\
           --shape LIST         pad,overflow,getdesc (default all three) | dnload (opt-in,\n\
                                STATE-CHANGING — only when named)\n\
           --lengths LIST       default: {defaults:?}\n\
           --repeats N          repeats per point, round-robin (default {repeats})\n\
           --deadline-ms N      generous per-row libusb timeout (default {deadline} ms;\n\
                                0 is refused). A row that exceeds it is TIMED_OUT and the\n\
                                ladder stops unless --continue-after-timeout.\n\
           --pattern P          zeros (default, gaster's own) | ramp | a5\n\
           --continue-after-timeout\n\
           --no-reset-between   do NOT reset after a TIMED_OUT row\n\
         \n\
         MODE abort-pad — the exploit's own order (STATE-CHANGING):\n\
           For each length: a COLD pad at L, then an aborted 2048-byte DFU_DNLOAD\n\
           (cancelled after --abort-us, default 0 = the winning runs' cut), then the\n\
           pad at L again with NO reset in between. Reports all three rows per point.\n\
           --abort-us N         cancel the DNLOAD after N microseconds (default 0)\n\
           Uses --lengths, --repeats, --deadline-ms, --pattern, --reset-between.\n\
         \n\
         COMMON\n\
           --dry-run            print the exact requests and exit; NEVER opens the device\n\
           --json               machine-readable output\n\
           -h, --help           this text\n\
         \n\
         EXIT  0 completed · 1 ladder INVALID or incomplete · 2 bad args / no device\n\
         \n\
         WHY sweep EXISTS. A STALL after a malformed request is checkm8's pass condition\n\
         (gaster.c:853, :1211), but a STALL is also what the ROM returns when it refuses\n\
         before touching the data. The same question decides whether PATCH's 48-byte\n\
         overflow stage is consumed. If latency rises with wLength at the per-packet cost\n\
         the GET_DESCRIPTOR control measures, the bytes are being consumed; if it is flat,\n\
         they are not. A table without that comparison is not a result.",
        fallback = IDENT_INDEX_FALLBACK,
        defaults = DEFAULT_LENGTHS,
        repeats = DEFAULT_REPEATS,
        deadline = DEFAULT_SWEEP_DEADLINE_MS,
    )
}

// ---------------------------------------------------------------------------
// The ladder (pure)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub round: u32,
    pub shape: Shape,
    pub length: u16,
}

/// Round-robin: every repeat walks ALL shapes and lengths in the same order.
///
/// This is not cosmetic. A sequential ladder (all lengths of one shape, then the
/// next) cannot tell a device slope from host drift — the later rows are later in
/// wall-clock time as well as longer, so a rising host cost manufactures a slope.
/// Interleaving makes drift affect every point equally.
pub fn plan(a: &Args) -> Vec<Step> {
    let mut out = Vec::new();
    for round in 0..a.repeats {
        for shape in &a.shapes {
            for length in &a.lengths {
                out.push(Step { round, shape: *shape, length: *length });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Samples and the pure analysis
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub elapsed_us: u64,
    pub status: i32,
    pub sz: i32,
}

#[derive(Clone, Debug)]
pub struct Point {
    pub shape: Shape,
    pub length: u16,
    pub samples: Vec<Sample>,
}

#[derive(Clone, Debug)]
pub struct RowStat {
    pub shape: Shape,
    pub length: u16,
    pub n: usize,
    pub median_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub median_sz: i32,
    pub statuses: Vec<(i32, usize)>,
}

/// Did the DEVICE answer this row, or did the host's own deadline end it?
///
/// A `TIMED_OUT` row's "latency" is libusb's deadline, not a device latency, so it
/// must never enter a slope fit: a slope through a host timeout always comes out as
/// "consumption supported" (MEASURED 2026-10-03 on the stock cold pad row, where it
/// printed 12792.6 us/packet — a measurement of the host).
pub fn is_silent_status(status: i32) -> bool {
    matches!(
        status,
        LIBUSB_TRANSFER_TIMED_OUT | LIBUSB_TRANSFER_CANCELLED | LIBUSB_TRANSFER_NO_DEVICE
    )
}

/// A row is "answered" only when every repeat ended in a non-silent status.
pub fn answered(r: &RowStat) -> bool {
    !r.statuses.is_empty() && r.statuses.iter().all(|(s, _)| !is_silent_status(*s))
}

/// A row is "wedged" when every repeat went silent.
pub fn wedged(r: &RowStat) -> bool {
    !r.statuses.is_empty() && r.statuses.iter().all(|(s, _)| is_silent_status(*s))
}

pub fn median(v: &mut [u64]) -> u64 {
    if v.is_empty() {
        return 0;
    }
    v.sort_unstable();
    let n = v.len();
    if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2
    }
}

pub fn stat_points(points: &[Point]) -> Vec<RowStat> {
    points
        .iter()
        .map(|p| {
            let mut lat: Vec<u64> = p.samples.iter().map(|s| s.elapsed_us).collect();
            let mut szs: Vec<i64> = p.samples.iter().map(|s| s.sz as i64).collect();
            let n = lat.len();
            let median_us = median(&mut lat);
            let min_us = lat.first().copied().unwrap_or(0);
            let max_us = lat.last().copied().unwrap_or(0);
            szs.sort_unstable();
            let median_sz: i32 = if szs.is_empty() {
                0
            } else if n % 2 == 1 {
                szs[n / 2] as i32
            } else {
                ((szs[n / 2 - 1] + szs[n / 2]) / 2) as i32
            };
            let mut statuses: Vec<(i32, usize)> = Vec::new();
            for s in &p.samples {
                match statuses.iter_mut().find(|(st, _)| *st == s.status) {
                    Some(e) => e.1 += 1,
                    None => statuses.push((s.status, 1)),
                }
            }
            RowStat { shape: p.shape, length: p.length, n, median_us, min_us, max_us, median_sz, statuses }
        })
        .collect()
}

/// Least-squares slope of `ys` on `xs`; `None` when there is no variation in `xs`.
pub fn ls_slope(xs: &[f64], ys: &[f64]) -> Option<f64> {
    if xs.len() < 2 || xs.len() != ys.len() {
        return None;
    }
    let n = xs.len() as f64;
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..xs.len() {
        num += (xs[i] - mx) * (ys[i] - my);
        den += (xs[i] - mx).powi(2);
    }
    if den <= f64::EPSILON {
        None
    } else {
        Some(num / den)
    }
}

fn slope_for(stats: &[RowStat], shape: Shape, lo: u16, hi: u16) -> Option<(f64, usize)> {
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for r in stats
        .iter()
        .filter(|r| r.shape == shape && r.length >= lo && r.length <= hi && answered(r))
    {
        xs.push(r.length as f64 / 64.0);
        ys.push(r.median_us as f64);
    }
    ls_slope(&xs, &ys).map(|s| (s, xs.len()))
}

/// The instrument's own jitter: the largest min..max spread among points whose
/// repeats all ended in the SAME status. A point that mixes COMPLETED and
/// TIMED_OUT is a state change, not noise, and is excluded.
pub fn noise_floor(stats: &[RowStat]) -> u64 {
    stats
        .iter()
        .filter(|r| r.n >= 2 && r.statuses.len() == 1 && answered(r))
        .map(|r| r.max_us.saturating_sub(r.min_us))
        .max()
        .unwrap_or(0)
}

/// What a SERVED transfer costs per 64-byte packet on this host, from the
/// GET_DESCRIPTOR rows: `x` is the bytes the device actually returned (libusb's
/// own `sz`), not the length asked for.
pub fn served_calibration(stats: &[RowStat]) -> Option<(f64, usize)> {
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for r in stats.iter().filter(|r| {
        r.shape == Shape::GetDesc
            && r.median_sz > 0
            && r.statuses.len() == 1
            && r.statuses[0].0 == LIBUSB_TRANSFER_COMPLETED
    }) {
        xs.push(r.median_sz as f64 / 64.0);
        ys.push(r.median_us as f64);
    }
    ls_slope(&xs, &ys).map(|s| (s, xs.len()))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Claim {
    Consumption,
    Deliberation,
    Knee,
    /// The request STOPS being answered above some length: one or more rows went
    /// silent, so no slope over the whole ladder is defined (T3-R/Lead: the stock
    /// cold pad's third branch).
    Wedge,
    Indeterminate,
    NoCalibration,
}

impl Claim {
    pub fn as_str(self) -> &'static str {
        match self {
            Claim::Consumption => "DATA CONSUMPTION (a) SUPPORTED",
            Claim::Deliberation => "DELIBERATION (b) SUPPORTED",
            Claim::Knee => "KNEE — flat, then rising",
            Claim::Wedge => "WEDGE — answered up to a length, silent above it (no slope is defined)",
            Claim::Indeterminate => "INDETERMINATE",
            Claim::NoCalibration => "NO CALIBRATION",
        }
    }
}

pub fn span(stats: &[RowStat], shape: Shape, length: u16) -> Option<u64> {
    stats.iter().find(|r| r.shape == shape && r.length == length).map(|r| r.median_us)
}

/// The classification, with its thresholds stated so a reader can disagree.
pub fn classify_shape(stats: &[RowStat], shape: Shape, noise_us: u64) -> (Claim, Vec<String>) {
    let mut notes = Vec::new();
    let cal = served_calibration(stats);
    let all = slope_for(stats, shape, 0, 65535);
    let low = slope_for(stats, shape, 0, 512);
    let high = slope_for(stats, shape, 1024, 65535);

    let silent_lengths: Vec<u16> = stats
        .iter()
        .filter(|r| r.shape == shape && wedged(r))
        .map(|r| r.length)
        .collect();
    // F2: a row whose repeats DISAGREED (some silent, some answered) is neither
    // `answered` nor `wedged`, so it was dropped from every fit without a word.
    // It must be reported, and it must block a clean claim when it is the longest
    // row tested.
    let mixed_lengths: Vec<u16> = stats
        .iter()
        .filter(|r| r.shape == shape && !answered(r) && !wedged(r))
        .map(|r| r.length)
        .collect();
    if !silent_lengths.is_empty() {
        notes.push(format!(
            "EXCLUDED from the fit (no device answer, only the host's deadline): lengths {silent_lengths:?}"
        ));
    }
    if !mixed_lengths.is_empty() {
        notes.push(format!(
            "UNUSABLE rows (repeats disagreed — some silent, some answered): lengths \
             {mixed_lengths:?}; no clean claim is made while the longest tested row is among them"
        ));
    }
    let longest_tested = stats
        .iter()
        .filter(|r| r.shape == shape)
        .map(|r| r.length)
        .max();
    let longest_unusable = longest_tested
        .map(|l| mixed_lengths.contains(&l))
        .unwrap_or(false);
    let cal_line = match cal {
        Some((c, n)) => format!("served calibration = {c:.1} us per 64-byte packet (n={n} GET_DESCRIPTOR points)"),
        None => "served calibration UNAVAILABLE (no completed GET_DESCRIPTOR row with >0 bytes)".to_string(),
    };
    notes.push(cal_line);
    notes.push(format!("noise floor = {noise_us} us (largest same-status repeat spread)"));
    match all {
        Some((s, n)) => notes.push(format!("{shape:?} slope over all lengths = {s:.1} us/packet (n={n})"),),
        None => notes.push(format!("{shape:?} slope over all lengths: not computable (fewer than 2 distinct lengths)")),
    }
    match (low, high) {
        (Some((l, _)), Some((h, _))) => notes.push(format!(
            "sub-ranges: <=512 B {l:.1} us/packet, >=1024 B {h:.1} us/packet"
        )),
        _ => {}
    }

    // A wedge dominates: if the device stops answering, the slope over the whole
    // ladder is a host artifact and must not be reported as consumption.
    if !silent_lengths.is_empty() {
        // The defining feature is that the request STOPS being answered. Report
        // that unless the ANSWERED rows themselves show a real consumption slope
        // (>= half the served calibration), in which case both facts matter.
        let answered_slope = all.map(|(sl, _)| sl).unwrap_or(0.0);
        // A slope needs an answered SPAN worth fitting. One packet (the stock cold
        // pad's 0 -> 64 us pair) cannot distinguish consumption from the cost of
        // serving the first packet, so a wedge dominates there.
        let mut answered_lens: Vec<u16> = stats
            .iter()
            .filter(|r| r.shape == shape && answered(r))
            .map(|r| r.length)
            .collect();
        answered_lens.sort_unstable();
        let span_packets = match (answered_lens.first(), answered_lens.last()) {
            (Some(a), Some(b)) => (*b - *a) / 64,
            _ => 0,
        };
        let consumption_below_wedge = match cal {
            Some((c, _)) => span_packets >= 2 && answered_slope >= 0.5 * c,
            None => false,
        };
        notes.push(format!(
            "answered rows only (n={} points, span {span_packets} packet(s)): slope {answered_slope:.1} us/packet",
            all.map(|(_, n)| n).unwrap_or(0)
        ));
        // F3: silence is not necessarily monotone — a reset between rows lets a
        // LONGER row answer after a shorter one went silent. Say which it is.
        let max_answered = answered_lens.last().copied();
        let max_silent = silent_lengths.iter().copied().max();
        let non_monotone = matches!((max_answered, max_silent), (Some(a), Some(s)) if a > s);
        // G2: no calibration means the threshold is UNAVAILABLE, not NaN.
        let threshold_text = match cal {
            Some((c, _)) => format!("{:.1} us/packet", 0.5 * c),
            None => "UNAVAILABLE (no served calibration)".to_string(),
        };
        // G1: derive the decision string FROM the claim, so the note and the claim
        // cannot contradict each other. The earlier form omitted `longest_unusable`
        // and printed "=> WEDGE" beside an INDETERMINATE claim.
        let claim = if non_monotone || consumption_below_wedge || longest_unusable {
            Claim::Indeterminate
        } else {
            Claim::Wedge
        };
        notes.push(format!(
            "decision: consumption below a wedge needs >= {threshold_text} over >= 2 answered \
             packets; this ladder: {answered_slope:.1} us/packet over {span_packets} packet(s), \
             non_monotone={non_monotone}, longest_row_unusable={longest_unusable} => {}",
            claim.as_str()
        ));
        if non_monotone {
            notes.push(format!(
                "NON-MONOTONE: silent at {silent_lengths:?} but answered at {max_answered:?} — a reset \
                 between rows can produce this; the wedge claim is not made"
            ));
        }
        return (claim, notes);
    }

    // F2: a clean consumption/deliberation claim is refused while the longest
    // tested row is unusable — otherwise the decisive row drops out silently and
    // the remaining answered rows still produce a confident claim.
    if longest_unusable {
        notes.push(
            "no clean claim: the longest tested row's repeats disagreed, so the shape's behaviour at \
             its decisive length is unknown"
                .to_string(),
        );
        return (Claim::Indeterminate, notes);
    }

    let claim = match (cal, all) {
        (Some((c, _)), Some((s, _))) => {
            let noise = noise_us as f64;
            // A genuine knee has a POSITIVE overall slope (the rising half drags
            // the least-squares fit up), so the piecewise test must come first or
            // every knee would be read as plain consumption.
            let knee = match (low, high) {
                (Some((l, _)), Some((h, _))) => l.abs() <= noise && h >= 0.5 * c,
                _ => false,
            };
            if knee {
                Claim::Knee
            } else if s >= 0.5 * c && s > 2.0 * noise {
                Claim::Consumption
            } else if s.abs() <= noise {
                Claim::Deliberation
            } else {
                Claim::Indeterminate
            }
        }
        _ => Claim::NoCalibration,
    };
    (claim, notes)
}

/// The required "so what" block: which explanation the data supports, and the
/// measurement that would refute it.
pub fn verdict_lines(stats: &[RowStat], noise_us: u64, shapes: &[Shape]) -> (Vec<String>, Claim) {
    let mut out = Vec::new();
    let mut worst = Claim::NoCalibration;
    for shape in shapes.iter().filter(|s| matches!(s, Shape::Pad | Shape::Overflow | Shape::Dnload)) {
        let (claim, notes) = classify_shape(stats, *shape, noise_us);
        out.push(format!("  {} ({}) — {}", shape.label(), shape.describe(), claim.as_str()));
        for n in &notes {
            out.push(format!("      {n}"));
        }
        // The exploit's own length, stated as a delta from the zero-length row.
        let exploit_len = match shape {
            Shape::Pad => Some(1280u16),
            Shape::Overflow => Some(48),
            Shape::Dnload => Some(2048),
            Shape::GetDesc => None,
        };
        if let Some(len) = exploit_len {
            let base_row = stats.iter().find(|r| r.shape == *shape && r.length == 0);
            let at_row = stats.iter().find(|r| r.shape == *shape && r.length == len);
            let usable = base_row.map(answered).unwrap_or(false) && at_row.map(answered).unwrap_or(false);
            if usable {
                if let (Some(base), Some(at)) = (span(stats, *shape, 0), span(stats, *shape, len)) {
                let packets = len as f64 / 64.0;
                let per = if packets > 0.0 { (at as f64 - base as f64) / packets } else { 0.0 };
                out.push(format!(
                    "      exploit length {len} B: median {at} us vs {base} us at wLength 0 \
                     ({per:.1} us per 64-byte packet over {packets:.2} packets)"
                ));
                }
            } else if let Some(at_row) = at_row {
                out.push(format!(
                    "      exploit length {len} B: NO DEVICE ANSWER ({} at {} us) — the host's deadline, \
                     so no per-packet number is reported here",
                    at_row
                        .statuses
                        .iter()
                        .map(|(st, n)| format!("{}x{}", status_name(*st), n))
                        .collect::<Vec<_>>()
                        .join(","),
                    at_row.median_us
                ));
            }
        }
        out.push(format!(
            "      FALSIFIED IF: a repeat of the {shape:?} row at its longest length lands within \
             the noise floor ({noise_us} us) of the wLength-0 row (that is explanation (b)), or if \
             the GET_DESCRIPTOR rows that return the SAME byte count at different asked lengths \
             show the same slope (then the slope is a host artifact, not the device)."
        ));
        if claim == Claim::Consumption {
            worst = Claim::Consumption;
        } else if worst != Claim::Consumption && claim == Claim::Knee {
            worst = Claim::Knee;
        } else if worst == Claim::NoCalibration {
            worst = claim;
        }
    }
    if out.is_empty() {
        out.push("  no malformed shape was in the ladder — nothing to conclude".to_string());
    }
    (out, worst)
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

pub fn status_name(s: i32) -> &'static str {
    match s {
        LIBUSB_TRANSFER_COMPLETED => "COMPLETED",
        LIBUSB_TRANSFER_ERROR => "ERROR",
        LIBUSB_TRANSFER_TIMED_OUT => "TIMED_OUT",
        LIBUSB_TRANSFER_CANCELLED => "CANCELLED",
        LIBUSB_TRANSFER_STALL => "STALL",
        LIBUSB_TRANSFER_NO_DEVICE => "NO_DEVICE",
        LIBUSB_TRANSFER_OVERFLOW => "OVERFLOW",
        _ => "?",
    }
}

/// The `--dry-run` text. Pure, so the exact ladder is reviewable offline and
/// testable without a device.
pub fn render_plan(a: &Args, index_reason: &str) -> String {
    let mut s = String::new();
    s.push_str("ep0cut --dry-run — NOTHING IS SENT, THE DEVICE IS NOT OPENED\n");
    if a.mode == Mode::Cut {
        s.push_str(&format!(
            "\nmode cut — GET_DESCRIPTOR(3,{}) wLength={} on {VID:04x}:{PID:04x}\n  index: {index_reason}\n",
            a.index.unwrap_or(a.fallback_index),
            a.cut_length
        ));
        s.push_str(&format!("  deadline ladder (us): {:?}\n", a.effective_deadlines()));
        s.push_str(&format!(
            "  reset-between: {} (a cancel wedges EP0 on this bootrom; the reset is the measured recovery)\n",
            a.reset_between
        ));
        s.push_str("\n  asked_us  -> cancel if not completed by then; status/sz reported as libusb gives them\n");
        return s;
    }

    if a.mode == Mode::AbortPad {
        let lengths = abort_lengths(a);
        s.push_str(&format!("\nmode abort-pad — pad AFTER an aborted DNLOAD, with its cold baseline, on {VID:04x}:{PID:04x}\n"));
        s.push_str(&format!("  index: {index_reason}\n"));
        s.push_str(&format!(
            "  per point: (1) pad at L COLD x{}{}; (2) RESET; (3) aborted DFU_DNLOAD 2048,\n\
             \x20             cancel after {} us; (4) pad at L again with NO reset between (3) and (4).\n\
             \x20             The decisive length is FIRST.\n",
            a.repeats.max(1),
            if a.repeats.max(1) > 1 { " (the only non-state-changing arm; its median/n/spread are printed and its spread widens the point's tolerance)" } else { "" },
            a.abort_us
        ));
        s.push_str(&format!("  lengths: {lengths:?}\n"));
        s.push_str(&format!(
            "  per-row deadline: {} ms (libusb's timeout; the pad is never cancelled by this tool)\n",
            a.sweep_deadline_ms
        ));
        s.push_str(&format!(
            "  reset-between: {} (between the arms, and after any wedged PAD row; the abort row is\n\
             \x20                expected to end CANCELLED — that is the cut, not a wedge)\n",
            a.reset_between
        ));
        s.push_str("  *** STATE-CHANGING: step (2)+(3) is checkm8's SETUP corruption step. ***\n");
        s.push_str("  SCOPE: this is the ISOLATED abort->pad. The real attempt-3 pad was preceded by two\n");
        s.push_str("         COMPLETED 2048-byte DNLOADs and two drains, and on a pwned device this\n");
        s.push_str("         measures the pwned EP0 path — attribute to the SecureROM only with a stock\n");
        s.push_str("         (power-cycled) control.\n");
        s.push_str("\n  the sequence, with the exact setup packets:\n");
        for (i, (_, len)) in abort_plan(a).iter().enumerate() {
            let dn = Shape::Dnload.setup(2048, a.index.unwrap_or(a.fallback_index));
            let pd = Shape::Pad.setup(*len, a.index.unwrap_or(a.fallback_index));
            s.push_str(&format!(
                "  point {i}: cold pad [{}] x{} -> dnload [{}] -> pad [{}] (no reset between the last two)\n",
                pd.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                a.repeats.max(1),
                dn.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                pd.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
            ));
        }
        s.push_str(&format!(
            "\n  READ IT LIKE THIS: the tool reports, per length, the cold median/n/spread, the abort's sz\n\
             \x20 and the after row, then classifies the point (same / CHANGED / WEDGED-after-cold-answered /\n\
             \x20 NO BASELINE) and fits the after-arm's slope. A point whose cold arm wedged or whose cold\n\
             \x20 repeats disagree is NO BASELINE — unclassifiable, never a silent 'same'. `CHANGED` proves\n\
             \x20 the pad is STATE-DEPENDENT, not that it consumed data — the cancel also leaves an\n\
             \x20 EP0-recovery cost. Only a rising after-slope at the served-transfer per-packet cost\n\
             \x20 supports consumption. If NOTHING was classifiable the verdict says so and the tool exits 1.\n\
             \x20 Noise floor {} us (archived cold rows' 171-187 us range) or the point's own spread.\n",
            STATE_EFFECT_FLOOR_US
        ));
        return s;
    }

    s.push_str(&format!("\nmode sweep — wLength x latency on {VID:04x}:{PID:04x}\n"));
    s.push_str(&format!("  index: {index_reason}\n"));
    s.push_str(&format!("  repeats per point: {} (round-robin over every shape x length)\n", a.repeats));
    s.push_str(&format!(
        "  per-row deadline: {} ms (libusb's own timeout; THIS TOOL NEVER CANCELS). A row that \
         exceeds it is TIMED_OUT; the ladder stops{}\n",
        a.sweep_deadline_ms,
        if a.continue_after_timeout { " (--continue-after-timeout: it does not)" } else { "" }
    ));
    s.push_str(&format!(
        "  reset-between: {} (a TIMED_OUT row is libusb cancelling internally — the same wedge risk)\n",
        a.reset_between
    ));
    s.push_str(&format!("  OUT data pattern: {:?} (zeros = gaster's own memset)\n", a.pattern));
    s.push_str("  shapes:\n");
    for sh in &a.shapes {
        let warn = if sh.is_state_changing() { "   *** STATE-CHANGING ***" } else { "" };
        s.push_str(&format!("    {:<9} {}{warn}\n", sh.label(), sh.describe()));
    }
    s.push_str("\n  the exact ladder, in order (setup packet bytes as they go on the wire):\n");
    s.push_str(&format!("  {:>5}  {:<9} {:>7}  setup packet (8 bytes)\n", "round", "shape", "wLength"));
    for st in plan(a) {
        let setup = st.shape.setup(st.length, a.index.unwrap_or(a.fallback_index));
        let hex = setup.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        s.push_str(&format!("  {:>5}  {:<9} {:>7}  {hex}\n", st.round, st.shape.label(), st.length));
    }
    let out_rows = plan(a).iter().filter(|s| !s.shape.is_in()).count();
    s.push_str(&format!(
        "\n  {} requests total: {out_rows} OUT (data stage filled with {:?}), {} IN (GET_DESCRIPTOR control)\n",
        plan(a).len(),
        a.pattern,
        plan(a).len() - out_rows
    ));
    s.push_str(
        "\n  CONTROLS this ladder will check at run time:\n\
         \x20   C1  at least one GET_DESCRIPTOR row must COMPLETE with >0 bytes (the device answers it)\n\
         \x20   C2  GET_DESCRIPTOR rows that return the SAME byte count at DIFFERENT asked lengths must be\n\
         \x20       flat within the noise floor; a slope there is a HOST artifact and invalidates any slope\n\
         \x20   C3  the wLength-0 rows are the baseline every per-packet number is measured from\n",
    );
    s.push_str(
        "\n  READ IT LIKE THIS: consumption (a) predicts a rise of ~the GET_DESCRIPTOR calibration\n\
         \x20 per 64-byte packet; deliberation (b) predicts flat. The run prints both numbers and\n\
         \x20 the falsification. A slope through 3 points is not a measurement of the ROM.\n",
    );
    s
}

/// The per-point table, as text. Pure, and returned rather than printed so the
/// caller can route it to stdout or stderr — under `--json` the machine-readable
/// document must be the ONLY thing on stdout.
pub fn stats_lines(stats: &[RowStat]) -> String {
    let mut s = String::new();
    s.push_str("\n  ---- per point (median of N repeats) ----\n");
    s.push_str(&format!(
        "  {:<9} {:>7} {:>2}  {:>10} {:>9} {:>9} {:>7}  {:>5}  statuses\n",
        "shape", "wLength", "N", "median_us", "min_us", "max_us", "spread", "sz"
    ));
    for r in stats {
        let statuses = r
            .statuses
            .iter()
            .map(|(s, n)| format!("{}x{}", status_name(*s), n))
            .collect::<Vec<_>>()
            .join(",");
        s.push_str(&format!(
            "  {:<9} {:>7} {:>2}  {:>10} {:>9} {:>9} {:>7}  {:>5}  {}\n",
            r.shape.label(),
            r.length,
            r.n,
            r.median_us,
            r.min_us,
            r.max_us,
            r.max_us.saturating_sub(r.min_us),
            r.median_sz,
            statuses
        ));
    }
    s
}

/// C1/C2/C3, printed as numbers a reader can check.
pub fn control_lines(stats: &[RowStat], noise_us: u64) -> (Vec<String>, bool) {
    let mut out = Vec::new();
    let mut ok = true;

    let answered: Vec<&RowStat> = stats
        .iter()
        .filter(|r| {
            r.shape == Shape::GetDesc
                && r.statuses.len() == 1
                && r.statuses[0].0 == LIBUSB_TRANSFER_COMPLETED
                && r.median_sz > 0
        })
        .collect();
    if answered.is_empty() {
        ok = false;
        out.push("  C1 FAILED — no GET_DESCRIPTOR row COMPLETED with >0 bytes: the device is not answering, so every other row is meaningless".to_string());
    } else {
        let best = answered.iter().map(|r| r.median_sz).max().unwrap_or(0);
        out.push(format!(
            "  C1 OK — GET_DESCRIPTOR answered with up to {best} bytes in {} points",
            answered.len()
        ));
        // C2: the rows that returned the full descriptor, at different asked lengths.
        let full: Vec<&RowStat> = answered.iter().copied().filter(|r| r.median_sz == best).collect();
        if full.len() >= 2 {
            let lo = full.iter().map(|r| r.median_us).min().unwrap_or(0);
            let hi = full.iter().map(|r| r.median_us).max().unwrap_or(0);
            let asked: Vec<u16> = full.iter().map(|r| r.length).collect();
            let flat = hi.saturating_sub(lo) <= 2 * noise_us;
            if !flat {
                ok = false;
            }
            out.push(format!(
                "  C2 {} — the same {best}-byte answer at asked lengths {asked:?} took {lo}..{hi} us \
                 (spread {} us, 2x noise floor = {} us): {}",
                if flat { "OK" } else { "FAILED (host artifact)" },
                hi.saturating_sub(lo),
                2 * noise_us,
                if flat {
                    "flat, so a slope elsewhere is not the instrument drifting"
                } else {
                    "a length-tracking latency with the SAME returned byte count — any slope in the \
                     malformed shapes is a HOST artifact"
                }
            ));
        } else {
            out.push(format!(
                "  C2 NOT EVALUABLE with this ladder — only {} asked length(s) returned the full \
                 {best}-byte answer. The control needs TWO OR MORE asked lengths that return the \
                 whole descriptor (a short ladder like 0,64,1280 has one: the device returns \
                 min(wLength, {best}) by definition). This is expected for a short ladder, not a \
                 failure; add lengths above {best} B for a drift check.",
                full.len()
            ));
        }
    }

    let base: Vec<&RowStat> = stats.iter().filter(|r| r.length == 0).collect();
    if base.is_empty() {
        out.push("  C3 MISSING — no wLength-0 row: there is no baseline for a per-packet number".to_string());
    } else {
        let txt = base
            .iter()
            .map(|r| format!("{}={} us ({})", r.shape.label(), r.median_us, r.statuses.iter().map(|(s, n)| format!("{}x{}", status_name(*s), n)).collect::<Vec<_>>().join(",")))
            .collect::<Vec<_>>()
            .join(", ");
        out.push(format!("  C3 baseline (wLength 0): {txt}"));
    }
    (out, ok)
}

/// Human output: stdout normally, stderr under `--json` so the machine-readable
/// document is the ONLY thing on stdout.
macro_rules! out {
    ($a:expr, $($t:tt)*) => {
        if $a.json { eprintln!($($t)*) } else { println!($($t)*) }
    };
}

// ---------------------------------------------------------------------------
// The libusb shell (never reached by --dry-run)
// ---------------------------------------------------------------------------

/// Was the transfer refused by the poisoned-handle path? `submitted_rc` is
/// libusb's own return from `libusb_submit_transfer`.
pub struct RowOutcome {
    pub sample: Option<Sample>,
    pub submitted_rc: i32,
    /// libusb never said this transfer was complete: it may still write through
    /// the buffer, so the caller must STOP and leak rather than free it.
    pub unreaped: bool,
}

#[derive(Clone, Copy)]
pub enum RowMode {
    /// µs deadline, then `libusb_cancel_transfer` (mode `cut` only).
    CutAt { at_us: u64 },
    /// libusb's own timeout; this tool never calls cancel (mode `sweep`).
    Wait { timeout_ms: u32 },
}

unsafe fn run_row(
    ctx: *mut sys::libusb_context,
    handle: *mut sys::libusb_device_handle,
    shape: Shape,
    length: u16,
    index: u8,
    pattern: Pattern,
    mode: RowMode,
) -> RowOutcome {
    const TV_ZERO: libc::timeval = libc::timeval { tv_sec: 0, tv_usec: 0 };

    let data_len = length as usize;
    let mut buf = vec![0u8; LIBUSB_CONTROL_SETUP_SIZE + data_len];
    buf[..8].copy_from_slice(&shape.setup(length, index));
    if !shape.is_in() && data_len > 0 {
        fill_pattern(&mut buf[8..], pattern);
    }

    let xfer = sys::libusb_alloc_transfer(0);
    (*xfer).dev_handle = handle;
    (*xfer).flags = 0;
    (*xfer).endpoint = 0;
    (*xfer).transfer_type = LIBUSB_TRANSFER_TYPE_CONTROL;
    (*xfer).timeout = match mode {
        RowMode::CutAt { .. } => 0,
        RowMode::Wait { timeout_ms } => timeout_ms,
    };
    // Not seeded to 0: 0 is LIBUSB_TRANSFER_COMPLETED. libusb fills both in
    // before the callback, but a stale read must not look like success.
    (*xfer).status = -1;
    (*xfer).length = (LIBUSB_CONTROL_SETUP_SIZE + data_len) as i32;
    (*xfer).actual_length = 0;
    // libusb1-sys declares this as a plain `extern "system" fn`, not an Option:
    // a no-op callback is not available, and this is the completion signal.
    (*xfer).callback = on_complete;
    (*xfer).user_data = std::ptr::null_mut();
    (*xfer).buffer = buf.as_mut_ptr();

    COMPLETED.store(false, Ordering::SeqCst);
    let start = Instant::now();
    let rc = sys::libusb_submit_transfer(xfer);
    if rc != LIBUSB_SUCCESS {
        sys::libusb_free_transfer(xfer);
        return RowOutcome { sample: None, submitted_rc: rc, unreaped: false };
    }

    match mode {
        RowMode::CutAt { at_us } => {
            while start.elapsed() < Duration::from_micros(at_us) {
                let mut done: i32 = 0;
                sys::libusb_handle_events_timeout_completed(ctx, &TV_ZERO, &mut done);
                if COMPLETED.load(Ordering::SeqCst) {
                    break;
                }
            }
            if !COMPLETED.load(Ordering::SeqCst) {
                // The cancel is the POINT of this mode: it is what makes a
                // partial `actual_length` observable. It is also what wedges EP0.
                let _ = sys::libusb_cancel_transfer(xfer);
                let guard = Instant::now();
                while !COMPLETED.load(Ordering::SeqCst) && guard.elapsed() < Duration::from_secs(2) {
                    let mut done: i32 = 0;
                    sys::libusb_handle_events_timeout_completed(ctx, &TV_ZERO, &mut done);
                }
            }
        }
        RowMode::Wait { timeout_ms } => {
            let hard = Duration::from_millis(timeout_ms as u64 + 2_000);
            while start.elapsed() < hard {
                let mut done: i32 = 0;
                sys::libusb_handle_events_timeout_completed(ctx, &TV_ZERO, &mut done);
                if COMPLETED.load(Ordering::SeqCst) {
                    break;
                }
            }
        }
    }

    let elapsed_us = start.elapsed().as_micros() as u64;
    if !COMPLETED.load(Ordering::SeqCst) {
        // libusb still owns the transfer and the buffer; leaking both is the only
        // sound option. The caller stops the ladder.
        return RowOutcome { sample: None, submitted_rc: rc, unreaped: true };
    }
    let sample = Sample { elapsed_us, status: (*xfer).status, sz: (*xfer).actual_length };
    sys::libusb_free_transfer(xfer);
    RowOutcome { sample: Some(sample), submitted_rc: rc, unreaped: false }
}

/// The descriptor's declared `iSerialNumber` (cached host-side — this is not a
/// wire read), else the fallback. Returns the index and why.
unsafe fn resolve_index(
    handle: *mut sys::libusb_device_handle,
    explicit: Option<u8>,
    fallback: u8,
) -> (u8, String) {
    if let Some(i) = explicit {
        return (i, format!("--index {i} (explicit)"));
    }
    let dev = sys::libusb_get_device(handle);
    if !dev.is_null() {
        let mut d: sys::libusb_device_descriptor = std::mem::zeroed();
        if sys::libusb_get_device_descriptor(dev, &mut d) == LIBUSB_SUCCESS && d.iSerialNumber != 0 {
            return (
                d.iSerialNumber,
                format!(
                    "declared iSerialNumber {} from the host-cached device descriptor (a pwn moves \
                     the marker to a different index; a hardcoded index is how a tool reports the \
                     wrong string)",
                    d.iSerialNumber
                ),
            );
        }
    }
    (fallback, format!("fallback {fallback}: the declared iSerialNumber was 0 or unreadable"))
}

/// The `cut` mode's two controls. Pure, so they are testable without a device.
///
/// **C1 is "a cancel happened", NOT "a cancel moved nothing".** MEASURED
/// 2026-10-03 (`a9pwn-traces/linux/e1-ep0cut-ladder.txt:5`): a nominal 0 us
/// deadline achieved its cut at 134 us and reported `CANCELLED, 64 bytes` —
/// one whole packet had crossed before the cancel landed. An earlier revision
/// required `sz == 0` here and therefore declared the ladder that CONTAINED THE
/// ANSWER invalid. The rule this project keeps re-learning: a control must be
/// able to fail, but it must fail for the right reason.
///
/// **C2 is "the device answers when it is not cut", NOT "it returns wLength
/// bytes".** A string descriptor is legitimately shorter than the wLength asked
/// for: 198 of 255 is the complete, correct answer (`e1-ep0cut-ladder.txt:17`).
pub fn cut_controls(samples: &[Sample]) -> (bool, bool) {
    let zero_ok = samples
        .first()
        .map(|s| s.status == LIBUSB_TRANSFER_CANCELLED)
        .unwrap_or(false);
    let complete_ok = samples
        .last()
        .map(|s| s.status == LIBUSB_TRANSFER_COMPLETED && s.sz > 0)
        .unwrap_or(false);
    (zero_ok, complete_ok)
}

/// The first cancelled row that reported bytes: the answer to the `sz` question.
pub fn first_partial(samples: &[Sample]) -> Option<Sample> {
    samples
        .iter()
        .find(|s| s.status == LIBUSB_TRANSFER_CANCELLED && s.sz > 0)
        .copied()
}

// ---------------------------------------------------------------------------
// abort-pad: the exploit's own order (pure parts)
// ---------------------------------------------------------------------------

/// The exploit's pad is 1280 bytes; 0/64 are the cold-flat lengths the task-9
/// sweep located, and 128/256 straddle its knee.
/// ORDER MATTERS: the exploit's own pad length is FIRST, because the loop stops
/// at the first row that never answers and the ladder must not lose its
/// decisive point to a wedge at a shorter length (T3-R B3).
pub const ABORT_PAD_DEFAULT_LENGTHS: [u16; 5] = [1280, 256, 128, 64, 0];

pub fn abort_lengths(a: &Args) -> Vec<u16> {
    if a.lengths_explicit {
        a.lengths.clone()
    } else {
        ABORT_PAD_DEFAULT_LENGTHS.to_vec()
    }
}

/// One round per length, deliberately. Each point performs the exploit's own
/// corruption step, and the comparison this mode makes is *within* a point
/// (cold vs after-abort at the same length), so repetitions buy less here than
/// they cost in risk. Re-run the whole mode for repeatability.
pub fn abort_plan(a: &Args) -> Vec<(u32, u16)> {
    abort_lengths(a).into_iter().enumerate().map(|(i, l)| (i as u32, l)).collect()
}

#[derive(Clone, Copy, Debug)]
pub struct AbortPoint {
    pub length: u16,
    /// The pad with NO preceding abort, taken FIRST in the point so it really is
    /// cold (T3-R A1: it used to be taken last, after both interventions it is
    /// supposed to be the baseline for). Median of `cold_n` repeats.
    pub cold: Sample,
    pub cold_n: usize,
    pub cold_spread_us: u64,
    /// The cold repeats disagreed on terminal status, so there is no single
    /// baseline at this length (T3-R R5).
    pub cold_mixed: bool,
    /// The aborted 2048-byte DNLOAD itself.
    pub abort: Sample,
    /// The pad immediately after the abort, with no reset in between.
    pub after: Sample,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StateEffect {
    /// The preceding abort made no measurable difference at this length.
    Same,
    /// Same request, different answer: the state matters.
    Changed,
    /// No usable baseline: the cold arm wedged, or its repeats disagreed. The
    /// point cannot be classified at all — and in particular must NOT be read as
    /// "same as cold" (T3-R R2/R5).
    NoBaseline,
    /// Cold answered, after silent: the abort changed the outcome.
    Wedged,
}

impl StateEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            StateEffect::Same => "same as cold",
            StateEffect::Changed => "CHANGED by the preceding abort",
            StateEffect::NoBaseline => "NO BASELINE (cold arm wedged or mixed) — unclassifiable",
            StateEffect::Wedged => "WEDGED after the abort (cold answered)",
        }
    }
}

/// A floor so a tiny difference is not called a state effect. 50 us is
/// justified from the ARCHIVED CROSS-ROW range, not from a within-point spread:
/// the five cold pad rows of the task-9 sweep span 171-187 us, i.e. +/-16 us
/// (T3-R B1 — an earlier comment cited a "spread of 0" that was an artifact of
/// N=1 per point).
pub const STATE_EFFECT_FLOOR_US: u64 = 50;

/// Collapse the cold repeats into ONE baseline sample without letting repeat
/// order decide the classification (T3-R R5).
///
/// Latency is the median; status and `sz` come from the MAJORITY status among the
/// repeats, and `mixed` is set when the repeats do not agree — in which case the
/// point has no baseline and must be reported as unclassifiable rather than
/// silently taking the first row's state.
pub fn aggregate_cold(colds: &[Sample]) -> (Sample, u64, bool) {
    assert!(!colds.is_empty());
    let mut lats: Vec<u64> = colds.iter().map(|s| s.elapsed_us).collect();
    let med = median(&mut lats);
    let spread = lats.last().copied().unwrap_or(0).saturating_sub(*lats.first().unwrap_or(&0));
    let mut counts: Vec<(i32, usize)> = Vec::new();
    for c in colds {
        match counts.iter_mut().find(|(st, _)| *st == c.status) {
            Some(e) => e.1 += 1,
            None => counts.push((c.status, 1)),
        }
    }
    let (status, _count) = counts
        .iter()
        .copied()
        .max_by_key(|(_, n)| *n)
        .unwrap_or((colds[0].status, 1));
    let mut szs: Vec<i64> = colds
        .iter()
        .filter(|c| c.status == status)
        .map(|c| c.sz as i64)
        .collect();
    szs.sort_unstable();
    // R9: `sz` is what `state_effect` compares for equality, so repeats that
    // agree on status but moved different byte counts are ALSO not a baseline.
    // R15: use the same statistic as the latency median (average the middle two
    // on an even count) so the two halves of the aggregate agree.
    let sz_mixed = szs.windows(2).any(|w| w[0] != w[1]);
    let sz = if szs.is_empty() {
        0
    } else if szs.len() % 2 == 1 {
        szs[szs.len() / 2] as i32
    } else {
        ((szs[szs.len() / 2 - 1] + szs[szs.len() / 2]) / 2) as i32
    };
    let mixed = counts.len() > 1 || sz_mixed;
    (Sample { elapsed_us: med, status, sz }, spread, mixed)
}

fn silent(s: &Sample) -> bool {
    matches!(
        s.status,
        LIBUSB_TRANSFER_TIMED_OUT | LIBUSB_TRANSFER_CANCELLED | LIBUSB_TRANSFER_NO_DEVICE
    )
}

pub fn state_effect(p: &AbortPoint, noise_us: u64) -> StateEffect {
    // A reset is inserted between the cold arm and the treatment arm (T3-R R3),
    // and a wedged/mixed cold arm cannot serve as the comparison basis at all.
    if p.cold_mixed || silent(&p.cold) {
        return StateEffect::NoBaseline;
    }
    if silent(&p.after) {
        return StateEffect::Wedged;
    }
    // The tolerance uses THIS point's own repeat spread, not only the constant
    // (T3-R R4): a point whose cold repeats scattered by 200 us cannot call a
    // 60 us difference a state effect.
    let tol = noise_us.max(STATE_EFFECT_FLOOR_US).max(p.cold_spread_us);
    if p.after.status == p.cold.status
        && p.after.sz == p.cold.sz
        && p.after.elapsed_us.abs_diff(p.cold.elapsed_us) <= tol
    {
        StateEffect::Same
    } else {
        StateEffect::Changed
    }
}

/// The mode's verdict: did the preceding aborted DNLOAD change how the pad is
/// handled, and what does that say about the exploit's own pad?
pub fn abort_pad_verdict(points: &[AbortPoint], noise_us: u64, abort_us: u64) -> (Vec<String>, String) {
    let mut out = Vec::new();
    let mut changed = Vec::new();
    let mut wedged = Vec::new();
    let mut no_baseline = Vec::new();
    for p in points {
        match state_effect(p, noise_us) {
            StateEffect::Same => {}
            StateEffect::Changed => changed.push(p.length),
            StateEffect::Wedged => wedged.push(p.length),
            StateEffect::NoBaseline => no_baseline.push(p.length),
        }
        out.push(format!(
            "  L={:<5} cold: {:<10} sz={:<4} {:>7}us (n={} spread={}us) | abort: {:<10} sz={:<4} {:>7}us | after: {:<10} sz={:<4} {:>7}us  -> {}",
            p.length,
            if p.cold_mixed { "MIXED".to_string() } else { status_name(p.cold.status).to_string() },
            p.cold.sz,
            p.cold.elapsed_us,
            p.cold_n,
            p.cold_spread_us,
            status_name(p.abort.status),
            p.abort.sz,
            p.abort.elapsed_us,
            status_name(p.after.status),
            p.after.sz,
            p.after.elapsed_us,
            state_effect(p, noise_us).as_str()
        ));
    }
    if let Some(p) = points.iter().find(|p| p.length == 1280) {
        out.push(format!(
            "  exploit length 1280: abort at {}us reported sz={} of 2048 (the reference's `sz`), then the pad \
             answered {} with sz={} in {}us (cold: {} / sz={} / {}us)",
            abort_us,
            p.abort.sz,
            status_name(p.after.status),
            p.after.sz,
            p.after.elapsed_us,
            if p.cold_mixed { "MIXED".to_string() } else { status_name(p.cold.status).to_string() },
            p.cold.sz,
            p.cold.elapsed_us
        ));
    }
    // The mode's own observable is an EQUALITY, which cannot separate "the pad
    // consumed its data" from "the pad paid the EP0-wedge recovery the cancel
    // creates" (T3-R A2). So report the after-arm's slope too, in the tool's own
    // latency terms, and say what each outcome can and cannot support.
    let mut xs = Vec::new();
    let mut ys = Vec::new();
    for p in points.iter().filter(|p| !silent(&p.after)) {
        xs.push(p.length as f64 / 64.0);
        ys.push(p.after.elapsed_us as f64);
    }
    match ls_slope(&xs, &ys) {
        Some(slope) => out.push(format!(
            "  after-abort slope: {slope:.1} us per 64-byte packet over lengths {:?} — rising is \
             consumption-CONSISTENT, flat (within {noise_us} us) is refusal-consistent",
            points.iter().map(|p| p.length).collect::<Vec<_>>()
        )),
        None => out.push("  after-abort slope: not computable (fewer than two lengths answered)".to_string()),
    }
    if !no_baseline.is_empty() {
        out.push(format!(
            "  lengths with NO USABLE BASELINE ({no_baseline:?}): the cold arm wedged or its repeats \
             disagreed, so these points are UNCLASSIFIABLE — not evidence of 'no change'"
        ));
    }

    // R1: an empty or all-unclassifiable result must never read as a completed
    // negative. LINUX-HANDOFF §8 rule 1 is exactly this failure.
    let verdict: String = if points.is_empty() {
        "NO POINTS MEASURED — the ladder stopped in its control arm; nothing was tested, so there is \
         no result here (this is NOT a negative finding)"
            .to_string()
    } else if changed.is_empty() && wedged.is_empty() && no_baseline.len() == points.len() {
        "NO CLASSIFIABLE POINT — every tested length lacked a usable cold baseline; nothing can be \
         said about whether the abort changes the pad (this is NOT a negative finding)"
            .to_string()
    } else if !wedged.is_empty() && changed.is_empty() {
        "cold answered but the pad WEDGES after the abort at some lengths — the abort changed the \
         outcome there; that is state-dependence, NOT evidence of consumption"
            .to_string()
    } else if changed.is_empty() && !no_baseline.is_empty() {
        format!(
            "no CHANGED point among the classifiable lengths, but {no_baseline:?} were unclassifiable \
             — read those before drawing a negative"
        )
    } else if changed.is_empty() {
        "the preceding aborted DNLOAD does NOT change the pad's handling at any CLASSIFIABLE tested \
         length: the 736/889 us post-abort STALL is NOT a property of the abort"
            .to_string()
    } else {
        "the preceding aborted DNLOAD CHANGES the pad's handling (see the CHANGED rows): the pad's \
         behaviour is state-dependent, and a cold-pad ladder cannot describe the exploit's pad"
            .to_string()
    };
    out.push(format!("  VERDICT: {verdict}"));
    out.push(format!(
        "  WHAT THIS CANNOT SHOW: `Changed` proves state-dependence, not consumption — the abort's cancel \
         also leaves an EP0-recovery cost that a post-abort pad can absorb. Use the after-abort slope \
         above plus the cold band (171-187 us archived) before writing the word 'consumption'."
    ));
    out.push(format!(
        "  FALSIFIED IF: the CHANGED rows are explained by within-run drift (the cold arm is repeated, so \
         its spread is printed per point) or by the abort rows' own sz differing across lengths."
    ));
    (out, verdict)
}

// ---------------------------------------------------------------------------
// JSON output (hand-rolled: the crate has no dependencies beyond libusb1-sys
// and libc on purpose, and `--json` is advertised in the help text)
// ---------------------------------------------------------------------------

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_strings(items: &[String]) -> String {
    let body = items
        .iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{body}]")
}

/// One machine-readable document for either mode. `stats` is `None` when the
/// ladder stopped early, which is recorded as `"incomplete":true` rather than
/// being smoothed over.
pub fn json_document(
    mode: &str,
    rows: &[(u32, Shape, u16, Sample)],
    stats: Option<&[RowStat]>,
    noise_us: Option<u64>,
    controls: &[String],
    verdict: &str,
    incomplete: bool,
) -> String {
    let row_lines = rows
        .iter()
        .map(|(round, shape, length, s)| {
            format!(
                "{{\"round\":{round},\"shape\":\"{}\",\"length\":{length},\"status\":\"{}\",\"sz\":{},\"elapsed_us\":{}}}",
                shape.label(),
                status_name(s.status),
                s.sz,
                s.elapsed_us
            )
        })
        .collect::<Vec<_>>()
        .join(",\n  ");
    let point_lines = stats
        .map(|st| {
            st.iter()
                .map(|r| {
                    let statuses = r
                        .statuses
                        .iter()
                        .map(|(s, n)| format!("{{\"status\":\"{}\",\"n\":{n}}}", status_name(*s)))
                        .collect::<Vec<_>>()
                        .join(",");
                    format!(
                        "{{\"shape\":\"{}\",\"length\":{},\"n\":{},\"median_us\":{},\"min_us\":{},\"max_us\":{},\"median_sz\":{},\"statuses\":[{statuses}]}}",
                        r.shape.label(),
                        r.length,
                        r.n,
                        r.median_us,
                        r.min_us,
                        r.max_us,
                        r.median_sz
                    )
                })
                .collect::<Vec<_>>()
                .join(",\n    ")
        })
        .unwrap_or_default();
    format!(
        "{{\"tool\":\"ep0cut\",\"mode\":\"{mode}\",\"incomplete\":{incomplete},\n  \"rows\":[\n  {row_lines}\n  ],\n  \"points\":[\n    {point_lines}\n  ],\n  \"noise_us\":{},\n  \"controls\":{},\n  \"verdict\":\"{}\"}}",
        noise_us.map(|n| n.to_string()).unwrap_or_else(|| "null".to_string()),
        json_strings(controls),
        json_escape(verdict)
    )
}

fn exit_code(n: u8) -> std::process::ExitCode {
    std::process::ExitCode::from(n)
}

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let a = match parse_args_from(&argv) {
        Ok(a) => a,
        Err(msg) => {
            // `--help` arrives here as its own text; anything else is an error.
            if msg.starts_with("ep0cut —") {
                println!("{msg}");
                return exit_code(0);
            }
            eprintln!("ep0cut: {msg}");
            eprintln!();
            eprintln!("{}", usage_text());
            return exit_code(2);
        }
    };

    if a.dry_run {
        let reason = match a.index {
            Some(i) => format!("--index {i} (explicit)"),
            None => format!(
                "the DECLARED iSerialNumber from the device descriptor, else fallback {}",
                a.fallback_index
            ),
        };
        print!("{}", render_plan(&a, &reason));
        return exit_code(0);
    }

    unsafe {
        let mut ctx: *mut sys::libusb_context = std::ptr::null_mut();
        if sys::libusb_init(&mut ctx) != LIBUSB_SUCCESS {
            eprintln!("ep0cut: libusb_init failed");
            return exit_code(2);
        }
        let handle = sys::libusb_open_device_with_vid_pid(ctx, VID, PID);
        if handle.is_null() {
            eprintln!(
                "ep0cut: could not open {VID:04x}:{PID:04x}. Is the device in DFU mode, and do you \
                 have permission on /dev/bus/usb (see /etc/udev/rules.d/99-apple-dfu.rules)?"
            );
            sys::libusb_exit(ctx);
            return exit_code(2);
        }
        // libusb skips ResetDevice unless an interface is claimed; claim it so the
        // reset recovery is real, and so this exercises the same open shape a9pwn
        // uses.
        let _ = sys::libusb_claim_interface(handle, 0);

        let (index, index_reason) = resolve_index(handle, a.index, a.fallback_index);
        let code = match a.mode {
            Mode::Cut => run_cut(ctx, handle, &a, index, &index_reason),
            Mode::Sweep => run_sweep(ctx, handle, &a, index, &index_reason),
            Mode::AbortPad => run_abort_pad(ctx, handle, &a, index, &index_reason),
        };
        sys::libusb_close(handle);
        sys::libusb_exit(ctx);
        code
    }
}

unsafe fn run_cut(
    ctx: *mut sys::libusb_context,
    handle: *mut sys::libusb_device_handle,
    a: &Args,
    index: u8,
    index_reason: &str,
) -> std::process::ExitCode {
    let deadlines = a.effective_deadlines();
    out!(a, "ep0cut --mode cut — GET_DESCRIPTOR(3,{index}) wLength={} on {VID:04x}:{PID:04x}", a.cut_length);
    out!(a, "  index: {index_reason}");
    out!(a, "  ladder (us): {deadlines:?}   reset-between: {}", a.reset_between);
    out!(a, "  THIS MODE CANCELS BY DESIGN (that is what exposes a partial `actual_length`); a");
    out!(a, "  cancel wedges EP0 on this bootrom. Use --mode sweep for a ladder that never cancels.");
    out!(a, );
    out!(a, "  {:>8}  {:>9}  {:<10} {:>9}  head", "asked", "achieved", "status", "libusb sz");

    let mut rows: Vec<Sample> = Vec::new();
    let mut json_rows: Vec<(u32, Shape, u16, Sample)> = Vec::new();
    for (i, d) in deadlines.iter().enumerate() {
        let out = run_row(ctx, handle, Shape::GetDesc, a.cut_length, index, a.pattern, RowMode::CutAt { at_us: *d });
        if out.unreaped {
            out!(a, "  {:>6}us  — libusb never reaped the transfer; STOPPING (the handle is no longer trustworthy)", d);
            if a.json {
                println!("{}", json_document("cut", &json_rows, None, None, &[], "INCOMPLETE: transfer never reaped", true));
            }
            return exit_code(1);
        }
        let s = match out.sample {
            Some(s) => s,
            None => {
                out!(a, "  {:>6}us  — submit refused, libusb rc={}", d, out.submitted_rc);
                if a.json {
                    println!("{}", json_document("cut", &json_rows, None, None, &[], "INCOMPLETE: submit refused", true));
                }
                return exit_code(1);
            }
        };
        out!(a, 
            "  {:>6}us  {:>7}us  {:<10} {:>6}/{}",
            d,
            s.elapsed_us,
            status_name(s.status),
            s.sz,
            a.cut_length
        );
        let cancelled = s.status == LIBUSB_TRANSFER_CANCELLED;
        rows.push(s);
        json_rows.push((i as u32, Shape::GetDesc, a.cut_length, s));
        if cancelled && a.reset_between && i + 1 < deadlines.len() {
            let rc = sys::libusb_reset_device(handle);
            out!(a, "            (port reset after the cancel: rc={rc}; the measured recovery for the EP0 wedge)");
        }
    }

    let first = &rows[0];
    let last = rows.last().unwrap();
    let (zero_ok, complete_ok) = cut_controls(&rows);
    out!(a, );
    out!(a, 
        "  control 1 (deadline {}us): {} — {}",
        deadlines[0],
        if zero_ok { "OK" } else { "FAILED" },
        if zero_ok {
            format!(
                "a cancel really was produced ({}; a partial count here is FINDING, not a control \
                 failure — a 0 us deadline still achieves its cut after the pump slice)",
                if first.sz > 0 {
                    format!("CANCELLED with {} bytes already crossed", first.sz)
                } else {
                    "CANCELLED with 0 bytes".to_string()
                }
            )
        } else {
            format!(
                "expected CANCELLED, got {}/{} — the cancelled state is NOT being produced, so no \
                 other row means anything",
                status_name(first.status),
                first.sz
            )
        }
    );
    out!(a, 
        "  control 2 (deadline {}us): {} — {}",
        deadlines.last().unwrap(),
        if complete_ok { "OK" } else { "FAILED" },
        if complete_ok {
            format!(
                "the device answers this request when it is not cut ({} bytes of the {} asked — a \
                 string descriptor is legitimately shorter)",
                last.sz, a.cut_length
            )
        } else {
            format!(
                "expected COMPLETED with >0 bytes, got {}/{} — the device is NOT answering, so every \
                 other row is meaningless",
                status_name(last.status),
                last.sz
            )
        }
    );
    if !zero_ok || !complete_ok {
        out!(a, );
        out!(a, "  VERDICT  INVALID LADDER — fix the controls before reading anything below.");
        if a.json {
            println!("{}", json_document("cut", &json_rows, None, None, &[], "INVALID LADDER", true));
        }
        return exit_code(1);
    }
    out!(a, );
    let verdict = match first_partial(&rows) {
        Some(r) => {
            out!(a, 
                "  VERDICT  PARTIALS SURVIVE CANCELLATION: a control transfer cut after {}us reported \
                 libusb sz={} of {}. On this host `sz` is a real, packet-quantised measurement, so \
                 gaster's `pad = overwrite_pad - sz` is exact and the packet-quantised sweep is NOT \
                 needed.",
                r.elapsed_us, r.sz, a.cut_length
            );
            format!("PARTIALS SURVIVE CANCELLATION: sz={} of {}", r.sz, a.cut_length)
        }
        None => {
            out!(a, 
                "  VERDICT  NO PARTIAL ON A CUT TRANSFER: every cancelled row reported sz=0. This is only \
                 as strong as the ladder — a cut before the first packet also reports 0. Add rows between \
                 0 and the completion latency before concluding the API cannot report partials."
            );
            "NO PARTIAL ON A CUT TRANSFER".to_string()
        }
    };
    if a.json {
        println!("{}", json_document("cut", &json_rows, None, None, &[], &verdict, false));
    }
    exit_code(0)
}

unsafe fn run_sweep(
    ctx: *mut sys::libusb_context,
    handle: *mut sys::libusb_device_handle,
    a: &Args,
    index: u8,
    index_reason: &str,
) -> std::process::ExitCode {
    let steps = plan(a);
    out!(a, "ep0cut --mode sweep — wLength x latency on {VID:04x}:{PID:04x}");
    out!(a, "  index: {index_reason}");
    out!(a, "  shapes: {:?}", a.shapes.iter().map(|s| s.label()).collect::<Vec<_>>());
    out!(a, "  lengths: {:?}  repeats: {}  rows: {}", a.lengths, a.repeats, steps.len());
    out!(a, 
        "  per-row deadline: {} ms (libusb's timeout). THIS TOOL NEVER CANCELS{}. reset-between: {}",
        a.sweep_deadline_ms,
        if a.continue_after_timeout { "; a TIMED_OUT row does not stop the ladder" } else { "; a TIMED_OUT row stops the ladder" },
        a.reset_between
    );
    out!(a, "  OUT data pattern: {:?}", a.pattern);
    if a.shapes.iter().any(|s| s.is_state_changing()) {
        out!(a, "  *** WARNING: the dnload shape is STATE-CHANGING (it advances the ROM's DFU state). ***");
    }
    out!(a, "  NOTE: this sends the exploit's own request shapes. It is a measurement tool, not a pwn.");
    out!(a, );
    out!(a, "  {:>5} {:<9} {:>7}  {:<10} {:>5}  {:>9}", "round", "shape", "wLength", "status", "sz", "us");

    let mut points: Vec<Point> = Vec::new();
    let mut json_rows: Vec<(u32, Shape, u16, Sample)> = Vec::new();
    for st in &steps {
        let out = run_row(
            ctx,
            handle,
            st.shape,
            st.length,
            index,
            a.pattern,
            RowMode::Wait { timeout_ms: a.sweep_deadline_ms },
        );
        if out.unreaped {
            out!(a, 
                "  {:>5} {:<9} {:>7}  UNREAPED — libusb never completed it; STOPPING (nothing is freed; \
                 the handle is no longer trustworthy)",
                st.round,
                st.shape.label(),
                st.length
            );
            emit_json_incomplete(a, &json_rows, "INCOMPLETE: transfer never reaped");
            return exit_code(1);
        }
        let s = match out.sample {
            Some(s) => s,
            None => {
                out!(a, 
                    "  {:>5} {:<9} {:>7}  SUBMIT REFUSED rc={} — STOPPING",
                    st.round,
                    st.shape.label(),
                    st.length,
                    out.submitted_rc
                );
                emit_json_incomplete(a, &json_rows, "INCOMPLETE: submit refused");
                return exit_code(1);
            }
        };
        out!(a, 
            "  {:>5} {:<9} {:>7}  {:<10} {:>5}  {:>9}",
            st.round,
            st.shape.label(),
            st.length,
            status_name(s.status),
            s.sz,
            s.elapsed_us
        );
        json_rows.push((st.round, st.shape, st.length, s));
        match points.iter_mut().find(|p| p.shape == st.shape && p.length == st.length) {
            Some(p) => p.samples.push(s),
            None => points.push(Point { shape: st.shape, length: st.length, samples: vec![s] }),
        }
        let wedged = s.status == LIBUSB_TRANSFER_TIMED_OUT || s.status == LIBUSB_TRANSFER_CANCELLED;
        if wedged {
            out!(a, 
                "            (row ended {}; libusb's timeout cancels the URB internally — this is the \
                 EP0 wedge risk)",
                status_name(s.status)
            );
            if a.reset_between {
                let rc = sys::libusb_reset_device(handle);
                out!(a, "            (port reset: rc={rc}; the measured recovery)");
            }
            if !a.continue_after_timeout {
                out!(a, );
                out!(a, 
                    "  SWEEP STOPPED after a {} row. The partial ladder is printed below but it is",
                    status_name(s.status)
                );
                out!(a, "  NOT a valid slope: the rows after the stop were never taken. Re-run with");
                out!(a, "  --continue-after-timeout only if you accept that.");
                let stats = stat_points(&points);
                out!(a, "{}", stats_lines(&stats));
                if a.json {
                    println!(
                        "{}",
                        json_document(
                            "sweep",
                            &json_rows,
                            Some(&stats),
                            Some(noise_floor(&stats)),
                            &[],
                            "INCOMPLETE: ladder stopped after a wedged row",
                            true
                        )
                    );
                }
                return exit_code(1);
            }
        }
    }

    let stats = stat_points(&points);
    out!(a, "{}", stats_lines(&stats));

    let noise = noise_floor(&stats);
    out!(a, );
    out!(a, "  ---- controls ----");
    let (ctl, ctl_ok) = control_lines(&stats, noise);
    for l in &ctl {
        out!(a, "{l}");
    }

    out!(a, );
    if !ctl_ok {
        out!(a, "  VERDICT  INVALID LADDER — a control failed; the ladder below is not a result.");
        if a.json {
            println!(
                "{}",
                json_document("sweep", &json_rows, Some(&stats), Some(noise), &ctl, "INVALID LADDER", true)
            );
        }
        return exit_code(1);
    }
    let (lines, _worst) = verdict_lines(&stats, noise, &a.shapes);
    out!(a, "  ---- what the data supports (INFERRED from this ladder alone) ----");
    for l in &lines {
        out!(a, "{l}");
    }
    out!(a, );
    out!(a, 
        "  A slope through a handful of points is NOT a measurement of the ROM's behaviour. What would \
         make it solid: more repeats, a second run on a re-enumerated device, and the same ladder at a \
         different host load."
    );
    if a.json {
        let verdict = lines
            .iter()
            .find(|l| l.contains("— "))
            .cloned()
            .unwrap_or_else(|| "see controls".to_string());
        println!(
            "{}",
            json_document("sweep", &json_rows, Some(&stats), Some(noise), &ctl, verdict.trim(), false)
        );
    }
    exit_code(0)
}

unsafe fn run_abort_pad(
    ctx: *mut sys::libusb_context,
    handle: *mut sys::libusb_device_handle,
    a: &Args,
    index: u8,
    index_reason: &str,
) -> std::process::ExitCode {
    let lengths = abort_lengths(a);
    let planv = abort_plan(a);
    out!(a, "ep0cut --mode abort-pad — the exploit's own order on {VID:04x}:{PID:04x}");
    out!(a, "  index: {index_reason}");
    out!(a, "  per point: pad at L COLD (repeated), RESET, then aborted 2048-byte DFU_DNLOAD (cancel");
    out!(a, "             after {}us), then the pad at L again with NO reset between those two.", a.abort_us);
    out!(a, "  scope: the exploit's ISOLATED abort->pad, not the full attempt-3 history (two completed");
    out!(a, "         2048-byte DNLOADs and two 64-byte drains precede the real pad). On a PWNED device");
    out!(a, "         this measures the pwned EP0 path; attribute to the SecureROM only with a stock");
    out!(a, "  lengths: {lengths:?}  cold arm repeated {}x (--repeats); the abort->pad arm runs once",
        a.repeats.max(1));
    out!(a, "  points: {}  per-row deadline: {} ms", planv.len(), a.sweep_deadline_ms);
    out!(a, "  *** STATE-CHANGING: this performs checkm8's SETUP corruption step (abort + pad). ***");
    out!(a, "  *** It never cancels the pad; a TIMED_OUT row stops the ladder. reset-between: {} ***", a.reset_between);
    out!(a, "");
    out!(a, "  {:>5} {:>7}  {:<10} {:>5} {:>9}", "round", "wLength", "row", "sz", "us");

    let mut points: Vec<AbortPoint> = Vec::new();
    let mut json_rows: Vec<(u32, Shape, u16, Sample)> = Vec::new();
    let mut unreaped = false;
    // R1: any early stop must reach the JSON as `incomplete` and the exit code, so
    // a stopped ladder can never read as a completed measurement.
    let mut early_stop = false;

    for (round, len) in &planv {
        // 1. the COLD baseline, taken FIRST so it is genuinely cold (T3-R A1). It
        //    is repeated, because it is the only non-state-changing arm and its
        //    spread is the drift estimate the verdict needs (T3-R B2).
        // R10: reset BEFORE the cold repeats. Without this only the FIRST point's
        // baseline is cold — point k+1's "cold" arm would follow point k's abort+pad,
        // and that contamination pushes the classifier toward `Same` (a false
        // negative), which is the one error this mode must not make.
        if a.reset_between {
            let rc = sys::libusb_reset_device(handle);
            out!(a, "  {round:>5} {len:>7}  (port reset at point start, so the cold arm is cold: rc={rc})");
        }
        let cold_repeats = a.repeats.max(1);
        let mut colds: Vec<Sample> = Vec::new();
        let mut cold_wedged = false;
        for k in 0..cold_repeats {
            let c = run_row(ctx, handle, Shape::Pad, *len, index, a.pattern, RowMode::Wait { timeout_ms: a.sweep_deadline_ms });
            match c.sample {
                Some(s) if !c.unreaped => {
                    out!(a, "  {round:>5} {len:>7}  {:<10} {:>5} {:>9}", format!("cold#{k}"), s.sz, s.elapsed_us);
                    json_rows.push((*round, Shape::Pad, *len, s));
                    if silent(&s) {
                        cold_wedged = true;
                    }
                    colds.push(s);
                }
                _ => {
                    out!(a, "  {round:>5} {len:>7}  cold#{k} UNREAPED/refused — STOPPING");
                    unreaped = true;
                    early_stop = true;
                    break;
                }
            }
        }
        if unreaped || colds.is_empty() {
            break;
        }
        if cold_wedged {
            // A length that wedges cold needs one EP0-wedge recovery. When the run
            // is going to continue, the unconditional between-arms reset below IS
            // that recovery — doing both put two resets back to back (T3-R R12).
            if a.reset_between && !a.continue_after_timeout {
                let rc = sys::libusb_reset_device(handle);
                out!(a, "            (cold pad at this length ended without an answer; EP0-wedge reset: rc={rc})");
            }
            if !a.continue_after_timeout {
                out!(a, "            (this length wedges cold — recording it and stopping; re-run with");
                out!(a, "             --continue-after-timeout to walk on)");
            }
        }
        let (cold, cold_spread, cold_mixed) = aggregate_cold(&colds);
        out!(a, "            (cold n={} spread={cold_spread}us{})",
            colds.len(),
            if cold_mixed { ", MIXED statuses — no baseline at this length" } else { "" });
        if cold_wedged && !a.continue_after_timeout {
            // Do NOT fabricate an abort/after pair here: the abort is never sent at
            // this length, and inventing rows would make the verdict read "Same".
            out!(a, "            (length {len} wedges even cold — recorded, no abort sent, ladder stops)");
            early_stop = true;
            break;
        }

        // R3: reset between the arms, so the treatment arm does not inherit the
        // cold arm's history (three pads immediately before a heap-corruption step
        // can change what the abort acts on). The abort->pad adjacency itself is
        // preserved below, because that is what the exploit does.
        if a.reset_between {
            let rc = sys::libusb_reset_device(handle);
            out!(a, "            (port reset between the cold arm and the abort: rc={rc})");
        }

        // 2. the aborted DNLOAD — the exploit's own cut window.
        let ab = run_row(ctx, handle, Shape::Dnload, 2048, index, a.pattern, RowMode::CutAt { at_us: a.abort_us });
        if ab.unreaped {
            out!(a, "  {round:>5} {len:>7}  abort UNREAPED — libusb never completed it; STOPPING");
            unreaped = true;
            early_stop = true;
            break;
        }
        let ab = match ab.sample {
            Some(s) => s,
            None => {
                out!(a, "  {round:>5} {len:>7}  abort submit refused — STOPPING");
                unreaped = true;
                early_stop = true;
                break;
            }
        };
        out!(a, "  {round:>5} {len:>7}  {:<10} {:>5} {:>9}", "abort", ab.sz, ab.elapsed_us);
        json_rows.push((*round, Shape::Dnload, 2048, ab));

        // 3. the pad immediately after it — NO reset in between, exactly as the
        //    exploit sends it. This is the state-changing arm, taken once.
        let after = run_row(ctx, handle, Shape::Pad, *len, index, a.pattern, RowMode::Wait { timeout_ms: a.sweep_deadline_ms });
        let after = match after.sample {
            Some(s) if !after.unreaped => s,
            _ => {
                out!(a, "  {round:>5} {len:>7}  after UNREAPED/refused — STOPPING");
                unreaped = true;
                early_stop = true;
                break;
            }
        };
        out!(a, "  {round:>5} {len:>7}  {:<10} {:>5} {:>9}", "after", after.sz, after.elapsed_us);
        json_rows.push((*round, Shape::Pad, *len, after));

        points.push(AbortPoint {
            length: *len,
            cold,
            cold_n: colds.len(),
            cold_spread_us: cold_spread,
            cold_mixed,
            abort: ab,
            after,
        });

        if silent(&after) {
            out!(a, "            (pad after the abort ended {}; libusb's timeout cancels internally)", status_name(after.status));
            // F5: only reset here when the run is going to STOP — when it continues,
            // the next point's start-of-point reset is the same recovery, and doing
            // both put two resets back to back.
            if a.reset_between && !a.continue_after_timeout {
                let rc = sys::libusb_reset_device(handle);
                out!(a, "            (port reset: rc={rc}; the measured recovery, and the run stops here)");
            }
            if !a.continue_after_timeout {
                out!(a, "");
                out!(a, "  ABORT-PAD STOPPED after a pad that never answered. The rows so far are printed;");
                out!(a, "  later lengths were never taken (--continue-after-timeout walks on).");
                early_stop = true;
                break;
            }
        }
    }

    out!(a, "");
    out!(a, "  ---- per length (one round each; noise floor = {STATE_EFFECT_FLOOR_US} us) ----");
    // The verdict's own default tolerance; each point may widen it with its own
    // cold spread (state_effect does that), and the per-point spread is printed.
    let noise = STATE_EFFECT_FLOOR_US;
    let (lines, verdict) = abort_pad_verdict(&points, noise, a.abort_us);
    for l in &lines {
        out!(a, "{l}");
    }
    if a.json {
        println!(
            "{}",
            json_document(
                "abort-pad",
                &json_rows,
                None,
                Some(noise),
                &lines,
                &verdict,
                unreaped || early_stop
            )
        );
    }
    // R11: exit 1 also when the ladder completed but produced NO result — the exit
    // code contract must cover "ran but nothing is classifiable", not only
    // "stopped early". (`incomplete` in the JSON means "ladder stopped".)
    let no_result = verdict.starts_with("NO POINTS MEASURED") || verdict.starts_with("NO CLASSIFIABLE POINT");
    if unreaped || early_stop || points.is_empty() || no_result {
        out!(a, "  EXIT 1: no usable result — see the verdict above.");
        return exit_code(1);
    }
    exit_code(0)
}

/// The early-stop JSON path, so an incomplete ladder is machine-readable as
/// INCOMPLETE rather than looking like a finished result.
fn emit_json_incomplete(a: &Args, rows: &[(u32, Shape, u16, Sample)], why: &str) {
    if a.json {
        println!("{}", json_document("sweep", rows, None, None, &[], why, true));
    }
}

// ---------------------------------------------------------------------------
// Tests — the pure parts only: no device is opened by `cargo test`
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Args {
        parse_args_from(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn setup_bytes_pin_the_reference_wire_requests() {
        // The pad request exactly as gaster.c:853 sends it at overwrite_pad=1280
        // (CPID 0x8003, gaster.c:626) — MEASURED on the wire as `00 00 0000 0000 0500`.
        assert_eq!(Shape::Pad.setup(1280, 4), [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]);
        // PATCH's overflow, gaster.c:1211, 48 bytes — MEASURED as `02 03 0000 0080 0030`.
        assert_eq!(Shape::Overflow.setup(48, 4), [0x02, 0x03, 0x00, 0x00, 0x80, 0x00, 0x30, 0x00]);
        // The zero-length form of the same request — SPRAY's stall primitive,
        // gaster.c:893, MEASURED as `02 03 0000 0080 0000`.
        assert_eq!(Shape::Overflow.setup(0, 4), [0x02, 0x03, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00]);
        // GET_DESCRIPTOR(3,4), 255 bytes — MEASURED as `80 06 0304 0409 00ff`.
        assert_eq!(Shape::GetDesc.setup(255, 4), [0x80, 0x06, 0x04, 0x03, 0x09, 0x04, 0xff, 0x00]);
        // DFU_DNLOAD 2048 — gaster.c:853's aborted transfer, `21 01 0000 0000 0800`.
        assert_eq!(Shape::Dnload.setup(2048, 4), [0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08]);
    }

    #[test]
    fn default_ladder_covers_the_task_lengths_and_the_exploit_lengths() {
        for want in [0u16, 64, 128, 256, 512, 1024, 1280, 2048] {
            assert!(DEFAULT_LENGTHS.contains(&want), "task-9 requires wLength {want}");
        }
        assert!(DEFAULT_LENGTHS.contains(&48), "PATCH's overflow is 48 bytes");
        assert!(DEFAULT_LENGTHS.contains(&1280), "the pad is 1280 bytes");
    }

    #[test]
    fn plan_is_round_robin_not_shape_sequential() {
        let mut a = args(&["--mode", "sweep", "--shape", "pad,getdesc", "--lengths", "0,64", "--repeats", "2"]);
        a.shapes = vec![Shape::Pad, Shape::GetDesc];
        let p = plan(&a);
        assert_eq!(
            p,
            vec![
                Step { round: 0, shape: Shape::Pad, length: 0 },
                Step { round: 0, shape: Shape::Pad, length: 64 },
                Step { round: 0, shape: Shape::GetDesc, length: 0 },
                Step { round: 0, shape: Shape::GetDesc, length: 64 },
                Step { round: 1, shape: Shape::Pad, length: 0 },
                Step { round: 1, shape: Shape::Pad, length: 64 },
                Step { round: 1, shape: Shape::GetDesc, length: 0 },
                Step { round: 1, shape: Shape::GetDesc, length: 64 },
            ]
        );
    }

    #[test]
    fn median_handles_odd_even_and_empty() {
        assert_eq!(median(&mut []), 0);
        assert_eq!(median(&mut [5]), 5);
        assert_eq!(median(&mut [9, 1, 5]), 5);
        assert_eq!(median(&mut [1, 2, 3, 4]), 2);
    }

    #[test]
    fn ls_slope_is_exact_on_a_line_and_none_without_variation() {
        let s = ls_slope(&[0.0, 1.0, 2.0], &[10.0, 30.0, 50.0]).unwrap();
        assert!((s - 20.0).abs() < 1e-9);
        assert!(ls_slope(&[1.0], &[2.0]).is_none());
        assert!(ls_slope(&[1.0, 1.0], &[2.0, 3.0]).is_none());
    }

    fn stat(shape: Shape, length: u16, us: u64, sz: i32, status: i32) -> RowStat {
        RowStat {
            shape,
            length,
            n: 1,
            median_us: us,
            min_us: us,
            max_us: us,
            median_sz: sz,
            statuses: vec![(status, 1)],
        }
    }

    /// Synthetic served calibration: 100 us fixed + 30 us per 64-byte packet.
    fn served_rows() -> Vec<RowStat> {
        (0..=4)
            .map(|p| stat(Shape::GetDesc, (p * 64) as u16, 100 + 30 * p as u64, (p * 64) as i32, LIBUSB_TRANSFER_COMPLETED))
            .collect()
    }

    #[test]
    fn flat_latency_classifies_as_deliberation() {
        let mut stats = served_rows();
        for len in [0u16, 64, 128, 256, 512, 1024, 1280, 2048] {
            stats.push(stat(Shape::Pad, len, 900, 0, LIBUSB_TRANSFER_STALL));
        }
        let (claim, _) = classify_shape(&stats, Shape::Pad, 10);
        assert_eq!(claim, Claim::Deliberation);
    }

    #[test]
    fn length_tracking_latency_classifies_as_consumption() {
        let mut stats = served_rows();
        for p in 0..=20u64 {
            stats.push(stat(Shape::Pad, (p * 64) as u16, 150 + 30 * p, 0, LIBUSB_TRANSFER_STALL));
        }
        let (claim, _) = classify_shape(&stats, Shape::Pad, 10);
        assert_eq!(claim, Claim::Consumption);
    }

    #[test]
    fn flat_then_rising_classifies_as_a_knee() {
        let mut stats = served_rows();
        // <=512 flat at 200 us; >=1024 rises at 30 us/packet from 512.
        for len in [0u16, 64, 128, 256, 512] {
            stats.push(stat(Shape::Pad, len, 200, 0, LIBUSB_TRANSFER_STALL));
        }
        stats.push(stat(Shape::Pad, 1024, 200 + 30 * 8, 0, LIBUSB_TRANSFER_STALL));
        stats.push(stat(Shape::Pad, 1280, 200 + 30 * 12, 0, LIBUSB_TRANSFER_STALL));
        stats.push(stat(Shape::Pad, 2048, 200 + 30 * 24, 0, LIBUSB_TRANSFER_STALL));
        let (claim, _) = classify_shape(&stats, Shape::Pad, 10);
        assert_eq!(claim, Claim::Knee);
    }

    /// The stock cold pad row MEASURED on 2026-10-03 (a9pwn-traces/linux/
    /// stock-pad-1280.table.txt, sha256 4bd8814b…): a freshly power-cycled STOCK
    /// SecureROM, three real repeats per point —
    ///   pad 0     STALL 0 154/158/169;  pad 64 STALL 0 172/174/177;
    ///   pad 1280  TIMED_OUT sz=64 250084/250113/250151;
    ///   getdesc 0 COMPLETED 0 51/68/78; 64 COMPLETED 64 51/73/82;
    ///   1280 COMPLETED 198 132/154/174.
    /// The pre-fix tool fitted the 250 ms deadline and printed "DATA CONSUMPTION
    /// (a) SUPPORTED" at 12792.6 us/packet. It must now be a WEDGE.
    #[test]
    fn the_measured_stock_row_is_a_wedge_not_consumption() {
        let pt = |shape: Shape, length: u16, us: [u64; 3], sz: i32, status: i32| {
            Point {
                shape,
                length,
                samples: us.iter().map(|u| Sample { elapsed_us: *u, status, sz }).collect(),
            }
        };
        let points = vec![
            pt(Shape::Pad, 0, [154, 158, 169], 0, LIBUSB_TRANSFER_STALL),
            pt(Shape::Pad, 64, [172, 174, 177], 0, LIBUSB_TRANSFER_STALL),
            pt(Shape::Pad, 1280, [250_084, 250_113, 250_151], 64, LIBUSB_TRANSFER_TIMED_OUT),
            pt(Shape::GetDesc, 0, [51, 68, 78], 0, LIBUSB_TRANSFER_COMPLETED),
            pt(Shape::GetDesc, 64, [51, 73, 82], 64, LIBUSB_TRANSFER_COMPLETED),
            pt(Shape::GetDesc, 1280, [132, 154, 174], 198, LIBUSB_TRANSFER_COMPLETED),
        ];
        let stats = stat_points(&points);
        let noise = noise_floor(&stats);
        assert_eq!(noise, 42, "the largest answered same-status spread is getdesc 1280");
        let (claim, notes) = classify_shape(&stats, Shape::Pad, noise);
        assert_eq!(claim, Claim::Wedge, "{notes:?}");
        let joined = notes.join("\n");
        assert!(joined.contains("EXCLUDED from the fit (no device answer"), "{joined}");
        assert!(joined.contains("span 1 packet"), "{joined}");
        assert!(!joined.contains("12792"), "{joined}");
        let (lines, _) = verdict_lines(&stats, noise, &[Shape::Pad]);
        let text = lines.join("\n");
        assert!(text.contains("WEDGE"), "{text}");
        assert!(!text.contains("DATA CONSUMPTION"), "{text}");
        assert!(text.contains("NO DEVICE ANSWER"), "the 1280 row must be reported as unanswered: {text}");
    }

    #[test]
    fn a_row_with_disagreeing_repeats_is_reported_and_blocks_a_clean_claim() {
        // Rows: pad answered 0/64, then a row at 128 whose repeats disagreed
        // (2 TIMED_OUT + 1 STALL) — the shape's decisive length is unusable, so no
        // consumption/deliberation claim may be made (T3-R round 5 F2).
        let pts = vec![
            Point { shape: Shape::Pad, length: 0, samples: vec![Sample { elapsed_us: 158, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point { shape: Shape::Pad, length: 64, samples: vec![Sample { elapsed_us: 174, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point {
                shape: Shape::Pad,
                length: 128,
                samples: vec![
                    Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 },
                    Sample { elapsed_us: 250_100, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 },
                    Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_STALL, sz: 0 },
                ],
            },
        ];
        let mut stats = stat_points(&pts);
        stats.extend(served_rows());
        let (claim, notes) = classify_shape(&stats, Shape::Pad, 10);
        assert_eq!(claim, Claim::Indeterminate, "{notes:?}");
        let joined = notes.join("\n");
        assert!(joined.contains("UNUSABLE rows"), "{joined}");
        assert!(joined.contains("no clean claim"), "{joined}");
    }

    #[test]
    fn the_printed_decision_never_contradicts_the_claim() {
        // G1: silent at 128, and the LONGEST row (256) has disagreeing repeats.
        // `non_monotone` and `consumption_below_wedge` are both false here, so the
        // old decision string printed "=> WEDGE" beside an INDETERMINATE claim.
        let pts = vec![
            Point { shape: Shape::Pad, length: 0, samples: vec![Sample { elapsed_us: 158, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point { shape: Shape::Pad, length: 64, samples: vec![Sample { elapsed_us: 174, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point { shape: Shape::Pad, length: 128, samples: vec![Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 }] },
            Point {
                shape: Shape::Pad,
                length: 256,
                samples: vec![
                    Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 },
                    Sample { elapsed_us: 250_100, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 },
                    Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_STALL, sz: 0 },
                ],
            },
        ];
        let mut stats = stat_points(&pts);
        stats.extend(served_rows());
        let (claim, notes) = classify_shape(&stats, Shape::Pad, 10);
        let joined = notes.join("\n");
        assert!(joined.contains("UNUSABLE rows"), "{joined}");
        let decision = notes
            .iter()
            .find(|n| n.starts_with("decision:"))
            .expect("the decision note must be printed");
        assert!(
            decision.ends_with(claim.as_str()),
            "decision must end with the claim it accompanies: {decision:?} vs {:?}",
            claim.as_str()
        );
        assert!(!decision.contains("=> WEDGE"), "{decision}");
    }

    #[test]
    fn no_calibration_prints_unavailable_not_nan() {
        // G2: a silent row with no served calibration.
        let pts = vec![
            Point { shape: Shape::Pad, length: 0, samples: vec![Sample { elapsed_us: 158, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point { shape: Shape::Pad, length: 64, samples: vec![Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 }] },
        ];
        let stats = stat_points(&pts);
        let (_, notes) = classify_shape(&stats, Shape::Pad, 10);
        let joined = notes.join("\n");
        assert!(joined.contains("UNAVAILABLE"), "{joined}");
        assert!(!joined.contains("NaN"), "{joined}");
    }

    #[test]
    fn non_monotone_silence_is_not_a_wedge_claim() {
        // 0/64 answered, 128 silent, but 256 answered: a reset between rows can do
        // this, and the tool must not call it "answered up to a length, silent
        // above it" (T3-R round 5 F3).
        let pts = vec![
            Point { shape: Shape::Pad, length: 0, samples: vec![Sample { elapsed_us: 158, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point { shape: Shape::Pad, length: 64, samples: vec![Sample { elapsed_us: 174, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
            Point { shape: Shape::Pad, length: 128, samples: vec![Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 }] },
            Point { shape: Shape::Pad, length: 256, samples: vec![Sample { elapsed_us: 190, status: LIBUSB_TRANSFER_STALL, sz: 0 }] },
        ];
        let mut stats = stat_points(&pts);
        stats.extend(served_rows());
        let (claim, notes) = classify_shape(&stats, Shape::Pad, 10);
        assert_eq!(claim, Claim::Indeterminate, "{notes:?}");
        let joined = notes.join("\n");
        assert!(joined.contains("NON-MONOTONE"), "{joined}");
        // F4: the decision itself is printed, with its threshold and inputs.
        assert!(joined.contains("decision: consumption below a wedge needs"), "{joined}");
    }

    #[test]
    fn no_calibration_is_reported_rather_than_guessed() {
        let stats = vec![stat(Shape::Pad, 0, 500, 0, LIBUSB_TRANSFER_STALL)];
        let (claim, _) = classify_shape(&stats, Shape::Pad, 10);
        assert_eq!(claim, Claim::NoCalibration);
    }

    #[test]
    fn noise_floor_ignores_mixed_status_points() {
        let mut p = Point { shape: Shape::Pad, length: 64, samples: vec![] };
        p.samples.push(Sample { elapsed_us: 100, status: LIBUSB_TRANSFER_STALL, sz: 0 });
        p.samples.push(Sample { elapsed_us: 300, status: LIBUSB_TRANSFER_STALL, sz: 0 });
        let mut q = Point { shape: Shape::Pad, length: 128, samples: vec![] };
        q.samples.push(Sample { elapsed_us: 100, status: LIBUSB_TRANSFER_STALL, sz: 0 });
        q.samples.push(Sample { elapsed_us: 9000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 0 });
        let stats = stat_points(&[p, q]);
        assert_eq!(noise_floor(&stats), 200);
    }

    #[test]
    fn parse_defaults_are_the_cut_ladder() {
        let a = args(&[]);
        assert_eq!(a.mode, Mode::Cut);
        assert_eq!(a.effective_deadlines(), vec![0, 25, 50, 75, 100, 125, 150, 300, 2000]);
        assert_eq!(a.shapes, Shape::default_set());
        assert_eq!(a.lengths, DEFAULT_LENGTHS.to_vec());
        assert!(a.reset_between);
        assert!(!a.continue_after_timeout);
    }

    #[test]
    fn parse_sweep_options() {
        let a = args(&[
            "--mode", "sweep", "--shape", "pad,overflow,pad", "--lengths", "0,48,2048", "--repeats", "5",
            "--deadline-ms", "400", "--pattern", "ramp", "--json", "--continue-after-timeout",
        ]);
        assert_eq!(a.mode, Mode::Sweep);
        assert_eq!(a.shapes, vec![Shape::Pad, Shape::Overflow]);
        assert_eq!(a.lengths, vec![0, 48, 2048]);
        assert_eq!(a.repeats, 5);
        assert_eq!(a.sweep_deadline_ms, 400);
        assert_eq!(a.pattern, Pattern::Ramp);
        assert!(a.json && a.continue_after_timeout);
    }

    #[test]
    fn parse_rejects_the_three_ways_to_get_this_wrong() {
        assert!(parse_args_from(&["--deadline-ms".to_string(), "0".to_string()]).is_err());
        assert!(parse_args_from(&["--repeats".to_string(), "0".to_string()]).is_err());
        assert!(parse_args_from(&["--shape".to_string(), "dnloadd".to_string()]).is_err());
        assert!(parse_args_from(&["--mode".to_string(), "fast".to_string()]).is_err());
        assert!(parse_args_from(&["--nonsense".to_string()]).is_err());
    }

    #[test]
    fn dnload_is_opt_in_only() {
        let a = args(&["--mode", "sweep"]);
        assert!(!a.shapes.contains(&Shape::Dnload), "dnload is state-changing and must not default on");
        let b = args(&["--mode", "sweep", "--shape", "dnload"]);
        assert!(b.shapes.contains(&Shape::Dnload));
        assert!(Shape::Dnload.is_state_changing());
    }

    #[test]
    fn cut_controls_accept_the_measured_ladder_that_contains_the_answer() {
        // MEASURED, a9pwn-traces/linux/e1-ep0cut-ladder.txt: rows 0..125us are
        // CANCELLED with 64/0/64/128/192/198 bytes, then COMPLETED 198. An earlier
        // control 1 required sz == 0 on the first row and threw this ladder away.
        let rows = vec![
            Sample { elapsed_us: 134, status: LIBUSB_TRANSFER_CANCELLED, sz: 64 },
            Sample { elapsed_us: 167, status: LIBUSB_TRANSFER_CANCELLED, sz: 0 },
            Sample { elapsed_us: 180, status: LIBUSB_TRANSFER_CANCELLED, sz: 128 },
            Sample { elapsed_us: 176, status: LIBUSB_TRANSFER_COMPLETED, sz: 198 },
        ];
        assert_eq!(cut_controls(&rows), (true, true));
        assert_eq!(first_partial(&rows).map(|s| s.sz), Some(64));
    }

    #[test]
    fn cut_controls_reject_a_ladder_with_no_cancel_and_a_silent_device() {
        let no_cancel = vec![
            Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_COMPLETED, sz: 198 },
            Sample { elapsed_us: 180, status: LIBUSB_TRANSFER_COMPLETED, sz: 198 },
        ];
        assert_eq!(cut_controls(&no_cancel), (false, true));
        let silent = vec![
            Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_CANCELLED, sz: 0 },
            Sample { elapsed_us: 2_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 0 },
        ];
        assert_eq!(cut_controls(&silent), (true, false));
        assert!(first_partial(&silent).is_none());
    }

    #[test]
    fn abort_pad_defaults_and_plan_are_the_exploit_lengths() {
        let a = args(&["--mode", "abort-pad"]);
        assert_eq!(abort_lengths(&a), vec![1280, 256, 128, 64, 0]);
        assert_eq!(abort_plan(&a).len(), 5, "one round per length");
        assert_eq!(abort_plan(&a)[0], (0, 1280), "the exploit's own pad length is FIRST (T3-R B3)");
        let b = args(&["--mode", "abort-pad", "--lengths", "64,1280"]);
        assert_eq!(abort_lengths(&b), vec![64, 1280]);
    }

    fn ap(len: u16, cold: Sample, abort: Sample, after: Sample) -> AbortPoint {
        AbortPoint { length: len, cold, cold_n: 3, cold_spread_us: 16, cold_mixed: false, abort, after }
    }

    fn stall(us: u64) -> Sample {
        Sample { elapsed_us: us, status: LIBUSB_TRANSFER_STALL, sz: 0 }
    }

    #[test]
    fn state_effect_distinguishes_same_changed_and_wedged() {
        let cold = stall(200);
        let same = ap(64, cold, stall(120), stall(210));
        assert_eq!(state_effect(&same, 50), StateEffect::Same);
        let changed = ap(1280, stall(250), stall(110), stall(890));
        assert_eq!(state_effect(&changed, 50), StateEffect::Changed);
        let wedged = ap(1280, stall(250), stall(110), Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 });
        assert_eq!(state_effect(&wedged, 50), StateEffect::Wedged);
        // A different byte count is a change even when the latency matches.
        let sz_change = ap(128, stall(200), stall(120), Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_STALL, sz: 64 });
        assert_eq!(state_effect(&sz_change, 50), StateEffect::Changed);
        // Cold wedged: NO baseline, and explicitly not a state effect (T3-R R2).
        let timed_out = Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 };
        let both = ap(128, timed_out, stall(120), timed_out);
        assert_eq!(state_effect(&both, 50), StateEffect::NoBaseline);
        // Cold repeats that disagree on status cannot be a baseline either (R5).
        let mut mixed = ap(128, stall(200), stall(120), stall(205));
        mixed.cold_mixed = true;
        assert_eq!(state_effect(&mixed, 50), StateEffect::NoBaseline);
        // A point's own spread raises its tolerance (R4): 60 us apart with a
        // 200 us cold spread is NOT a state effect.
        let mut noisy = ap(64, stall(200), stall(120), stall(260));
        noisy.cold_spread_us = 200;
        assert_eq!(state_effect(&noisy, 50), StateEffect::Same);
    }

    #[test]
    fn abort_pad_verdict_says_which_way_the_state_matters() {
        let cold = stall(200);
        let identical = vec![
            ap(0, cold, stall(120), stall(205)),
            ap(64, cold, stall(118), stall(210)),
            ap(1280, cold, stall(115), stall(195)),
        ];
        let (lines, v) = abort_pad_verdict(&identical, 50, 0);
        assert!(v.contains("does NOT change"), "{v}");
        assert!(lines.iter().any(|l| l.contains("exploit length 1280")));

        let one_changed = vec![
            ap(64, cold, stall(118), stall(205)),
            ap(1280, stall(250), Sample { elapsed_us: 117, status: LIBUSB_TRANSFER_CANCELLED, sz: 0 }, stall(890)),
        ];
        let (_, v2) = abort_pad_verdict(&one_changed, 50, 0);
        assert!(v2.contains("CHANGES"), "{v2}");

        let silent_after = Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 };
        let wedged = vec![ap(128, stall(200), stall(120), silent_after)];
        let (_, v3) = abort_pad_verdict(&wedged, 50, 0);
        assert!(v3.contains("WEDGES after the abort"), "{v3}");

        // Cold ALSO wedged: no baseline, and the verdict must NOT claim a negative
        // from it (T3-R R2).
        let both = vec![
            ap(64, stall(200), stall(118), stall(205)),
            ap(128, silent_after, stall(120), silent_after),
        ];
        let (lines, v4) = abort_pad_verdict(&both, 50, 0);
        assert!(!v4.contains("does NOT change"), "unclassifiable points must not produce a negative: {v4}");
        assert!(lines.iter().any(|l| l.contains("NO USABLE BASELINE")), "{lines:?}");

        // R1: no points at all must never read as a completed negative.
        let (lines5, v5) = abort_pad_verdict(&[], 50, 0);
        assert!(v5.contains("NO POINTS MEASURED"), "{v5}");
        assert!(!v5.contains("does NOT change"), "{v5}");
        assert!(lines5.iter().any(|l| l.contains("after-abort slope")), "{lines5:?}");

        // R16: a ladder that ran but measured nothing classifiable must also say so
        // — this is the branch that exists to stop a false negative.
        let (_, v6) = abort_pad_verdict(&[ap(128, silent_after, stall(120), silent_after)], 50, 0);
        assert!(v6.contains("NO CLASSIFIABLE POINT"), "{v6}");
        assert!(!v6.contains("does NOT change"), "{v6}");
        let (lines6, _) = abort_pad_verdict(&[ap(128, silent_after, stall(120), silent_after)], 50, 0);
        assert!(lines6.iter().any(|l| l.contains("MIXED") || l.contains("TIMED_OUT")), "{lines6:?}");
    }

    #[test]
    fn abort_pad_dry_run_prints_the_sequence_and_never_opens_a_device() {
        let a = args(&["--mode", "abort-pad", "--lengths", "64,1280"]);
        let text = render_plan(&a, "declared iSerialNumber 4");
        assert!(text.contains("NOTHING IS SENT, THE DEVICE IS NOT OPENED"));
        assert!(text.contains("STATE-CHANGING"));
        assert!(text.contains("21 01 00 00 00 00 00 08"), "the 2048-byte DNLOAD setup");
        assert!(text.contains("00 00 00 00 00 00 00 05"), "the 1280-byte pad setup");
        assert!(text.contains("point 1"));
        assert!(text.contains("Noise floor"));
    }

    #[test]
    fn aggregate_cold_is_order_independent_and_flags_mixed() {
        let a = Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_STALL, sz: 0 };
        let b = Sample { elapsed_us: 400, status: LIBUSB_TRANSFER_STALL, sz: 0 };
        let c = Sample { elapsed_us: 300, status: LIBUSB_TRANSFER_STALL, sz: 0 };
        let (s1, spread, mixed) = aggregate_cold(&[a, b, c]);
        assert_eq!(s1.elapsed_us, 300);
        assert_eq!(spread, 200);
        assert!(!mixed);
        assert_eq!(s1.status, LIBUSB_TRANSFER_STALL);
        // Same rows, reversed: identical baseline and spread (T3-R R5).
        let (s2, spread2, mixed2) = aggregate_cold(&[c, b, a]);
        assert_eq!(s2.elapsed_us, s1.elapsed_us);
        assert_eq!(spread2, spread);
        assert!(!mixed2);
        // Disagreement on status is flagged, not silently resolved to row 0.
        let t = Sample { elapsed_us: 250_000, status: LIBUSB_TRANSFER_TIMED_OUT, sz: 64 };
        let (_, _, mixed3) = aggregate_cold(&[a, t]);
        assert!(mixed3, "disagreeing repeats must be reported as mixed");
        let (_, _, mixed4) = aggregate_cold(&[t, a]);
        assert!(mixed4, "and symmetrically");
        // R9: agreeing on STATUS but disagreeing on the byte count is also not a
        // baseline — `sz` is what the classifier compares.
        let moved = Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_STALL, sz: 64 };
        let zero = Sample { elapsed_us: 200, status: LIBUSB_TRANSFER_STALL, sz: 0 };
        let (same_sz, _, mixed5) = aggregate_cold(&[zero, zero, zero]);
        assert!(!mixed5, "identical repeats are a valid baseline");
        assert_eq!(same_sz.sz, 0);
        let (_, _, mixed6) = aggregate_cold(&[zero, zero, moved]);
        assert!(mixed6, "status-equal but sz-different repeats must be mixed");
        // R15: the two halves of the aggregate use the same median convention.
        let s1 = Sample { elapsed_us: 100, status: LIBUSB_TRANSFER_STALL, sz: 0 };
        let s2 = Sample { elapsed_us: 300, status: LIBUSB_TRANSFER_STALL, sz: 10 };
        let (agg, _, _) = aggregate_cold(&[s1, s2]);
        assert_eq!(agg.elapsed_us, 200, "averaged middle for latency");
        assert_eq!(agg.sz, 5, "and averaged middle for sz, not the upper one");
    }

    #[test]
    fn json_document_is_well_formed_and_counts_every_row() {
        // A tiny structural scanner that respects string literals — no serde in
        // this crate, so the test checks brackets/quotes itself.
        fn balanced(s: &str) -> bool {
            let (mut depth, mut in_str, mut esc) = (0i32, false, false);
            for c in s.chars() {
                if in_str {
                    if esc {
                        esc = false;
                    } else if c == '\\' {
                        esc = true;
                    } else if c == '"' {
                        in_str = false;
                    }
                } else {
                    match c {
                        '"' => in_str = true,
                        '{' | '[' => depth += 1,
                        '}' | ']' => depth -= 1,
                        _ => {}
                    }
                }
            }
            depth == 0 && !in_str
        }

        let a = Sample { elapsed_us: 150, status: LIBUSB_TRANSFER_STALL, sz: 0 };
        let b = Sample { elapsed_us: 180, status: LIBUSB_TRANSFER_COMPLETED, sz: 198 };
        let rows = vec![(0u32, Shape::Pad, 0u16, a), (0, Shape::GetDesc, 255u16, b)];
        let stats = stat_points(&[
            Point { shape: Shape::Pad, length: 0, samples: vec![a] },
            Point { shape: Shape::GetDesc, length: 255, samples: vec![b] },
        ]);
        let doc = json_document(
            "sweep",
            &rows,
            Some(&stats),
            Some(12),
            &["a \"quoted\" control".to_string()],
            "PARTIALS \"x\"",
            false,
        );
        assert!(balanced(&doc), "unbalanced JSON: {doc}");
        assert_eq!(doc.matches("\"shape\":\"").count(), 4, "2 rows + 2 points: {doc}");
        assert!(doc.contains("\\\"quoted\\\""), "quotes must be escaped: {doc}");
        assert!(doc.contains("\"noise_us\":12"));
        assert!(doc.contains("\"incomplete\":false"));
        assert!(doc.contains("\"status\":\"STALL\""));
        assert!(doc.contains("\"median_sz\":198"));
    }

    #[test]
    fn dry_run_prints_every_row_and_never_needs_a_device() {
        let a = args(&[
            "--mode", "sweep", "--shape", "pad,overflow,getdesc", "--lengths", "0,48,255,1280",
            "--repeats", "2",
        ]);
        let text = render_plan(&a, "declared iSerialNumber 4");
        assert!(text.contains("NOTHING IS SENT, THE DEVICE IS NOT OPENED"));
        // 2 rounds x 3 shapes x 4 lengths = 24 rows; pad+overflow are OUT.
        assert!(text.contains("24 requests total: 16 OUT"), "ladder size must be stated: {text}");
        for want in [
            "00 00 00 00 00 00 00 00", // pad, wLength 0
            "00 00 00 00 00 00 00 05", // pad, wLength 1280 (MEASURED on the wire)
            "02 03 00 00 80 00 30 00", // overflow, wLength 48 (MEASURED on the wire)
            "80 06 04 03 09 04 ff 00", // getdesc, wLength 255 (MEASURED on the wire)
        ] {
            assert!(text.contains(want), "dry run must print the exact setup packet {want}");
        }
        assert!(text.contains("CONTROLS this ladder will check"));
        assert!(text.contains("FALSIFICATION") || text.contains("falsification"));
    }

    #[test]
    fn verdict_lines_state_the_falsification() {
        let mut stats = served_rows();
        for p in 0..=20u64 {
            stats.push(stat(Shape::Pad, (p * 64) as u16, 150 + 30 * p, 0, LIBUSB_TRANSFER_STALL));
        }
        let (lines, claim) = verdict_lines(&stats, 10, &[Shape::Pad]);
        assert_eq!(claim, Claim::Consumption);
        let joined = lines.join("\n");
        assert!(joined.contains("FALSIFIED IF"));
        assert!(joined.contains("us per 64-byte packet"));
    }
}
