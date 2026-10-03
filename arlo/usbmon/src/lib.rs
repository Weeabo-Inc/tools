//! usbmon — read Linux usbmon's `u` text format and report what the kernel recorded.
//!
//! WHY THIS EXISTS. On Windows the only capture instrument was USBPcap, which is
//! IRP-level and provably cannot say what a device consumed (a *successful* OUT
//! transfer also completes with `dataLength = 0`). usbmon is the kernel's own
//! URB-level record: the submit line carries the setup packet, the callback line
//! carries the status and the transferred length. This crate reads that record
//! from a text file. It never opens a device, never links libusb, and never needs
//! root — the debugfs node is read by `tools/arlo/usbmon-capture.sh` under sudo,
//! and the resulting file is analysed here as an ordinary user.
//!
//! THE GRAMMAR IS THE KERNEL'S, NOT OURS. The layout implemented here is read off
//! `drivers/usb/mon/mon_text.c` (`mon_text_read_head_u`, `mon_text_read_statset`,
//! `mon_text_read_intstat`, `mon_text_read_data`), not guessed from samples:
//!
//! ```text
//! <tag> <timestamp-us> <S|C|E> <type><dir>:<bus>:<dev>:<ep> ...
//!     control/bulk S : " s <bm> <b> <wValue> <wIndex> <wLength>" <len> <datatag>
//!     control S, no setup packet captured: " Z __ __ ____ ____ ____" <len> <datatag>
//!     control/bulk C : <status> <len> <datatag>
//!     bulk/int S     : <status> <len> <datatag>          (status is always -115)
//!     interrupt      : <status>:<interval> <len> <datatag>
//!     E (error)      : <status> 0                        (always exactly these)
//!     datatag        : '<' IN submit | '>' OUT callback | Z/D data unavailable
//!                    | " =" then up to 32 bytes of data in 4-byte groups
//! ```
//!
//! TWO LIMITS OF THE INSTRUMENT ARE REPORTED, NEVER HIDDEN:
//!   * `DATA_MAX 32` — the text interface prints at most 32 bytes of data per
//!     line, so a 198-byte transfer shows 32 bytes. `printed_bytes < transferred`
//!     is normal and is stated as truncation, never as the payload.
//!   * A completion with no submit line means the capture is INCOMPLETE for that
//!     URB (the URB was submitted before the reader opened, or an event was lost
//!     from usbmon's ring). Real captures contain these — the E4 gold fixture has
//!     one — so it is a labelled boundary condition, excluded from paired
//!     analysis and counted in the header, never an error and never silent.
//!
//! WHAT A NUMBER HERE MEANS. Every value is read from the file, or arithmetic on
//! file values. It is a claim about *the capture*, never about the device beyond
//! what the kernel wrote down. Derivations (attempt grouping, elapsed-time wrap
//! correction, request naming) carry their own label so a modelled number never
//! wears a measured name.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufRead};
use std::path::Path;

use sha2::{Digest, Sha256};

pub const TOOL: &str = "usbmon";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA: u32 = 1;

/// `DATA_MAX` in `drivers/usb/mon/mon_text.c`. The kernel truncates displayed
/// data to this many bytes before we ever see it.
pub const KERNEL_DATA_MAX: usize = 32;

/// usbmon timestamps are `(tv_sec & 0xFFF) * 1e6 + tv_nsec / 1000` — unsigned
/// 32-bit microseconds that wrap every 4096 s. A backwards step is expected
/// exactly once per wrap; we say which of the two we saw instead of assuming.
pub const KERNEL_STAMP_WRAP_US: u64 = 4_096_000_000;

/// A usbmon line is a few hundred bytes. A longer *line* is not a usbmon line,
/// and the cap stops a corrupt or hostile file from making us allocate without
/// bound (a 10 GiB file with no newline must be an error, not an OOM).
pub const DEFAULT_MAX_LINE_BYTES: usize = 1 << 20;

// Exit codes. They are part of the contract: a gate script branches on them.
pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_IO: i32 = 3;
/// Structural errors: nothing in this file is trustworthy.
pub const EXIT_STRUCTURAL: i32 = 4;
/// Parsed clean but nothing matched — an empty file, or a filter that selected
/// nothing. This is the negative-control pass condition, and it is deliberately
/// NOT 0: "no URBs" must never look like success.
pub const EXIT_NO_URBS: i32 = 5;
/// `--strict` and the file carried warnings (including a boundary completion).
pub const EXIT_STRICT_WARNINGS: i32 = 6;
pub const EXIT_SHA_MISMATCH: i32 = 7;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    Submit,
    Complete,
    Error,
}

impl Event {
    pub fn ch(self) -> char {
        match self {
            Event::Submit => 'S',
            Event::Complete => 'C',
            Event::Error => 'E',
        }
    }
    /// True for the two event kinds that close a URB.
    pub fn closes_urb(self) -> bool {
        matches!(self, Event::Complete | Event::Error)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum XferType {
    Control,
    Bulk,
    Interrupt,
    Isoc,
}

impl XferType {
    pub fn ch(self) -> char {
        match self {
            XferType::Control => 'C',
            XferType::Bulk => 'B',
            XferType::Interrupt => 'I',
            XferType::Isoc => 'Z',
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            XferType::Control => "control",
            XferType::Bulk => "bulk",
            XferType::Interrupt => "interrupt",
            XferType::Isoc => "isochronous",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    In,
    Out,
}

impl Dir {
    pub fn ch(self) -> char {
        match self {
            Dir::In => 'i',
            Dir::Out => 'o',
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Dir::In => "IN",
            Dir::Out => "OUT",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Address {
    pub bus: u32,
    pub dev: u32,
    pub ep: u32,
}

impl fmt::Display for Address {
    /// usbmon prints `%d:%03u:%u`; we print the same so output lines can be
    /// pasted back next to the raw capture.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:03}:{}", self.bus, self.dev, self.ep)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Setup {
    pub bm_request_type: u8,
    pub b_request: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
}

impl Setup {
    pub fn dir(&self) -> Dir {
        if self.bm_request_type & 0x80 != 0 {
            Dir::In
        } else {
            Dir::Out
        }
    }
    /// bmRequestType bits 6:5 — 0 standard, 1 class, 2 vendor, 3 reserved.
    pub fn kind(&self) -> u8 {
        (self.bm_request_type >> 5) & 0x03
    }
    pub fn kind_name(&self) -> &'static str {
        match self.kind() {
            0 => "standard",
            1 => "class",
            2 => "vendor",
            _ => "reserved",
        }
    }
    /// bmRequestType bits 4:0.
    pub fn recipient(&self) -> u8 {
        self.bm_request_type & 0x1f
    }
    pub fn recipient_name(&self) -> &'static str {
        match self.recipient() {
            0 => "device",
            1 => "interface",
            2 => "endpoint",
            3 => "other",
            _ => "reserved",
        }
    }
    /// The five hex fields exactly as the kernel prints them.
    pub fn wire(&self) -> String {
        format!(
            "{:02x} {:02x} {:04x} {:04x} {:04x}",
            self.bm_request_type, self.b_request, self.w_value, self.w_index, self.w_length
        )
    }
}

#[derive(Clone, Debug)]
pub struct EventLine {
    pub line_no: u64,
    pub tag: u64,
    pub timestamp_us: u64,
    pub event: Event,
    pub xfer: XferType,
    pub dir: Dir,
    pub addr: Address,
    /// Completion/submit status. `None` on a control submit line, where the
    /// kernel prints the setup packet in this slot instead of a status.
    pub status: Option<i64>,
    /// Interrupt transfers print `status:interval`; the interval lands here.
    pub interval: Option<u32>,
    pub setup: Option<Setup>,
    /// `Some('Z')` when the kernel had a control submit but could not capture
    /// the setup packet (`Z __ __ ____ ____ ____`).
    pub setup_unavailable: Option<char>,
    /// Submit line: the URB's transfer_buffer_length. Callback: actual_length.
    pub length: u32,
    /// `<`, `>`, `Z`, `D`, or `=` (data follows). `None` when length == 0,
    /// because the kernel prints no data section at all for a zero-length
    /// transfer.
    pub data_flag: Option<char>,
    /// Exactly the bytes usbmon printed — at most [`KERNEL_DATA_MAX`].
    pub data: Vec<u8>,
    /// True when a hex field carried A-F in upper case. The kernel prints
    /// `%lx`/`%02x`/`%04x` (lower case), so this says "something rewrote this
    /// line between the kernel and this file" — a warning, never an error,
    /// because case does not change meaning.
    pub uppercase_hex: bool,
}

impl EventLine {
    /// True when the kernel printed data for this line (`=` section present).
    pub fn has_data(&self) -> bool {
        self.data_flag == Some('=')
    }
    /// The kernel truncates at DATA_MAX; say so instead of implying the payload.
    pub fn data_truncated(&self) -> bool {
        self.has_data() && (self.length as usize) > self.data.len()
    }
    /// True exactly when the 32-byte display cap explains the shortfall:
    /// the kernel prints min(length, DATA_MAX) bytes.
    pub fn data_capped_by_kernel(&self) -> bool {
        self.has_data() && self.data.len() == KERNEL_DATA_MAX && (self.length as usize) > KERNEL_DATA_MAX
    }
    /// Fewer bytes than `min(length, DATA_MAX)`. The 32-byte cap cannot explain
    /// this. `mon_text_get_data` clamps to the first scatter-gather segment's
    /// length for sg URBs, so it is possible on the wire — and it is also what a
    /// capture truncated at a group boundary looks like. Report it; do not call
    /// it truncation-by-the-cap.
    pub fn data_underprinted(&self) -> bool {
        self.has_data() && self.data.len() < (self.length as usize).min(KERNEL_DATA_MAX)
    }
}

/// One URB: its submit line and, if the file contains it, its callback.
#[derive(Clone, Debug)]
pub struct Transfer {
    pub tag: u64,
    pub addr: Address,
    pub xfer: XferType,
    pub dir: Dir,
    /// Index into [`Capture::events`].
    pub submit: usize,
    /// Index into [`Capture::events`]; `None` means the file has no completion
    /// for this URB — which is "not in this file", never "aborted".
    pub completion: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    /// Structurally impossible given the kernel's formatter: nothing in the file
    /// can be trusted.
    Error,
    /// Possible but notable: reported, counted, and escalated by `--strict`.
    Warning,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warning => "WARNING",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Problem {
    pub line_no: u64,
    pub severity: Severity,
    pub code: &'static str,
    pub detail: String,
    pub excerpt: String,
}

impl Problem {
    /// A completion whose submit is not in the file: the capture is incomplete
    /// for that URB. Real (the E4 gold fixture has one), so it is a warning —
    /// but it is always printed and always counted.
    pub fn is_boundary(&self) -> bool {
        self.code == "unmatched-completion"
    }
}

#[derive(Clone, Debug)]
pub struct AddrStat {
    pub events: u64,
    pub transfers: u64,
    pub first_ts: u64,
    pub last_ts: u64,
}

#[derive(Clone, Debug)]
pub struct Capture {
    pub bytes: u64,
    pub sha256: String,
    pub lines: u64,
    pub events: Vec<EventLine>,
    pub transfers: Vec<Transfer>,
    /// Indices into `events` of completions with no submit line in this file.
    pub unmatched_completions: Vec<usize>,
    /// The first [`MAX_LISTED_PROBLEMS`] problems. Counts stay exact even when
    /// the list is capped, so a 1 GB malformed file cannot OOM the tool while
    /// still reporting the true number of errors.
    pub problems: Vec<Problem>,
    pub error_count: u64,
    pub warning_count: u64,
    pub problems_not_listed: u64,
}

/// A malformed capture can produce one problem per line. Listing all of them
/// costs ~200 bytes each; the count and the exit code stay exact, and the report
/// says how many were not listed.
pub const MAX_LISTED_PROBLEMS: usize = 1000;

impl Capture {
    fn push_problem(&mut self, p: Problem) {
        match p.severity {
            Severity::Error => self.error_count += 1,
            Severity::Warning => self.warning_count += 1,
        }
        if self.problems.len() < MAX_LISTED_PROBLEMS {
            self.problems.push(p);
        } else {
            self.problems_not_listed += 1;
        }
    }
    pub fn errors(&self) -> usize {
        self.error_count as usize
    }
    pub fn warnings(&self) -> usize {
        self.warning_count as usize
    }
    pub fn status_of(&self, t: &Transfer) -> Option<i64> {
        t.completion.map(|i| self.events[i].status.unwrap_or(0))
    }
    /// Signed submit→callback delta in microseconds. Negative values are
    /// reported as negative: the only legitimate cause is the 4096 s stamp wrap,
    /// and the renderer says which reading it used.
    pub fn elapsed_us(&self, t: &Transfer) -> Option<i64> {
        t.completion
            .map(|i| self.events[i].timestamp_us as i64 - self.events[t.submit].timestamp_us as i64)
    }
    pub fn setup_of(&self, t: &Transfer) -> Option<Setup> {
        self.events[t.submit].setup
    }
}

// ---------------------------------------------------------------------------
// Line reading (bounded)
// ---------------------------------------------------------------------------

enum NextLine {
    Eof,
    Line,
    TooLong,
    /// A line with no newline that exceeded the drain cap: not a usbmon file,
    /// and reading on would never end (a live pipe or /dev/zero).
    Unterminated,
}

/// How much of an over-long line is drained before giving up. A usbmon line is
/// a few hundred bytes; this only exists so a reader can never hang, and it is
/// scaled to the caller's per-line cap so `--max-line-bytes 100` cannot read 64
/// MiB of /dev/zero before saying no.
fn drain_cap_for(line_cap: usize) -> u64 {
    (line_cap as u64).saturating_mul(16).clamp(1 << 20, 64 << 20)
}

/// Read one line into `buf` (newline stripped), or report that the line is
/// longer than `cap` — in which case the rest of that line is drained without
/// being stored, so memory stays bounded no matter what the file contains.
fn next_line<R: BufRead>(
    r: &mut R,
    buf: &mut Vec<u8>,
    cap: usize,
    hasher: &mut Sha256,
    bytes: &mut u64,
) -> io::Result<NextLine> {
    buf.clear();
    let mut too_long = false;
    let mut drained: u64 = 0;
    loop {
        let avail = r.fill_buf()?;
        if avail.is_empty() {
            return Ok(if too_long {
                NextLine::TooLong
            } else if buf.is_empty() {
                NextLine::Eof
            } else {
                NextLine::Line
            });
        }
        let nl = avail.iter().position(|&b| b == b'\n');
        let take = nl.map(|i| i + 1).unwrap_or(avail.len());
        hasher.update(&avail[..take]);
        *bytes += take as u64;
        if !too_long {
            if buf.len() + take <= cap {
                buf.extend_from_slice(&avail[..take]);
            } else {
                too_long = true;
                buf.clear();
            }
        } else {
            drained += take as u64;
            if drained > drain_cap_for(cap) {
                return Ok(NextLine::Unterminated);
            }
        }
        r.consume(take);
        if nl.is_some() {
            if too_long {
                return Ok(NextLine::TooLong);
            }
            if buf.last() == Some(&b'\n') {
                buf.pop();
            }
            return Ok(NextLine::Line);
        }
    }
}

// ---------------------------------------------------------------------------
// Token/text helpers
// ---------------------------------------------------------------------------

pub struct ParseErr {
    pub code: &'static str,
    pub detail: String,
}

fn err(code: &'static str, detail: impl Into<String>) -> ParseErr {
    ParseErr {
        code,
        detail: detail.into(),
    }
}

/// A short, printable, unambiguous preview of a raw line: ASCII printable kept,
/// everything else escaped, capped so a garbage line cannot flood the report.
pub fn excerpt(raw: &[u8]) -> String {
    let mut s = String::new();
    for &b in raw.iter().take(160) {
        match b {
            0x20..=0x7e => s.push(b as char),
            b'\t' => s.push_str("\\t"),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    if raw.len() > 160 {
        s.push_str("...");
    }
    s
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn parse_hex_exact(s: &str, digits: usize, what: &str) -> Result<u64, ParseErr> {
    if s.len() != digits || !is_hex(s) {
        return Err(err(
            "malformed-field",
            format!("{what} must be exactly {digits} hex digits, saw {s:?}"),
        ));
    }
    u64::from_str_radix(s, 16)
        .map_err(|e| err("malformed-field", format!("{what} {s:?} is not hex: {e}")))
}

fn parse_dec(s: &str, what: &str) -> Result<u64, ParseErr> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err(
            "malformed-field",
            format!("{what} must be an unsigned decimal number, saw {s:?}"),
        ));
    }
    s.parse::<u64>()
        .map_err(|e| err("malformed-field", format!("{what} {s:?} overflows: {e}")))
}

fn parse_signed(s: &str, what: &str) -> Result<i64, ParseErr> {
    s.parse::<i64>()
        .map_err(|e| err("malformed-field", format!("{what} must be a signed decimal, saw {s:?}: {e}")))
}

/// A URB status is an errno: 0 or negative. The kernel prints it with `%d`, so a
/// positive value is not producible and must not be absorbed as "some status".
fn parse_urb_status(s: &str, what: &str) -> Result<i64, ParseErr> {
    let v = parse_signed(s, what)?;
    if v > 0 {
        return Err(err(
            "bad-status",
            format!("{what} {v} is positive; a URB status is 0 or a negative errno"),
        ));
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// Parse one usbmon `u` line. Every rejection is one of the kernel formatter's
/// invariants, not a style preference: see the module docs for the source.
pub fn parse_line(line_no: u64, raw_text: &str) -> Result<EventLine, ParseErr> {
    let tokens: Vec<&str> = raw_text.split(' ').collect();
    if tokens.iter().any(|t| t.is_empty()) {
        return Err(err(
            "empty-field",
            "empty field: usbmon separates fields with exactly one space (double space or \
             leading/trailing space)",
        ));
    }
    if tokens.len() < 5 {
        return Err(err(
            "malformed-field",
            format!("expected at least 5 fields, saw {}", tokens.len()),
        ));
    }

    let mut uppercase_hex = false;
    let tag = {
        let t = tokens[0];
        if t.len() > 16 || !is_hex(t) {
            return Err(err(
                "bad-tag",
                format!("URB tag {t:?} is not 1..=16 hex digits (kernel prints %lx)"),
            ));
        }
        mark_upper(&mut uppercase_hex, t);
        u64::from_str_radix(t, 16).expect("is_hex checked")
    };
    let timestamp_us = parse_dec(tokens[1], "timestamp")?;
    if timestamp_us > u32::MAX as u64 {
        return Err(err(
            "bad-timestamp",
            format!("timestamp {timestamp_us} does not fit the kernel's unsigned int stamp"),
        ));
    }
    let event = match tokens[2] {
        "S" => Event::Submit,
        "C" => Event::Complete,
        "E" => Event::Error,
        other => {
            return Err(err(
                "unknown-event",
                format!("event field {other:?} is not S, C or E"),
            ))
        }
    };
    let (xfer, dir, addr) = parse_address(tokens[3])?;

    let mut ev = EventLine {
        line_no,
        tag,
        timestamp_us,
        event,
        xfer,
        dir,
        addr,
        status: None,
        interval: None,
        setup: None,
        setup_unavailable: None,
        length: 0,
        data_flag: None,
        data: Vec::new(),
        uppercase_hex: false,
    };

    if xfer == XferType::Isoc {
        // The isochronous layout is a different format (`%d:%d:%d` plus up to 5
        // descriptor triples). Refusing loudly beats mis-reading it as control.
        return Err(err(
            "iso-unsupported",
            "isochronous URB: usbmon's `u` isochronous layout is not the control/bulk \
             layout and this tool does not parse it",
        ));
    }

    let rest = &tokens[4..];
    let used = match event {
        Event::Error => parse_error_event(&mut ev, rest)?,
        _ => match xfer {
            XferType::Control => parse_control(&mut ev, rest, &mut uppercase_hex)?,
            XferType::Interrupt => parse_interrupt(&mut ev, rest, &mut uppercase_hex)?,
            XferType::Bulk => parse_bulk(&mut ev, rest, &mut uppercase_hex)?,
            XferType::Isoc => unreachable!("rejected above"),
        },
    };
    if used != rest.len() {
        return Err(err(
            "trailing-token",
            format!(
                "{} unexpected token(s) after the fields this line's kind defines: {:?}",
                rest.len() - used,
                &rest[used..]
            ),
        ));
    }
    ev.uppercase_hex = uppercase_hex;
    Ok(ev)
}

/// `%c%c:%d:%03u:%u` on the `u` node: type, direction, bus, device, endpoint.
fn parse_address(tok: &str) -> Result<(XferType, Dir, Address), ParseErr> {
    let parts: Vec<&str> = tok.split(':').collect();
    if parts.len() == 3 {
        return Err(err(
            "t-node-format",
            format!(
                "address {tok:?} has no bus field: this is the `t` node format. This tool reads \
                 the `u` node (/sys/kernel/debug/usb/usbmon/<bus>u)"
            ),
        ));
    }
    if parts.len() != 4 {
        return Err(err(
            "bad-address",
            format!("address {tok:?} is not <type><dir>:<bus>:<dev>:<ep>"),
        ));
    }
    let td = parts[0].as_bytes();
    if td.len() != 2 {
        return Err(err(
            "bad-address",
            format!("address type field {:?} is not two characters", parts[0]),
        ));
    }
    let xfer = match td[0] {
        b'C' => XferType::Control,
        b'B' => XferType::Bulk,
        b'I' => XferType::Interrupt,
        b'Z' => XferType::Isoc,
        other => {
            return Err(err(
                "unknown-xfer-type",
                format!("transfer type {:?} is not one of C, B, I, Z", other as char),
            ))
        }
    };
    let dir = match td[1] {
        b'i' => Dir::In,
        b'o' => Dir::Out,
        other => {
            return Err(err(
                "bad-address",
                format!("direction {:?} is not i or o", other as char),
            ))
        }
    };
    // busnum is printed with %d, so its width is not fixed; only the device
    // number has a guaranteed shape (%03u).
    let bus = parse_dec(parts[1], "bus number")?;
    if bus > u32::MAX as u64 {
        return Err(err("bad-address", format!("bus number {bus} out of range")));
    }
    // devnum is printed with %03u; %03u means "at least three digits", so a
    // genuine line is exactly 3 digits for every device number USB allows.
    if parts[2].len() != 3 {
        return Err(err(
            "bad-address",
            format!(
                "device number {:?} is not three digits: the kernel prints it with %03u",
                parts[2]
            ),
        ));
    }
    let dev = parse_dec(parts[2], "device number")?;
    let ep = parse_dec(parts[3], "endpoint number")?;
    if ep > 255 {
        return Err(err("bad-address", format!("endpoint {ep} out of range")));
    }
    Ok((
        xfer,
        dir,
        Address {
            bus: bus as u32,
            dev: dev as u32,
            ep: ep as u32,
        },
    ))
}

/// `E <status> 0` — mon_text_error sets length 0 and no setup; this is the whole
/// line, always.
fn parse_error_event(ev: &mut EventLine, rest: &[&str]) -> Result<usize, ParseErr> {
    if rest.len() < 2 {
        return Err(err(
            "malformed-field",
            "E line needs <status> <length>",
        ));
    }
    ev.status = Some(parse_urb_status(rest[0], "error status")?);
    let len = parse_u32(rest[1], "length")?;
    if len != 0 {
        return Err(err(
            "e-event-length",
            format!("E event carries length {len}; the kernel sets 0 for every E event"),
        ));
    }
    ev.length = 0;
    Ok(2)
}

fn parse_u32(s: &str, what: &str) -> Result<u32, ParseErr> {
    let v = parse_dec(s, what)?;
    if v > u32::MAX as u64 {
        return Err(err(
            "bad-length",
            format!("{what} {v} does not fit an unsigned int"),
        ));
    }
    Ok(v as u32)
}

fn mark_upper(upper: &mut bool, t: &str) {
    if t.bytes().any(|b| b.is_ascii_uppercase()) {
        *upper = true;
    }
}

fn parse_control(ev: &mut EventLine, rest: &[&str], upper: &mut bool) -> Result<usize, ParseErr> {
    let mut used: usize;
    match ev.event {
        Event::Submit => {
            if rest.is_empty() {
                return Err(err("malformed-field", "control submit line ends after the address"));
            }
            if rest[0] == "s" {
                if rest.len() < 6 {
                    return Err(err(
                        "truncated-line",
                        "control submit with `s` needs five setup fields after it",
                    ));
                }
                for t in &rest[1..6] {
                    mark_upper(upper, t);
                }
                ev.setup = Some(Setup {
                    bm_request_type: parse_hex_exact(rest[1], 2, "bmRequestType")? as u8,
                    b_request: parse_hex_exact(rest[2], 2, "bRequest")? as u8,
                    w_value: parse_hex_exact(rest[3], 4, "wValue")? as u16,
                    w_index: parse_hex_exact(rest[4], 4, "wIndex")? as u16,
                    w_length: parse_hex_exact(rest[5], 4, "wLength")? as u16,
                });
                used = 6;
            } else if rest[0].len() == 1 && rest.len() >= 6 && rest[1..6] == ["__", "__", "____", "____", "____"] {
                let flag = rest[0].chars().next().expect("len 1");
                if flag != 'Z' {
                    return Err(err(
                        "bad-setup-flag",
                        format!(
                            "setup placeholder flag {flag:?}: mon_text_get_setup only emits `s` \
                             or `Z` (setup_packet == NULL)"
                        ),
                    ));
                }
                ev.setup_unavailable = Some(flag);
                used = 6;
            } else {
                return Err(err(
                    "setup-missing-on-submit",
                    format!(
                        "control submit line without a setup packet: the kernel always prints \
                         either `s <5 fields>` or `Z __ __ ____ ____ ____`, saw {:?}",
                        rest[0]
                    ),
                ));
            }
        }
        _ => {
            if rest.is_empty() {
                return Err(err("truncated-line", "callback line ends after the address"));
            }
            // A setup packet can only appear on a submit line.
            if rest[0] == "s" {
                return Err(err(
                    "setup-on-callback",
                    "callback line carries a setup packet; mon_text_get_setup only emits it for S",
                ));
            }
            ev.status = Some(parse_urb_status(rest[0], "completion status")?);
            used = 1;
        }
    }
    used += parse_length_and_data(ev, &rest[used..], upper)?;
    Ok(used)
}

fn parse_bulk(ev: &mut EventLine, rest: &[&str], upper: &mut bool) -> Result<usize, ParseErr> {
    if rest.is_empty() {
        return Err(err("truncated-line", "bulk line ends after the address"));
    }
    ev.status = Some(parse_urb_status(rest[0], "status")?);
    Ok(1 + parse_length_and_data(ev, &rest[1..], upper)?)
}

fn parse_interrupt(ev: &mut EventLine, rest: &[&str], upper: &mut bool) -> Result<usize, ParseErr> {
    if rest.is_empty() {
        return Err(err("truncated-line", "interrupt line ends after the address"));
    }
    // `%d:%d` — status:interval.
    let (st, iv) = match rest[0].split_once(':') {
        Some((a, b)) => (a, b),
        None => {
            return Err(err(
                "malformed-field",
                format!(
                    "interrupt status field {:?} is not <status>:<interval> (mon_text_read_intstat)",
                    rest[0]
                ),
            ))
        }
    };
    ev.status = Some(parse_urb_status(st, "interrupt status")?);
    ev.interval = Some(parse_u32(iv, "interrupt interval")?);
    Ok(1 + parse_length_and_data(ev, &rest[1..], upper)?)
}

/// `<len>` then the data section, for every non-E line.
///
/// The kernel prints a data section only when `length > 0`, and then it always
/// prints a tag: `<` or `>` when there is nothing to show, `Z`/`D` when the
/// buffer was unavailable, or `=` plus up to DATA_MAX bytes.
fn parse_length_and_data(
    ev: &mut EventLine,
    rest: &[&str],
    upper: &mut bool,
) -> Result<usize, ParseErr> {
    if rest.is_empty() {
        return Err(err(
            "truncated-line",
            "line ends before the length field",
        ));
    }
    ev.length = parse_u32(rest[0], "length")?;
    let mut used = 1usize;
    if ev.length == 0 {
        if rest.len() > 1 {
            return Err(err(
                "data-tag-on-empty-length",
                format!(
                    "length is 0 but the line continues with {:?}: mon_text_read_data prints \
                     nothing at all for a zero-length transfer",
                    rest[1]
                ),
            ));
        }
        return Ok(used);
    }
    if rest.len() < 2 {
        return Err(err(
            "data-tag-missing",
            format!(
                "length is {} but the line ends: every nonzero length carries a data tag \
                 (`<`, `>`, `Z`, `D`, or `=` plus bytes)",
                ev.length
            ),
        ));
    }
    let flag_tok = rest[1];
    if flag_tok.len() != 1 {
        return Err(err(
            "bad-data-tag",
            format!("data tag {flag_tok:?} is not a single character"),
        ));
    }
    let flag = flag_tok.chars().next().expect("len 1");
    used += 1;
    match flag {
        '<' => {
            require(
                ev.dir == Dir::In && ev.event == Event::Submit,
                "bad-data-tag",
                format!(
                    "data tag `<` means 'IN submit has no data yet'; this line is {} {}",
                    ev.dir.name(),
                    ev.event.ch()
                ),
            )?;
            ev.data_flag = Some('<');
        }
        '>' => {
            require(
                ev.dir == Dir::Out && ev.event == Event::Complete,
                "bad-data-tag",
                format!(
                    "data tag `>` means 'OUT callback carries no data'; this line is {} {}",
                    ev.dir.name(),
                    ev.event.ch()
                ),
            )?;
            ev.data_flag = Some('>');
        }
        'Z' | 'D' => {
            // Unavailable buffer: mon_text_get_data reaches this only after the
            // direction/event checks above, i.e. OUT submit or IN callback.
            require(
                (ev.dir == Dir::Out && ev.event == Event::Submit)
                    || (ev.dir == Dir::In && ev.event == Event::Complete),
                "bad-data-tag",
                format!(
                    "data tag `{flag}` means 'data unavailable' and can only appear where data \
                     is expected (OUT submit / IN callback), not on {} {}",
                    ev.dir.name(),
                    ev.event.ch()
                ),
            )?;
            ev.data_flag = Some(flag);
        }
        '=' => {
            require(
                (ev.dir == Dir::In && ev.event == Event::Complete)
                    || (ev.dir == Dir::Out && ev.event == Event::Submit),
                "bad-data-tag",
                format!(
                    "data tag `=` means captured bytes and can only appear where the kernel \
                     captures them (IN callback / OUT submit), not on {} {}",
                    ev.dir.name(),
                    ev.event.ch()
                ),
            )?;
            for t in &rest[2..] {
                mark_upper(upper, t);
            }
            let (bytes, consumed) = parse_data_groups(&rest[2..])?;
            if bytes.len() > KERNEL_DATA_MAX {
                return Err(err(
                    "data-too-large",
                    format!(
                        "{} data bytes printed: usbmon's text interface copies at most DATA_MAX \
                         = {KERNEL_DATA_MAX} bytes per line (mon_text.c)",
                        bytes.len()
                    ),
                ));
            }
            if bytes.len() as u32 > ev.length {
                return Err(err(
                    "data-exceeds-length",
                    format!(
                        "{} data bytes printed but the declared length is {}",
                        bytes.len(),
                        ev.length
                    ),
                ));
            }
            ev.data_flag = Some('=');
            ev.data = bytes;
            used += consumed;
        }
        other => {
            return Err(err(
                "bad-data-tag",
                format!(
                    "unknown data tag {other:?}: the kernel emits `<`, `>`, `Z`, `D` or `=` \
                     followed by hex bytes"
                ),
            ))
        }
    }
    Ok(used)
}

fn require(cond: bool, code: &'static str, detail: String) -> Result<(), ParseErr> {
    if cond {
        Ok(())
    } else {
        Err(err(code, detail))
    }
}

/// `=` data: groups of 4 bytes separated by single spaces; the kernel emits a
/// space before every group, so a final partial group may be 1..=3 bytes.
fn parse_data_groups(tokens: &[&str]) -> Result<(Vec<u8>, usize), ParseErr> {
    if tokens.is_empty() {
        return Err(err(
            "bad-data-group",
            "`=` with no bytes after it: the kernel prints at least one byte",
        ));
    }
    let mut out = Vec::new();
    let last = tokens.len() - 1;
    for (i, t) in tokens.iter().enumerate() {
        if t.len() % 2 != 0 || t.is_empty() || !is_hex(t) {
            return Err(err(
                "bad-data-group",
                format!("data group {t:?} is not an even-length run of hex digits"),
            ));
        }
        let bytes = t.len() / 2;
        if bytes > 4 {
            return Err(err(
                "bad-data-group",
                format!("data group {t:?} is {bytes} bytes; the kernel emits groups of 4"),
            ));
        }
        if i != last && bytes != 4 {
            return Err(err(
                "bad-data-group",
                format!("data group {t:?} is short but is not the last group"),
            ));
        }
        for k in 0..bytes {
            out.push(u8::from_str_radix(&t[k * 2..k * 2 + 2], 16).expect("is_hex checked"));
        }
    }
    Ok((out, tokens.len()))
}

// ---------------------------------------------------------------------------
// Whole-file parse
// ---------------------------------------------------------------------------

pub fn parse_reader<R: BufRead>(mut r: R, max_line_bytes: usize) -> io::Result<Capture> {
    let mut hasher = Sha256::new();
    let mut bytes: u64 = 0;
    let mut buf: Vec<u8> = Vec::new();
    let mut cap = Capture {
        bytes: 0,
        sha256: String::new(),
        lines: 0,
        events: Vec::new(),
        transfers: Vec::new(),
        unmatched_completions: Vec::new(),
        problems: Vec::new(),
        error_count: 0,
        warning_count: 0,
        problems_not_listed: 0,
    };
    // tag -> index into cap.events of the open submit line.
    let mut open: BTreeMap<u64, usize> = BTreeMap::new();
    let mut line_no: u64 = 0;
    loop {
        match next_line(&mut r, &mut buf, max_line_bytes, &mut hasher, &mut bytes)? {
            NextLine::Eof => break,
            NextLine::TooLong => {
                line_no += 1;
                cap.lines += 1;
                cap.push_problem(Problem {
                    line_no,
                    severity: Severity::Error,
                    code: "line-too-long",
                    detail: format!(
                        "line exceeds the {max_line_bytes} byte cap; a usbmon line is a few \
                         hundred bytes, so this is not usbmon output"
                    ),
                    excerpt: String::new(),
                });
            }
            NextLine::Line => {
                line_no += 1;
                cap.lines += 1;
                process_line(&mut cap, &mut open, line_no, &buf);
            }
            NextLine::Unterminated => {
                line_no += 1;
                cap.lines += 1;
                cap.push_problem(Problem {
                    line_no,
                    severity: Severity::Error,
                    code: "line-unterminated",
                    detail: format!(
                        "line has no newline and exceeds {} bytes; this is not a usbmon file. \
                         Stopped reading instead of draining an unbounded stream.",
                        drain_cap_for(max_line_bytes)
                    ),
                    excerpt: String::new(),
                });
                break;
            }
        }
    }
    cap.bytes = bytes;
    cap.sha256 = hex_lower(&hasher.finalize());
    Ok(cap)
}

pub fn parse_path(path: &Path, max_line_bytes: usize) -> io::Result<Capture> {
    let f = std::fs::File::open(path)?;
    parse_reader(io::BufReader::new(f), max_line_bytes)
}

fn process_line(cap: &mut Capture, open: &mut BTreeMap<u64, usize>, line_no: u64, raw: &[u8]) {
    let mut raw = raw;
    if raw.last() == Some(&b'\r') {
        // Tolerated: a capture that travelled through a CRLF host is still the
        // same capture. Noted nowhere because it changes no value.
        raw = &raw[..raw.len() - 1];
    }
    if raw.is_empty() {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Error,
            code: "empty-line",
            detail: "empty line: usbmon writes one event per line and never a blank one".into(),
            excerpt: String::new(),
        });
        return;
    }
    if !raw.is_ascii() {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Error,
            code: "non-ascii-line",
            detail: "line contains a byte above 0x7f; usbmon output is ASCII".into(),
            excerpt: excerpt(raw),
        });
        return;
    }
    let text = std::str::from_utf8(raw).expect("ascii is utf8");
    let ev = match parse_line(line_no, text) {
        Ok(ev) => ev,
        Err(e) => {
            cap.push_problem(Problem {
                line_no,
                severity: Severity::Error,
                code: e.code,
                detail: e.detail,
                excerpt: excerpt(raw),
            });
            return;
        }
    };

    let idx = cap.events.len();
    cap.events.push(ev);
    // From here on the pushed copy is the record: pairing validates against
    // `events`, so the completion must already be in the vector.
    let ev = cap.events[idx].clone();
    if ev.data_underprinted() {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Warning,
            code: "data-underprinted",
            detail: format!(
                "{} data byte(s) printed for a declared length of {}: the kernel prints exactly \
                 min(length, DATA_MAX={KERNEL_DATA_MAX}), so the 32-byte display cap cannot \
                 explain this. A short first scatter-gather segment can (mon_text_get_data clamps \
                 to sg->length); so can a capture truncated at a data-group boundary.",
                ev.data.len(),
                ev.length
            ),
            excerpt: excerpt(raw),
        });
    }
    if ev.uppercase_hex {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Warning,
            code: "uppercase-hex",
            detail: "a hex field uses A-F in upper case; the kernel prints %lx/%02x/%04x in                      lower case, so something rewrote this line between the kernel and this file"
                .into(),
            excerpt: excerpt(raw),
        });
    }
    if ev.event == Event::Submit {
        // Checked here rather than at pairing time: a submit whose callback is
        // not in the file must still be flagged.
        if ev.xfer != XferType::Control && ev.status != Some(-115) {
            cap.push_problem(Problem {
                line_no,
                severity: Severity::Warning,
                code: "submit-status-not-einprogress",
                detail: format!(
                    "non-control submit line carries status {:?}: mon_text_submit always stamps \
                     -EINPROGRESS (-115)",
                    ev.status
                ),
                excerpt: excerpt(raw),
            });
        }
        if open.insert(ev.tag, idx).is_some() {
            cap.push_problem(Problem {
                line_no,
                severity: Severity::Error,
                code: "duplicate-submit",
                detail: format!(
                    "tag {:x} is already submitted and has not completed: a URB's memory cannot \
                     be reused while the HCD owns it",
                    ev.tag
                ),
                excerpt: excerpt(raw),
            });
        }
        cap.transfers.push(Transfer {
            tag: ev.tag,
            addr: ev.addr,
            xfer: ev.xfer,
            dir: ev.dir,
            submit: idx,
            completion: None,
        });
    } else {
        match open.remove(&ev.tag) {
            Some(sub_idx) => {
                validate_pair(cap, sub_idx, idx, line_no);
                if let Some(t) = cap
                    .transfers
                    .iter_mut()
                    .rev()
                    .find(|t| t.submit == sub_idx)
                {
                    t.completion = Some(idx);
                } else {
                    // Cannot happen: every open tag came from a transfer.
                    cap.push_problem(Problem {
                        line_no,
                        severity: Severity::Error,
                        code: "internal-pairing",
                        detail: "completion matched a submit with no transfer record".into(),
                        excerpt: excerpt(raw),
                    });
                }
            }
            None => {
                cap.unmatched_completions.push(idx);
                cap.push_problem(Problem {
                    line_no,
                    severity: Severity::Warning,
                    code: "unmatched-completion",
                    detail: format!(
                        "completion for tag {:x} has no submit line in this file: the capture is \
                         incomplete for this URB (submitted before the reader opened, or an event \
                         was lost from usbmon's ring). Excluded from paired analysis; its data is \
                         still reported.",
                        ev.tag
                    ),
                    excerpt: excerpt(raw),
                });
            }
        }
    }
}

fn validate_pair(cap: &mut Capture, sub: usize, comp: usize, line_no: u64) {
    let s = cap.events[sub].clone();
    let c = cap.events[comp].clone();
    if s.addr != c.addr || s.xfer != c.xfer || s.dir != c.dir {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Error,
            code: "completion-attrs-mismatch",
            detail: format!(
                "callback {:?} {}:{} does not match its submit {:?} {}:{}",
                c.addr,
                c.xfer.name(),
                c.dir.name(),
                s.addr,
                s.xfer.name(),
                s.dir.name()
            ),
            excerpt: String::new(),
        });
    }
    if c.length > s.length {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Error,
            code: "transferred-exceeds-requested",
            detail: format!(
                "callback reports {} bytes transferred but the submit asked for {}: actual_length \
                 can never exceed transfer_buffer_length",
                c.length, s.length
            ),
            excerpt: String::new(),
        });
    }
    if let Some(st) = s.setup {
        if st.w_length as u32 != s.length {
            cap.push_problem(Problem {
                line_no,
                severity: Severity::Warning,
                code: "wlength-vs-buffer-length",
                detail: format!(
                    "submit line: setup wLength 0x{:04x} ({}) but transfer_buffer_length {} — \
                     usb_control_msg normally makes these equal, so a reader should check what \
                     built this URB",
                    st.w_length, st.w_length, s.length
                ),
                excerpt: String::new(),
            });
        }
    } else if s.xfer != XferType::Control && s.status != Some(-115) {
        // handled at submit time in process_line; kept out of pairing so a
        // pending submit is covered too.
    }
    if c.timestamp_us < s.timestamp_us {
        cap.push_problem(Problem {
            line_no,
            severity: Severity::Warning,
            code: "timestamp-backwards",
            detail: format!(
                "callback stamp {} is before its submit stamp {} (delta {} us). usbmon stamps \
                 are 32-bit microseconds that wrap every 4096 s; anything else is a clock step \
                 or a reassembled file",
                c.timestamp_us,
                s.timestamp_us,
                c.timestamp_us as i64 - s.timestamp_us as i64
            ),
            excerpt: String::new(),
        });
    }
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Per-address event counts, ordered by first appearance (then address), so a
/// reader can see re-enumeration (1:005 -> 1:006 -> 1:007) without guessing.
pub fn address_stats(cap: &Capture) -> Vec<(Address, AddrStat)> {
    let mut map: BTreeMap<Address, AddrStat> = BTreeMap::new();
    for ev in &cap.events {
        let e = map.entry(ev.addr).or_insert(AddrStat {
            events: 0,
            transfers: 0,
            first_ts: ev.timestamp_us,
            last_ts: ev.timestamp_us,
        });
        e.events += 1;
        e.first_ts = e.first_ts.min(ev.timestamp_us);
        e.last_ts = e.last_ts.max(ev.timestamp_us);
    }
    for t in &cap.transfers {
        if let Some(e) = map.get_mut(&t.addr) {
            e.transfers += 1;
        }
    }
    let mut v: Vec<(Address, AddrStat)> = map.into_iter().collect();
    v.sort_by_key(|(a, s)| (s.first_ts, *a));
    v
}

// ---------------------------------------------------------------------------
// Status and request naming (tables, not guesses)
// ---------------------------------------------------------------------------

/// Linux errno for the codes usbmon actually prints. Names come from errno(3);
/// the USB *meaning* is a separate note so the two are never conflated.
pub fn errno_name(code: i64) -> Option<&'static str> {
    Some(match code {
        0 => "OK",
        -1 => "EPERM",
        -2 => "ENOENT",
        -5 => "EIO",
        -19 => "ENODEV",
        -22 => "EINVAL",
        -28 => "ENOSPC",
        -32 => "EPIPE",
        -62 => "ETIME",
        -71 => "EPROTO",
        -75 => "EOVERFLOW",
        -84 => "EILSEQ",
        -104 => "ECONNRESET",
        -108 => "ESHUTDOWN",
        -110 => "ETIMEDOUT",
        -113 => "EHOSTUNREACH",
        -115 => "EINPROGRESS",
        -121 => "EREMOTEIO",
        _ => return None,
    })
}

/// What the code means on a USB transfer. Deliberately not "STALL" for every
/// negative number: -32 EPIPE is how a device STALL reaches this host on a
/// control transfer; -71 EPROTO is a transaction/protocol error and is NOT the
/// same errno as -121 EREMOTEIO.
pub fn status_note(code: i64) -> Option<&'static str> {
    Some(match code {
        0 => "transfer completed; a nonzero transferred length is what the device accepted",
        -2 => "URB unlinked: cancelled by the caller (cancel/close) or the device went away",
        -32 => "STALL: the endpoint halted the transfer",
        -71 => "EPROTO: protocol/transaction error (babble, bad PID/CRC, response outside the transfer); not EREMOTEIO",
        -104 => "ECONNRESET: endpoint reset",
        -108 => "ESHUTDOWN: host controller or device shutting down",
        -110 => "ETIMEDOUT: the host gave up waiting",
        -115 => "EINPROGRESS: stamped by the kernel on every submit line, not a device result",
        -121 => "EREMOTEIO: remote I/O error; also a short control read when URB_SHORT_NOT_OK is set",
        _ => return None,
    })
}

pub fn status_label(code: i64) -> String {
    match errno_name(code) {
        Some(n) => format!("{code} {n}"),
        None => format!("{code} (unknown errno)"),
    }
}

/// Standard request names (USB 2.0 table 9.4) and DFU class names (DFU 1.1
/// table 3). Which table applies is decided by bmRequestType bits 6:5, so
/// GET_DESCRIPTOR(6) and DFU_ABORT(6) are never confused.
pub fn request_name(s: &Setup) -> &'static str {
    match s.kind() {
        0 => match s.b_request {
            0 => "GET_STATUS",
            1 => "CLEAR_FEATURE",
            2 => "RESERVED_2",
            3 => "SET_FEATURE",
            4 => "RESERVED_4",
            5 => "SET_ADDRESS",
            6 => "GET_DESCRIPTOR",
            7 => "SET_DESCRIPTOR",
            8 => "GET_CONFIGURATION",
            9 => "SET_CONFIGURATION",
            10 => "GET_INTERFACE",
            11 => "SET_INTERFACE",
            12 => "SYNCH_FRAME",
            _ => "STANDARD_RESERVED",
        },
        1 => {
            // DFU is an interface/device class: naming request 1 "DFU_DNLOAD" on
            // a recipient-3 (other) request would be a guess, so only device and
            // interface recipients get the DFU table.
            if s.recipient() <= 1 {
                match s.b_request {
                    0 => "DFU_DETACH",
                    1 => "DFU_DNLOAD",
                    2 => "DFU_UPLOAD",
                    3 => "DFU_GETSTATUS",
                    4 => "DFU_CLRSTATUS",
                    5 => "DFU_GETSTATE",
                    6 => "DFU_ABORT",
                    _ => "DFU_UNKNOWN",
                }
            } else {
                "CLASS_REQ"
            }
        }
        2 => "VENDOR_REQ",
        _ => "RESERVED_REQ",
    }
}

pub fn request_label(s: &Setup) -> String {
    format!("{}({})", request_name(s), s.b_request)
}

/// The direction USB 2.0 defines for a standard request, when it defines one.
pub fn standard_expected_dir(b_request: u8) -> Option<Dir> {
    match b_request {
        0 | 6 | 8 | 10 | 12 => Some(Dir::In),
        1 | 3 | 5 | 7 | 9 | 11 => Some(Dir::Out),
        _ => None,
    }
}

/// A factual note when a standard request is sent in a direction the spec does
/// not define — e.g. gaster's pad request is `bm=0x00 b=0`, a GET_STATUS with
/// the direction bit clear. The note states the mismatch; it does not assume
/// intent.
pub fn standard_dir_note(s: &Setup) -> Option<String> {
    if s.kind() != 0 {
        return None;
    }
    let expected = standard_expected_dir(s.b_request)?;
    if s.dir() == expected {
        return None;
    }
    Some(format!(
        "standard {} is defined {}-only; this request is {}",
        request_name(s),
        expected.name(),
        s.dir().name()
    ))
}

/// Human-readable GET_DESCRIPTOR target: descriptor type, index, and (for
/// STRING) the language id.
pub fn descriptor_target(w_value: u16, w_index: u16) -> String {
    let dtype = (w_value >> 8) as u8;
    let index = (w_value & 0xff) as u8;
    let tname = descriptor_type_name(dtype);
    if dtype == 3 {
        if w_index == 0 {
            format!("STRING(3) idx={index} (language-id list)")
        } else {
            format!(
                "STRING(3) idx={index} lang=0x{w_index:04x}{}",
                langid_note(w_index)
            )
        }
    } else {
        format!("{tname}({dtype}) idx={index}")
    }
}

pub fn descriptor_type_name(dtype: u8) -> &'static str {
    match dtype {
        1 => "DEVICE",
        2 => "CONFIGURATION",
        3 => "STRING",
        4 => "INTERFACE",
        5 => "ENDPOINT",
        6 => "DEVICE_QUALIFIER",
        7 => "OTHER_SPEED_CONFIGURATION",
        8 => "INTERFACE_POWER",
        0x0f => "BOS",
        0x10 => "DEVICE_CAPABILITY",
        0x21 => "HID",
        0x22 => "HID_REPORT",
        0x29 => "HUB",
        _ => "DESCRIPTOR",
    }
}

fn langid_note(lang: u16) -> &'static str {
    match lang {
        0x0409 => " (en-US)",
        0x0407 => " (de-DE)",
        0x040c => " (fr-FR)",
        0x0410 => " (it-IT)",
        0x0411 => " (ja-JP)",
        0x0804 => " (zh-CN)",
        0x040a => " (es-ES)",
        0x0419 => " (ru-RU)",
        0x0405 => " (cs-CZ)",
        0x040e => " (hu-HU)",
        0x0415 => " (pl-PL)",
        _ => " (not a USB LANGID in this table)",
    }
}

/// The 18-byte device descriptor, decoded from the bytes the capture actually
/// printed. Only returned when all 18 bytes are present — a partial descriptor
/// is reported as partial, never padded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceDescriptor {
    pub bcd_usb: u16,
    pub b_device_class: u8,
    pub b_device_sub_class: u8,
    pub b_device_protocol: u8,
    pub b_max_packet_size0: u8,
    pub id_vendor: u16,
    pub id_product: u16,
    pub bcd_device: u16,
    pub i_manufacturer: u8,
    pub i_product: u8,
    pub i_serial_number: u8,
}

pub fn decode_device_descriptor(data: &[u8]) -> Option<DeviceDescriptor> {
    if data.len() < 18 || data[0] != 18 || data[1] != 1 {
        return None;
    }
    Some(DeviceDescriptor {
        bcd_usb: u16::from_le_bytes([data[2], data[3]]),
        b_device_class: data[4],
        b_device_sub_class: data[5],
        b_device_protocol: data[6],
        b_max_packet_size0: data[7],
        id_vendor: u16::from_le_bytes([data[8], data[9]]),
        id_product: u16::from_le_bytes([data[10], data[11]]),
        bcd_device: u16::from_le_bytes([data[12], data[13]]),
        i_manufacturer: data[14],
        i_product: data[15],
        i_serial_number: data[16],
    })
}

// ---------------------------------------------------------------------------
// Filters and views
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum RequestMatch {
    Number(u8),
    Name(String),
}

impl RequestMatch {
    pub fn matches(&self, s: &Setup) -> bool {
        match self {
            RequestMatch::Number(n) => s.b_request == *n,
            RequestMatch::Name(want) => {
                // Normalise both sides: `DFU_DNLOAD`, `dfu dnload` and `DNLOAD`
                // are the same request, and a filter written by hand keeps its
                // underscores.
                let want = norm(want);
                let n = norm(request_name(s));
                n == want || short_alias(&n) == want || norm(&request_label(s)) == want
            }
        }
    }
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_uppercase()
}

/// `DNLOAD` and `DFU_DNLOAD(1)` both name the same request.
fn short_alias(normalized: &str) -> String {
    normalized
        .strip_prefix("DFU")
        .unwrap_or(normalized)
        .to_string()
}

#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub device: Option<(u32, u32)>,
    pub request: Option<RequestMatch>,
    pub endpoint: Option<u32>,
    /// Completion statuses to keep; `None` inside means "no completion in file".
    pub status: Option<Vec<Option<i64>>>,
    pub dir: Option<Dir>,
    pub xfer: Option<XferType>,
}

impl Filter {
    pub fn is_empty(&self) -> bool {
        self.device.is_none()
            && self.request.is_none()
            && self.endpoint.is_none()
            && self.status.is_none()
            && self.dir.is_none()
            && self.xfer.is_none()
    }

    pub fn matches_transfer(&self, cap: &Capture, t: &Transfer) -> bool {
        if let Some((bus, dev)) = self.device {
            if t.addr.bus != bus || t.addr.dev != dev {
                return false;
            }
        }
        if let Some(ep) = self.endpoint {
            if t.addr.ep != ep {
                return false;
            }
        }
        if let Some(d) = self.dir {
            if t.dir != d {
                return false;
            }
        }
        if let Some(x) = self.xfer {
            if t.xfer != x {
                return false;
            }
        }
        if let Some(req) = &self.request {
            match cap.setup_of(t) {
                Some(s) if req.matches(&s) => {}
                _ => return false,
            }
        }
        if let Some(want) = &self.status {
            let got = cap.status_of(t);
            if !want.contains(&got) {
                return false;
            }
        }
        true
    }

    pub fn matches_event(&self, ev: &EventLine) -> bool {
        if let Some((bus, dev)) = self.device {
            if ev.addr.bus != bus || ev.addr.dev != dev {
                return false;
            }
        }
        if let Some(ep) = self.endpoint {
            if ev.addr.ep != ep {
                return false;
            }
        }
        if let Some(d) = self.dir {
            if ev.dir != d {
                return false;
            }
        }
        if let Some(x) = self.xfer {
            if ev.xfer != x {
                return false;
            }
        }
        true
    }
}

/// A GET_DESCRIPTOR transfer — the view that makes descriptor lengths (and so
/// the stock/pwned difference) visible.
#[derive(Clone, Debug)]
pub struct DescriptorRead {
    pub transfer: usize,
    pub addr: Address,
    pub setup: Setup,
    pub transferred: u32,
    pub requested: u32,
    pub status: Option<i64>,
    pub data: Vec<u8>,
    pub data_truncated: bool,
    pub line_no: u64,
}

pub fn descriptor_reads(cap: &Capture) -> Vec<DescriptorRead> {
    let mut out = Vec::new();
    for (i, t) in cap.transfers.iter().enumerate() {
        let Some(s) = cap.setup_of(t) else { continue };
        if s.kind() != 0 || s.b_request != 6 {
            continue;
        }
        let ev = &cap.events[t.submit];
        out.push(DescriptorRead {
            transfer: i,
            addr: t.addr,
            setup: s,
            transferred: cap.events[t.completion.unwrap_or(t.submit)].length,
            requested: ev.length,
            status: cap.status_of(t),
            data: t
                .completion
                .map(|c| cap.events[c].data.clone())
                .unwrap_or_default(),
            data_truncated: t
                .completion
                .map(|c| cap.events[c].data_truncated())
                .unwrap_or(false),
            line_no: ev.line_no,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Attempts: the SETUP tick
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AttemptPlan {
    /// The aborted DNLOAD's wLength. gaster's `DFU_MAX_TRANSFER_SZ` is 0x800 and
    /// a9pwn's configs pin `overwrite_pad = 0x500`, but these are *arguments*,
    /// not facts about the device: pass what the run used.
    pub setup_len: u16,
    pub pad_len: u16,
    /// The drain DNLOAD that follows a tick that did not pass (`EP0_MAX_PACKET_SZ`
    /// in a9pwn, gaster.c:856).
    pub drain_len: u16,
}

impl Default for AttemptPlan {
    fn default() -> Self {
        AttemptPlan {
            setup_len: 0x800,
            pad_len: 0x500,
            drain_len: 0x40,
        }
    }
}

/// One SETUP tick as grouped from the capture: the 0x800 DNLOAD, the pad request
/// that is the pass condition, and the drain that follows a non-pass.
#[derive(Clone, Debug)]
pub struct Attempt {
    pub index: usize,
    pub addr: Address,
    pub start_ts: u64,
    pub abort: usize,
    pub pad: Option<usize>,
    pub drains: Vec<usize>,
    pub others: Vec<usize>,
}

#[derive(Clone, Debug)]
pub struct Attempts {
    pub plan: AttemptPlan,
    pub attempts: Vec<Attempt>,
    /// Transfers outside every attempt (PATCH, leak reads, enumeration traffic,
    /// the pad after the last attempt, ...).
    pub outside: Vec<usize>,
}

/// What a transfer can be *inside* a SETUP tick. Anything else ends the tick:
/// the tick is a contiguous run, so the PATCH overflow, a leak read or a
/// re-enumeration cannot be swallowed into "attempt 3".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TickShape {
    /// control-OUT class request 1 with wLength == setup_len.
    Start,
    /// control-OUT with wLength == pad_len (gaster's pad is bm=0x00 b=0).
    Pad,
    /// control-OUT class request 1 with wLength == drain_len.
    Drain,
    /// DFU_GET_STATUS (class request 3, IN, wLength 6): the state probe some
    /// runs insert between the aborted DNLOAD and the pad.
    Probe,
    /// Not part of a tick.
    End,
}

fn tick_shape(t: &Transfer, setup: Option<Setup>, plan: AttemptPlan) -> TickShape {
    let Some(s) = setup else { return TickShape::End };
    if t.xfer != XferType::Control {
        return TickShape::End;
    }
    let class_dnload = s.kind() == 1 && s.b_request == 1 && t.dir == Dir::Out;
    if class_dnload && s.w_length == plan.setup_len {
        TickShape::Start
    } else if class_dnload && s.w_length == plan.drain_len {
        TickShape::Drain
    } else if s.kind() == 1 && s.b_request == 3 && t.dir == Dir::In && s.w_length == 6 {
        TickShape::Probe
    } else if t.dir == Dir::Out && s.w_length == plan.pad_len {
        TickShape::Pad
    } else {
        TickShape::End
    }
}

/// Group transfers into SETUP ticks.
///
/// The rule is stated as a rule, not as device truth: an attempt starts at a
/// control-OUT class request 1 (DFU_DNLOAD) whose wLength equals
/// `plan.setup_len`, and it continues only while the next selected transfer is a
/// tick shape (pad, drain, probe, or another start). The first transfer that is
/// not one of those closes it. A tick never spans a device change, so a
/// re-enumeration cannot merge two attempts. Everything else is `outside` and is
/// reported separately.
pub fn group_attempts(cap: &Capture, filter: &Filter, plan: AttemptPlan) -> Attempts {
    let mut attempts: Vec<Attempt> = Vec::new();
    let mut outside: Vec<usize> = Vec::new();
    let mut current: Option<Attempt> = None;

    let close = |current: &mut Option<Attempt>, attempts: &mut Vec<Attempt>| {
        if let Some(a) = current.take() {
            attempts.push(a);
        }
    };

    for (i, t) in cap.transfers.iter().enumerate() {
        if !filter.matches_transfer(cap, t) {
            continue;
        }
        let shape = tick_shape(t, cap.setup_of(t), plan);
        // A device change ends the tick: the phone that re-enumerates is not the
        // same URB stream, and a pad must belong to the device that took the
        // aborted DNLOAD.
        if current.as_ref().map(|a| a.addr != t.addr).unwrap_or(false) {
            close(&mut current, &mut attempts);
        }
        match current.as_mut() {
            None => {
                if shape == TickShape::Start {
                    current = Some(Attempt {
                        index: attempts.len() + 1,
                        addr: t.addr,
                        start_ts: cap.events[t.submit].timestamp_us,
                        abort: i,
                        pad: None,
                        drains: Vec::new(),
                        others: Vec::new(),
                    });
                } else {
                    outside.push(i);
                }
            }
            Some(a) => match shape {
                TickShape::Start => {
                    close(&mut current, &mut attempts);
                    current = Some(Attempt {
                        index: attempts.len() + 1,
                        addr: t.addr,
                        start_ts: cap.events[t.submit].timestamp_us,
                        abort: i,
                        pad: None,
                        drains: Vec::new(),
                        others: Vec::new(),
                    });
                }
                TickShape::End => {
                    close(&mut current, &mut attempts);
                    outside.push(i);
                }
                TickShape::Pad if a.pad.is_none() => a.pad = Some(i),
                TickShape::Pad | TickShape::Drain => a.drains.push(i),
                // The state probe belongs between the aborted DNLOAD and the
                // pad; once the pad is in, the tick is over and a later
                // GET_STATUS is the next stage's read, not part of this attempt.
                TickShape::Probe if a.pad.is_none() => a.others.push(i),
                TickShape::Probe => {
                    close(&mut current, &mut attempts);
                    outside.push(i);
                }
            },
        }
    }
    close(&mut current, &mut attempts);
    Attempts {
        plan,
        attempts,
        outside,
    }
}

/// A one-word reading of an attempt's pad request, from the recorded status.
/// Labelled INFERRED wherever it is printed: usbmon records a status, not a
/// verdict, and `-32`/`-71` are different errnos even though both can mean the
/// endpoint refused the transfer.
pub fn pad_verdict(cap: &Capture, a: &Attempt) -> String {
    match a.pad {
        None => "PAD NOT IN THIS FILE".to_string(),
        Some(i) => match cap.status_of(&cap.transfers[i]) {
            Some(0) => {
                let t = &cap.transfers[i];
                format!(
                    "PAD COMPLETED (status 0, {} B) — a STALL is the reference's pass condition; \
                     a completion here is not it",
                    cap.events[t.completion.unwrap()].length
                )
            }
            Some(-32) => "PAD STALL (EPIPE)".to_string(),
            Some(-71) => "PAD STALL (EPROTO)".to_string(),
            Some(-2) => "PAD CANCELLED (ENOENT)".to_string(),
            Some(-110) => "PAD TIMEOUT (ETIMEDOUT)".to_string(),
            Some(c) => format!("PAD {}", errno_name(c).unwrap_or("ERROR")),
            None => "PAD PENDING (no completion in this file)".to_string(),
        },
    }
}

/// What the aborted DNLOAD actually shows: this is the `sz` question, answered
/// from the file rather than modelled.
pub fn abort_verdict(cap: &Capture, a: &Attempt) -> String {
    let t = &cap.transfers[a.abort];
    let req = cap.events[t.submit].length;
    match cap.status_of(t) {
        None => format!("NO CALLBACK IN THIS FILE (requested {req} B) — not evidence of an abort"),
        Some(c) if c == 0 && cap.events[t.completion.unwrap()].length == req => format!(
            "COMPLETED {}/{req} B — this window let the whole download through",
            cap.events[t.completion.unwrap()].length
        ),
        Some(0) => format!(
            "COMPLETED SHORT {} of {req} B at status 0 — this is a partial transfer",
            cap.events[t.completion.unwrap()].length
        ),
        Some(-2) => format!(
            "UNLINKED (ENOENT) after {} B of {req} — cancelled",
            cap.events[t.completion.unwrap()].length
        ),
        Some(c) => format!(
            "{} after {} B of {req}",
            status_label(c),
            cap.events[t.completion.unwrap()].length
        ),
    }
}

// ---------------------------------------------------------------------------
// Host trace (a9pwn's own JSONL) — an optional second instrument
// ---------------------------------------------------------------------------

/// One control transfer as a9pwn recorded it host-side. `abort_after_ms` is the
/// value the *host asked for*, which is why it is a separate instrument: the
/// wire shows whether the window fired, not what it was set to.
#[derive(Clone, Debug)]
pub struct HostXfer {
    pub seq: u64,
    pub stage: String,
    pub label: String,
    pub status: String,
    pub bm: u8,
    pub b: u8,
    pub w_value: u16,
    pub w_index: u16,
    pub w_length: u16,
    pub transferred: u32,
    pub xfer_micros: Option<u64>,
    pub abort_after_ms: Option<u32>,
}

impl HostXfer {
    /// The whole setup packet: two requests that differ only in wLength are
    /// different transfers and must never be merged (SPRAY's stall primitive is
    /// `02 03 0000 0080 0000`; PATCH's overflow is `02 03 0000 0080 0030`).
    pub fn setup_key(&self) -> (u8, u8, u16, u16, u16) {
        (self.bm, self.b, self.w_value, self.w_index, self.w_length)
    }
    pub fn setup_wire(&self) -> String {
        format!(
            "{:02x} {:02x} {:04x} {:04x} {:04x}",
            self.bm, self.b, self.w_value, self.w_index, self.w_length
        )
    }
}

/// Parse a9pwn's JSONL trace (`a9pwn/INTERFACE.md` §5). Only `xfer` records
/// carry wire parameters; every other kind is ignored, not guessed at. A line
/// that is not JSON is reported, never skipped silently.
pub fn parse_host_jsonl(text: &str) -> (Vec<HostXfer>, Vec<String>) {
    let mut out = Vec::new();
    let mut problems = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                problems.push(format!("line {}: not JSON: {e}", i + 1));
                continue;
            }
        };
        if v.get("kind").and_then(|k| k.as_str()) != Some("xfer") {
            continue;
        }
        let num = |k: &str| v.get(k).and_then(|x| x.as_u64());
        let Some(bm) = num("bm_request_type") else {
            continue;
        };
        out.push(HostXfer {
            seq: num("seq").unwrap_or(0),
            stage: v.get("stage").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            label: v.get("label").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            status: v.get("status").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            bm: bm as u8,
            b: num("b_request").unwrap_or(0) as u8,
            w_value: num("w_value").unwrap_or(0) as u16,
            w_index: num("w_index").unwrap_or(0) as u16,
            w_length: num("w_length").unwrap_or(0) as u16,
            transferred: num("transferred").unwrap_or(0) as u32,
            xfer_micros: num("xfer_micros"),
            abort_after_ms: num("abort_after_ms").map(|x| x as u32),
        });
    }
    (out, problems)
}

/// The wire-to-host mapping. The rule is stated and checked, not assumed: walk
/// the wire transfers in submit order, and for each host xfer advance until the
/// FULL setup packet matches. Wire transfers that no host record claims are
/// counted (enumeration traffic the host tool never issued). If a host xfer
/// finds no match, the join fails and says where — a half-aligned join would be
/// a wrong-value generator.
#[derive(Clone, Debug)]
pub struct HostJoin {
    pub wire_to_host: Vec<Option<usize>>,
    pub matched: usize,
    pub host_total: usize,
    pub wire_control_total: usize,
    pub skipped: usize,
    pub ok: bool,
    pub detail: String,
    /// The two instruments *contradicting* each other about the same transfer:
    /// one says it completed, the other says it did not. The JSONL carries no
    /// per-transfer id, so order+setup is the only key available, and this is how
    /// a permuted host trace is caught: identical setup packets can be swapped,
    /// but a `CANCELLED` host record cannot sit next to a wire transfer that
    /// completed 2048/2048. These make the host values SUSPECT and fail `--strict`.
    pub disagreements: Vec<String>,
    /// Same status class, different byte count. This is the known `abort_xfer`
    /// defect (libusb reports 0 bytes for a cancelled control transfer while the
    /// wire shows what moved), not evidence of misattribution, so it is reported
    /// without condemning the join.
    pub divergences: Vec<String>,
}

pub fn join_host(cap: &Capture, host: &[HostXfer]) -> HostJoin {
    let mut wire_to_host = vec![None; cap.transfers.len()];
    let mut wi = 0usize;
    let mut matched = 0usize;
    let mut skipped = 0usize;
    let mut detail = String::new();
    let wire_control_total = cap
        .transfers
        .iter()
        .filter(|t| t.xfer == XferType::Control && cap.setup_of(t).is_some())
        .count();
    for (hi, h) in host.iter().enumerate() {
        let mut found = false;
        while wi < cap.transfers.len() {
            let t = &cap.transfers[wi];
            let m = cap
                .setup_of(t)
                .map(|s| {
                    t.xfer == XferType::Control
                        && (s.bm_request_type, s.b_request, s.w_value, s.w_index, s.w_length)
                            == h.setup_key()
                })
                .unwrap_or(false);
            if m {
                wire_to_host[wi] = Some(hi);
                matched += 1;
                wi += 1;
                found = true;
                break;
            }
            skipped += 1;
            wi += 1;
        }
        if !found {
            detail = format!(
                "host record #{} (seq {}, {}/{}, setup {}) has no matching wire transfer after                  wire transfer index {} — the two records have diverged, so no host value is                  attached to any attempt",
                hi,
                h.seq,
                h.stage,
                h.label,
                h.setup_wire(),
                wi.saturating_sub(1)
            );
            break;
        }
    }
    let ok = detail.is_empty() && matched == host.len();
    let mut disagreements = Vec::new();
    let mut divergences = Vec::new();
    if ok {
        for (wi, hi) in wire_to_host.iter().enumerate() {
            let Some(hi) = hi else { continue };
            let h = &host[*hi];
            let t = &cap.transfers[wi];
            let Some(code) = cap.status_of(t) else { continue };
            let moved = cap.events[t.completion.unwrap()].length;
            let host_ok = h.status == "OK";
            let wire_ok = code == 0;
            if host_ok != wire_ok {
                disagreements.push(format!(
                    "wire #{} ({}, setup {}): host says {} with {} B, the wire says {} with {} B",
                    cap.events[t.submit].line_no,
                    t.addr,
                    h.setup_wire(),
                    h.status,
                    h.transferred,
                    status_label(code),
                    moved
                ));
            } else if !host_ok && h.transferred != moved {
                // The known `abort_xfer` defect: libusb reports 0 bytes for a
                // cancelled control transfer while the wire shows what moved.
                divergences.push(format!(
                    "wire #{} ({}, setup {}): host says {} with {} B, the wire shows {} B moved \
                     (a cancelled transfer whose byte count libusb could not report)",
                    cap.events[t.submit].line_no,
                    t.addr,
                    h.setup_wire(),
                    h.status,
                    h.transferred,
                    moved
                ));
            }
        }
    }
    if ok {
        detail = format!(
            "{matched}/{} host xfer record(s) matched a wire transfer by full setup packet; {} wire \
             control transfer(s) are not in the host trace (enumeration traffic the host tool did \
             not issue)",
            host.len(),
            skipped
        );
    }
    HostJoin {
        wire_to_host,
        matched,
        host_total: host.len(),
        wire_control_total,
        skipped,
        ok,
        detail,
        disagreements,
        divergences,
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Microseconds as they should be read: exact, and with a unit that cannot be
/// mistaken for milliseconds (the project has paid for that confusion).
pub fn us_label(us: i64) -> String {
    let sign = if us < 0 { "-" } else { "" };
    let a = us.unsigned_abs();
    if a >= 1_000_000 {
        format!("{sign}{}.{:03} s", a / 1_000_000, (a % 1_000_000) / 1000)
    } else if a >= 1000 {
        format!("{sign}{}.{:03} ms", a / 1000, a % 1000)
    } else {
        format!("{sign}{a} us")
    }
}

pub fn hex_bytes(data: &[u8]) -> String {
    let mut s = String::new();
    for (i, b) in data.iter().enumerate() {
        if i % 4 == 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s.trim_start().to_string()
}

// ---------------------------------------------------------------------------
// Tests. Every rejection rule has a negative control here, and the positive
// controls are the exact line shapes the kernel formatter produces.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(line: &str) -> EventLine {
        parse_line(1, line).unwrap_or_else(|e| panic!("expected accept, got {}: {}", e.code, e.detail))
    }
    fn bad(line: &str) -> ParseErr {
        match parse_line(1, line) {
            Ok(ev) => panic!("expected reject, got {:?}", ev),
            Err(e) => e,
        }
    }
    fn cap(text: &str) -> Capture {
        parse_reader(text.as_bytes(), DEFAULT_MAX_LINE_BYTES).unwrap()
    }

    // ---- positive controls: the shapes real kernels emit ----

    #[test]
    fn accepts_control_in_submit_with_setup() {
        let ev = ok("ffff888a0e7f4480 23336863 S Ci:1:005:0 s 80 06 0304 0409 00ff 255 <");
        assert_eq!(ev.event, Event::Submit);
        assert_eq!(ev.xfer, XferType::Control);
        assert_eq!(ev.dir, Dir::In);
        assert_eq!(ev.addr, Address { bus: 1, dev: 5, ep: 0 });
        let s = ev.setup.unwrap();
        assert_eq!(s.bm_request_type, 0x80);
        assert_eq!(s.b_request, 6);
        assert_eq!(s.w_value, 0x0304);
        assert_eq!(s.w_index, 0x0409);
        assert_eq!(s.w_length, 0x00ff);
        assert_eq!(ev.length, 255);
        assert_eq!(ev.data_flag, Some('<'));
        assert_eq!(ev.status, None);
    }

    #[test]
    fn accepts_control_in_callback_with_32_printed_bytes() {
        let line = "ffff888a0e7f4480 23337012 C Ci:1:005:0 0 198 = c6034300 50004900 44003a00 \
                    38003000 30003300 20004300 50005200 56003a00";
        let ev = ok(line);
        assert_eq!(ev.length, 198);
        assert_eq!(ev.data.len(), 32);
        assert_eq!(ev.data_flag, Some('='));
        assert!(ev.data_truncated(), "198 > 32 printed must read as truncation");
    }

    #[test]
    fn accepts_partial_last_data_group() {
        let ev = ok("ffff888a38e0ce40 178424251 C Ci:1:006:0 0 4 = 04030904");
        assert_eq!(ev.data, vec![0x04, 0x03, 0x09, 0x04]);
        let ev = ok("ffff888a0aa5b600 178954276 C Ci:1:007:0 0 9 = 09021900 01010580 fa");
        assert_eq!(ev.data.len(), 9);
        let ev = ok("ffff888a0aa5b600 178954169 C Ci:1:007:0 0 18 = 12010002 00000040 ac052712 00000203 0401");
        assert_eq!(ev.data.len(), 18);
    }

    #[test]
    fn accepts_out_submit_with_data_and_callback_with_gt() {
        let ev = ok("ffff888a38e0c240 177808811 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000");
        assert_eq!(ev.dir, Dir::Out);
        assert_eq!(ev.length, 2048);
        assert_eq!(ev.data.len(), 32);
        let ev = ok("ffff888a38e0c240 177809803 C Co:1:005:0 0 2048 >");
        assert_eq!(ev.status, Some(0));
        assert_eq!(ev.data_flag, Some('>'));
    }

    #[test]
    fn accepts_zero_length_transfer_with_no_data_section() {
        let ev = ok("ffff888a38e0c240 177811228 C Co:1:005:0 -2 0");
        assert_eq!(ev.length, 0);
        assert_eq!(ev.data_flag, None);
        let ev = ok("ffff888a38e0c240 177811285 S Co:1:005:0 s 00 00 0000 0000 0500 1280 = 00000000");
        assert_eq!(ev.setup.unwrap().w_length, 0x0500);
    }

    #[test]
    fn accepts_device_zero_and_short_address_forms() {
        let ev = ok("ffff888a32318d80 177924233 S Ci:1:000:0 s 80 06 0100 0000 0040 64 <");
        assert_eq!(ev.addr.dev, 0);
        assert_eq!(ev.addr.ep, 0);
    }

    #[test]
    fn accepts_interrupt_status_interval() {
        let ev = ok("ffff888a02ddb0c0 178055070 S Ii:1:001:1 -115:2048 4 <");
        assert_eq!(ev.xfer, XferType::Interrupt);
        assert_eq!(ev.status, Some(-115));
        assert_eq!(ev.interval, Some(2048));
        let ev = ok("ffff888a02ddb0c0 178055064 C Ii:1:001:1 0:2048 2 = 1000");
        assert_eq!(ev.status, Some(0));
        assert_eq!(ev.data, vec![0x10, 0x00]);
    }

    #[test]
    fn accepts_e_event() {
        let ev = ok("ffff888a02ddb0c0 178055064 E Co:1:006:0 -104 0");
        assert_eq!(ev.event, Event::Error);
        assert_eq!(ev.status, Some(-104));
        assert_eq!(ev.length, 0);
    }

    #[test]
    fn accepts_setup_placeholder_z() {
        let ev = ok("ffff888a0e7f4480 23336863 S Ci:1:005:0 Z __ __ ____ ____ ____ 255 <");
        assert_eq!(ev.setup_unavailable, Some('Z'));
        assert!(ev.setup.is_none());
    }

    #[test]
    fn accepts_uppercase_hex_digits() {
        // %lx is lowercase, but case cannot change meaning, so we do not reject
        // a capture just because a tool upstream upper-cased it.
        let ev = ok("FFFF888A0E7F4480 23336863 S Ci:1:005:0 s 80 06 0304 0409 00FF 255 <");
        assert_eq!(ev.setup.unwrap().w_length, 0x00ff);
    }

    #[test]
    fn accepts_crlf_line_endings_at_file_level() {
        let c = cap("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0\r\n");
        assert_eq!(c.errors(), 0);
        assert_eq!(c.events.len(), 1);
        assert!(c.events[0].line_no == 1);
    }

    #[test]
    fn tag_reuse_after_completion_is_not_a_duplicate() {
        // Every a9pwn capture looks like this: libusb reuses one URB struct.
        let c = cap("ffff888a0e7f4480 100 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n\
                     ffff888a0e7f4480 200 C Ci:1:005:0 0 18 = 12010002 00000040 ac052712 00000203 0401\n\
                     ffff888a0e7f4480 300 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n\
                     ffff888a0e7f4480 400 C Ci:1:005:0 0 18 = 12010002 00000040 ac052712 00000203 0401\n");
        assert_eq!(c.errors(), 0);
        assert_eq!(c.transfers.len(), 2);
        assert!(c.transfers.iter().all(|t| t.completion.is_some()));
        assert_eq!(c.elapsed_us(&c.transfers[0]), Some(100));
    }

    #[test]
    fn empty_file_is_clean_and_has_no_urbs() {
        let c = cap("");
        assert_eq!(c.lines, 0);
        assert_eq!(c.events.len(), 0);
        assert_eq!(c.errors(), 0);
        assert_eq!(c.warnings(), 0);
        // The documented negative control: the empty sha256.
        assert_eq!(
            c.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ---- negative controls ----

    #[test]
    fn rejects_garbage_line() {
        let e = bad("this is not a usbmon line");
        assert_eq!(e.code, "bad-tag");
    }

    #[test]
    fn rejects_truncated_line_mid_setup() {
        let e = bad("ffff888a0e7f4480 23336863 S Ci:1:005:0 s 80 06 0304 0409");
        assert_eq!(e.code, "truncated-line");
    }

    #[test]
    fn rejects_truncated_callback_missing_length() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0");
        assert_eq!(e.code, "truncated-line");
    }

    #[test]
    fn rejects_unknown_event_letter() {
        let e = bad("ffff888a0e7f4480 23337012 X Ci:1:005:0 0 0");
        assert_eq!(e.code, "unknown-event");
    }

    #[test]
    fn rejects_unknown_transfer_type() {
        let e = bad("ffff888a0e7f4480 23337012 C Xi:1:005:0 0 0");
        assert_eq!(e.code, "unknown-xfer-type");
    }

    #[test]
    fn rejects_t_node_address_with_helpful_message() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:005:0 0 0");
        assert_eq!(e.code, "t-node-format");
        assert!(e.detail.contains("u` node"));
    }

    #[test]
    fn rejects_iso_line_loudly() {
        let e = bad("ffff888a0e7f4480 23337012 C Zi:1:005:1 0:0:0 0");
        assert_eq!(e.code, "iso-unsupported");
    }

    #[test]
    fn rejects_short_device_number() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:5:0 0 0");
        assert_eq!(e.code, "bad-address");
    }

    #[test]
    fn rejects_bad_setup_word_width() {
        let e = bad("ffff888a0e7f4480 23336863 S Ci:1:005:0 s 80 06 304 0409 00ff 255 <");
        assert_eq!(e.code, "malformed-field");
    }

    #[test]
    fn rejects_callback_carrying_setup() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 s 80 06 0304 0409 00ff 255 <");
        assert_eq!(e.code, "setup-on-callback");
    }

    #[test]
    fn rejects_control_submit_without_setup() {
        let e = bad("ffff888a0e7f4480 23336863 S Ci:1:005:0 -115 255 <");
        assert_eq!(e.code, "setup-missing-on-submit");
    }

    #[test]
    fn rejects_unknown_setup_placeholder_flag() {
        let e = bad("ffff888a0e7f4480 23336863 S Ci:1:005:0 Q __ __ ____ ____ ____ 255 <");
        assert_eq!(e.code, "bad-setup-flag");
    }

    #[test]
    fn rejects_nonzero_length_without_data_tag() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 198");
        assert_eq!(e.code, "data-tag-missing");
    }

    #[test]
    fn rejects_data_tag_on_zero_length() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0 <");
        assert_eq!(e.code, "data-tag-on-empty-length");
    }

    #[test]
    fn rejects_data_bytes_over_the_kernel_cap() {
        let mut groups = Vec::new();
        for _ in 0..9 {
            groups.push("00000000");
        }
        let line = format!(
            "ffff888a0e7f4480 23337012 C Ci:1:005:0 0 64 = {}",
            groups.join(" ")
        );
        let e = bad(&line);
        assert_eq!(e.code, "data-too-large");
    }

    #[test]
    fn rejects_more_printed_bytes_than_the_declared_length() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 2 = 00000000 00000000");
        assert_eq!(e.code, "data-exceeds-length");
    }

    #[test]
    fn rejects_short_group_that_is_not_last() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 8 = 0000 00000000");
        assert_eq!(e.code, "bad-data-group");
    }

    #[test]
    fn rejects_odd_length_hex_group() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 8 = 0000000");
        assert_eq!(e.code, "bad-data-group");
    }

    #[test]
    fn rejects_in_data_tag_on_callback() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 64 <");
        assert_eq!(e.code, "bad-data-tag");
    }

    #[test]
    fn rejects_out_gt_data_tag_on_submit() {
        // OUT submit carries bytes or Z/D; `>` is the OUT *callback* marker.
        let e = bad("ffff888a0e7f4480 23337012 S Co:1:005:0 s 21 04 0000 0000 00c1 193 >");
        assert_eq!(e.code, "bad-data-tag");
    }

    #[test]
    fn rejects_data_bytes_on_in_submit() {
        let e = bad("ffff888a0e7f4480 23336863 S Ci:1:005:0 s 80 06 0304 0409 00ff 255 = 00000000");
        assert_eq!(e.code, "bad-data-tag");
    }

    #[test]
    fn rejects_trailing_token() {
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0 extra");
        assert_eq!(e.code, "data-tag-on-empty-length");
    }

    #[test]
    fn rejects_double_space() {
        let e = bad("ffff888a0e7f4480  23337012 C Ci:1:005:0 0 0");
        assert_eq!(e.code, "empty-field");
    }

    #[test]
    fn rejects_a_positive_status() {
        // urb->status is 0 or a negative errno; `%d` of a positive value cannot
        // come from usbmon, so it must not be absorbed as a status.
        let e = bad("ffff888a0e7f4480 23337012 C Ci:1:005:0 5 0");
        assert_eq!(e.code, "bad-status");
        let e = bad("ffff888a0e7f4480 23337012 S Bo:1:005:2 5 4 = 01020304");
        assert_eq!(e.code, "bad-status");
        let e = bad("ffff888a02ddb0c0 178055064 E Co:1:006:0 7 0");
        assert_eq!(e.code, "bad-status");
    }

    #[test]
    fn rejects_e_event_with_nonzero_length() {
        let e = bad("ffff888a02ddb0c0 178055064 E Co:1:006:0 -104 7");
        assert_eq!(e.code, "e-event-length");
    }

    #[test]
    fn rejects_interrupt_without_interval() {
        let e = bad("ffff888a02ddb0c0 178055070 S Ii:1:001:1 -115 4 <");
        assert_eq!(e.code, "malformed-field");
    }

    #[test]
    fn rejects_empty_line_and_non_ascii_at_file_level() {
        // The lone C line is a boundary warning; the blank line is the error.
        let c = cap("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0\n\n");
        assert!(c.problems.iter().any(|p| p.code == "empty-line"));
        assert!(c.problems.iter().any(|p| p.code == "unmatched-completion"));
        let raw: &[u8] = b"ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0\n\xff\xfe binary\n";
        let c = parse_reader(raw, DEFAULT_MAX_LINE_BYTES).unwrap();
        assert!(c.problems.iter().any(|p| p.code == "non-ascii-line"));
    }

    #[test]
    fn rejects_binary_garbage_without_panicking() {
        let mut data = vec![0u8; 512];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 256) as u8;
        }
        let c = parse_reader(&data[..], DEFAULT_MAX_LINE_BYTES).unwrap();
        assert!(c.errors() > 0);
    }

    #[test]
    fn huge_line_is_capped_and_reported() {
        let mut text = String::from("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0 ");
        text.push_str(&"a".repeat(3000));
        text.push('\n');
        text.push_str("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0\n");
        let c = parse_reader(text.as_bytes(), 1024).unwrap();
        assert_eq!(c.lines, 2);
        assert_eq!(c.problems[0].code, "line-too-long");
        assert_eq!(c.events.len(), 1, "the good line after the huge one still parses");
    }

    #[test]
    fn unmatched_completion_is_detected_not_absorbed() {
        let c = cap("ffff888a02ddb0c0 178055064 C Ii:1:001:1 0:2048 2 = 1000\n");
        assert_eq!(c.errors(), 0, "a real capture can start mid-URB");
        assert_eq!(c.warnings(), 1);
        assert_eq!(c.problems[0].code, "unmatched-completion");
        assert!(c.problems[0].is_boundary());
        assert_eq!(c.unmatched_completions.len(), 1);
        assert_eq!(c.transfers.len(), 0);
    }

    #[test]
    fn duplicate_submit_is_an_error() {
        let c = cap("ffff888a0e7f4480 100 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n\
                     ffff888a0e7f4480 200 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n");
        assert_eq!(c.errors(), 1);
        assert_eq!(c.problems[0].code, "duplicate-submit");
    }

    #[test]
    fn wrong_byte_count_in_callback_is_an_error() {
        // The task's doctored-fixture control, at unit level: 198 -> 300.
        let c = cap("ffff888a0e7f4480 23336863 S Ci:1:005:0 s 80 06 0304 0409 00ff 255 <\n\
                     ffff888a0e7f4480 23337012 C Ci:1:005:0 0 300 = c6034300 50004900 44003a00 \
                     38003000 30003300 20004300 50005200 56003a00\n");
        assert_eq!(c.errors(), 1);
        assert_eq!(c.problems[0].code, "transferred-exceeds-requested");
    }

    #[test]
    fn completion_on_the_wrong_address_is_an_error() {
        let c = cap("ffff888a0e7f4480 100 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n\
                     ffff888a0e7f4480 200 C Ci:1:006:0 0 18 = 12010002 00000040 ac052712 00000203 0401\n");
        assert_eq!(c.errors(), 1);
        assert_eq!(c.problems[0].code, "completion-attrs-mismatch");
    }

    #[test]
    fn backwards_timestamps_are_reported_negative_not_fixed_silently() {
        let c = cap("ffff888a0e7f4480 23337012 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n\
                     ffff888a0e7f4480 23336000 C Ci:1:005:0 0 18 = 12010002 00000040 ac052712 00000203 0401\n");
        assert_eq!(c.warnings(), 1);
        assert_eq!(c.problems[0].code, "timestamp-backwards");
        assert_eq!(c.elapsed_us(&c.transfers[0]), Some(-1012));
    }

    #[test]
    fn wlength_mismatch_is_a_warning_not_a_rejection() {
        let c = cap("ffff888a0e7f4480 100 S Ci:1:005:0 s 80 06 0100 0000 0012 64 <\n\
                     ffff888a0e7f4480 200 C Ci:1:005:0 0 18 = 12010002 00000040 ac052712 00000203 0401\n");
        assert_eq!(c.errors(), 0);
        assert_eq!(c.problems[0].code, "wlength-vs-buffer-length");
    }

    #[test]
    fn non_control_submit_status_other_than_einprogress_is_a_warning() {
        // Checked at submit time, not at pairing time: a submit with no callback
        // in the file must still be flagged.
        let c = cap("ffff888a0e7f4480 100 S Bo:1:005:2 0 4 = 01020304\n");
        assert_eq!(c.errors(), 0);
        assert!(c.problems.iter().any(|p| p.code == "submit-status-not-einprogress"));
        let ok = cap("ffff888a0e7f4480 100 S Bo:1:005:2 -115 4 = 01020304\n");
        assert_eq!(ok.warnings(), 0);
    }

    // ---- naming tables ----

    #[test]
    fn names_dfu_and_standard_requests_by_bmrequesttype() {
        let dfu = Setup {
            bm_request_type: 0x21,
            b_request: 1,
            w_value: 0,
            w_index: 0,
            w_length: 0x800,
        };
        assert_eq!(request_name(&dfu), "DFU_DNLOAD");
        let std = Setup {
            bm_request_type: 0x80,
            b_request: 6,
            w_value: 0x0304,
            w_index: 0x0409,
            w_length: 0xff,
        };
        assert_eq!(request_name(&std), "GET_DESCRIPTOR");
        // Request 6 is DFU_ABORT in class space and GET_DESCRIPTOR in standard
        // space; the two must never be conflated.
        assert_eq!(descriptor_target(0x0304, 0x0409), "STRING(3) idx=4 lang=0x0409 (en-US)");
        assert_eq!(descriptor_target(0x0100, 0), "DEVICE(1) idx=0");
    }

    #[test]
    fn class_request_on_other_recipient_is_not_called_dfu() {
        let s = Setup {
            bm_request_type: 0xa3,
            b_request: 0,
            w_value: 0,
            w_index: 4,
            w_length: 4,
        };
        assert_eq!(request_name(&s), "CLASS_REQ");
    }

    #[test]
    fn standard_dir_note_flags_the_pad_request_shape() {
        let pad = Setup {
            bm_request_type: 0x00,
            b_request: 0,
            w_value: 0,
            w_index: 0,
            w_length: 0x500,
        };
        let note = standard_dir_note(&pad).expect("GET_STATUS is IN-only, this is OUT");
        assert!(note.contains("IN-only"));
        let normal = Setup {
            bm_request_type: 0x80,
            b_request: 0,
            w_value: 0,
            w_index: 0,
            w_length: 2,
        };
        assert!(standard_dir_note(&normal).is_none());
    }

    #[test]
    fn status_names_are_errnos_and_notes_do_not_conflate_them() {
        assert_eq!(status_label(-32), "-32 EPIPE");
        assert_eq!(status_label(-71), "-71 EPROTO");
        assert_eq!(status_label(0), "0 OK");
        assert!(status_note(-71).unwrap().contains("not EREMOTEIO"));
        assert_eq!(errno_name(-121), Some("EREMOTEIO"));
    }

    #[test]
    fn device_descriptor_decodes_only_complete_well_formed_data() {
        let stock: [u8; 18] = [
            0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0xac, 0x05, 0x27, 0x12, 0x00, 0x00,
            0x02, 0x03, 0x04, 0x01,
        ];
        let d = decode_device_descriptor(&stock).unwrap();
        assert_eq!((d.id_vendor, d.id_product), (0x05ac, 0x1227));
        assert_eq!((d.i_manufacturer, d.i_product, d.i_serial_number), (2, 3, 4));
        let mut pwned = stock;
        pwned[16] = 6;
        assert_eq!(decode_device_descriptor(&pwned).unwrap().i_serial_number, 6);
        assert!(decode_device_descriptor(&stock[..17]).is_none());
    }

    // ---- attempts ----

    #[test]
    fn groups_the_setup_tick_and_reports_the_pad_stall() {
        let text = "\
ffff888a38e0c240 177808811 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 177809803 C Co:1:005:0 0 2048 >\n\
ffff888a38e0c240 177809864 S Co:1:005:0 s 21 01 0000 0000 0040 64 = 00000000\n\
ffff888a38e0c240 177809932 C Co:1:005:0 0 64 >\n\
ffff888a38e0c240 177811111 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 177811228 C Co:1:005:0 -2 0\n\
ffff888a38e0c240 177811285 S Co:1:005:0 s 00 00 0000 0000 0500 1280 = 00000000\n\
ffff888a38e0c240 177812174 C Co:1:005:0 -32 0\n";
        let c = cap(text);
        assert_eq!(c.errors(), 0);
        let g = group_attempts(&c, &Filter::default(), AttemptPlan::default());
        assert_eq!(g.attempts.len(), 2);
        let a1 = &g.attempts[0];
        assert_eq!(a1.abort, 0);
        assert_eq!(a1.pad, None);
        assert_eq!(a1.drains, vec![1]);
        assert!(abort_verdict(&c, a1).starts_with("COMPLETED 2048/2048"));
        let a2 = &g.attempts[1];
        assert_eq!(a2.abort, 2);
        assert_eq!(a2.pad, Some(3));
        assert!(abort_verdict(&c, a2).starts_with("UNLINKED (ENOENT) after 0 B of 2048"));
        assert_eq!(pad_verdict(&c, a2), "PAD STALL (EPIPE)");
        assert_eq!(c.elapsed_us(&c.transfers[3]), Some(889));
    }

    /// The tick is a contiguous run: a PATCH overflow (standard SET_FEATURE with
    /// wLength 0) after the pad must be OUTSIDE the attempt. Before this rule,
    /// every later 1:005 transfer was swallowed into "attempt 3" as `other`,
    /// which silently hid the PATCH and the leak reads inside a SETUP label.
    #[test]
    fn a_tick_ends_at_the_first_non_tick_transfer() {
        let text = "\
ffff888a38e0c240 177811111 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 177811228 C Co:1:005:0 -2 0\n\
ffff888a38e0c240 177811285 S Co:1:005:0 s 00 00 0000 0000 0500 1280 = 00000000\n\
ffff888a38e0c240 177812174 C Co:1:005:0 -32 0\n\
ffff888a32318d80 178052047 S Co:1:005:0 s 02 03 0000 0080 0000 0\n\
ffff888a32318d80 178052205 C Co:1:005:0 -32 0\n\
ffff888a32318d80 178052217 S Ci:1:005:0 s 80 06 0304 000a 0040 64 <\n\
ffff888a32318d80 178053408 C Ci:1:005:0 -2 0\n";
        let c = cap(text);
        assert_eq!(c.errors(), 0);
        let g = group_attempts(&c, &Filter::default(), AttemptPlan::default());
        assert_eq!(g.attempts.len(), 1);
        let a = &g.attempts[0];
        assert_eq!(a.abort, 0);
        assert_eq!(a.pad, Some(1));
        assert!(a.drains.is_empty(), "a PATCH SET_FEATURE is not a drain");
        assert!(a.others.is_empty(), "the pad ended the tick");
        assert_eq!(g.outside, vec![2, 3], "the PATCH and the leak read are outside");
    }

    /// A state probe between the aborted DNLOAD and the pad belongs to the tick
    /// (`--probe-setup-state` inserts one DFU_GET_STATUS there).
    #[test]
    fn a_get_status_probe_inside_the_tick_is_kept() {
        let text = "\
ffff888a38e0c240 100 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 200 C Co:1:005:0 -2 0\n\
ffff888a38e0c240 300 S Ci:1:005:0 s a1 03 0000 0000 0006 6 <\n\
ffff888a38e0c240 400 C Ci:1:005:0 0 6 = 05000000 0000\n\
ffff888a38e0c240 500 S Co:1:005:0 s 00 00 0000 0000 0500 1280 = 00000000\n\
ffff888a38e0c240 600 C Co:1:005:0 -32 0\n";
        let c = cap(text);
        let g = group_attempts(&c, &Filter::default(), AttemptPlan::default());
        assert_eq!(g.attempts.len(), 1);
        assert_eq!(g.attempts[0].pad, Some(2));
        assert_eq!(g.attempts[0].others, vec![1]);
        assert!(g.outside.is_empty());
    }

    #[test]
    fn attempts_do_not_span_a_device_change() {
        let text = "\
ffff888a38e0c240 100 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 200 C Co:1:005:0 -2 0\n\
ffff888a0aa5dcc0 300 S Co:1:006:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a0aa5dcc0 400 C Co:1:006:0 -2 0\n";
        let c = cap(text);
        let g = group_attempts(&c, &Filter::default(), AttemptPlan::default());
        assert_eq!(g.attempts.len(), 2);
        assert_ne!(g.attempts[0].addr, g.attempts[1].addr);
    }

    #[test]
    fn attempt_grouping_respects_the_device_filter() {
        let text = "\
ffff888a38e0c240 100 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 200 C Co:1:005:0 -2 0\n\
ffff888a0aa5dcc0 300 S Co:1:006:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a0aa5dcc0 400 C Co:1:006:0 -2 0\n";
        let c = cap(text);
        let f = Filter {
            device: Some((1, 6)),
            ..Default::default()
        };
        let g = group_attempts(&c, &f, AttemptPlan::default());
        assert_eq!(g.attempts.len(), 1);
        assert_eq!(g.attempts[0].addr.dev, 6);
        assert!(g.outside.is_empty());
    }

    #[test]
    fn zero_length_einprogress_and_hex_helpers() {
        assert_eq!(us_label(889), "889 us");
        assert_eq!(us_label(1_412_945), "1.412 s");
        assert_eq!(us_label(-1012), "-1.012 ms");
        assert_eq!(hex_bytes(&[0xc6, 0x03, 0x43, 0x00, 0x50]), "c6034300 50");
    }

    #[test]
    fn data_classification_distinguishes_the_cap_from_an_underprint() {
        let capped = ok("ffff888a0e7f4480 100 C Ci:1:005:0 0 198 = c6034300 50004900 44003a00 \
                         38003000 30003300 20004300 50005200 56003a00");
        assert!(capped.data_capped_by_kernel());
        assert!(!capped.data_underprinted());
        let exact = ok("ffff888a0e7f4480 100 C Ci:1:005:0 0 4 = 04030904");
        assert!(!exact.data_capped_by_kernel(), "4 printed of 4 is not the cap");
        assert!(!exact.data_underprinted());
        let short = ok("ffff888a0e7f4480 100 C Ci:1:005:0 0 4 = 1201");
        assert!(!short.data_capped_by_kernel());
        assert!(short.data_underprinted(), "2 of min(4,32) cannot be the 32 B cap");
    }

    #[test]
    fn uppercase_hex_is_flagged_but_accepted() {
        let ev = ok("FFFF888A0E7F4480 100 S Ci:1:005:0 s 80 06 0304 0409 00FF 255 <");
        assert!(ev.uppercase_hex);
        let ev = ok("ffff888a0e7f4480 100 S Ci:1:005:0 s 80 06 0304 0409 00ff 255 <");
        assert!(!ev.uppercase_hex, "the address type letters are upper case but not hex");
        let ev = ok("ffff888a02ddb0c0 178055064 C Ii:1:001:1 0:2048 2 = 1000");
        assert!(!ev.uppercase_hex, "the `D`-style data flags are not hex fields");
    }

    #[test]
    fn host_jsonl_parses_the_window_the_wire_cannot_show() {
        let text = "\
{\"seq\":19,\"stage\":\"SETUP\",\"kind\":\"xfer\",\"label\":\"setup_abort_dnload\",\"status\":\"OK\",\
\"bm_request_type\":33,\"b_request\":1,\"w_value\":0,\"w_index\":0,\"w_length\":2048,\"transferred\":2048,\
\"xfer_micros\":946,\"abort_after_ms\":4}\n\
{\"seq\":20,\"stage\":\"SETUP\",\"kind\":\"setup_attempt\",\"detail\":\"not an xfer\"}\n";
        let (xfers, problems) = parse_host_jsonl(text);
        assert!(problems.is_empty());
        assert_eq!(xfers.len(), 1);
        assert_eq!(xfers[0].abort_after_ms, Some(4));
        assert_eq!(xfers[0].setup_wire(), "21 01 0000 0000 0800");
        // A non-JSON line is reported, never silently skipped.
        let (_, problems) = parse_host_jsonl("{\"kind\":\"xfer\"\n");
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn host_join_matches_by_the_full_setup_packet_and_fails_loudly() {
        let text = "\
ffff888a00000001 100 S Co:1:005:0 s 02 03 0000 0080 0000 0\n\
ffff888a00000001 156 C Co:1:005:0 -32 0\n\
ffff888a00000002 200 S Co:1:005:0 s 02 03 0000 0080 0030 48 = 00000000\n\
ffff888a00000002 364 C Co:1:005:0 -32 0\n";
        let c = cap(text);
        let host = vec![
            HostXfer {
                seq: 1, stage: "SPRAY".into(), label: "spray_request_stall".into(),
                status: "STALL".into(), bm: 0x02, b: 3, w_value: 0, w_index: 0x80, w_length: 0,
                transferred: 0, xfer_micros: Some(166), abort_after_ms: None,
            },
            HostXfer {
                seq: 2, stage: "PATCH".into(), label: "patch_overflow_callback".into(),
                status: "STALL".into(), bm: 0x02, b: 3, w_value: 0, w_index: 0x80, w_length: 0x30,
                transferred: 0, xfer_micros: Some(187), abort_after_ms: None,
            },
        ];
        let j = join_host(&c, &host);
        assert!(j.ok, "{}", j.detail);
        assert_eq!(j.matched, 2);
        assert_eq!(j.wire_to_host[0], Some(0));
        assert_eq!(j.wire_to_host[1], Some(1));
        // A host record with no matching wire transfer must fail the join, not
        // attach a value to the wrong attempt.
        let mut bad = host.clone();
        bad[1].w_length = 0x40;
        let j = join_host(&c, &bad);
        assert!(!j.ok);
        assert!(j.detail.contains("has no matching wire transfer"));
    }

    #[test]
    fn a_tick_is_closed_by_a_get_status_after_the_pad() {
        // The project's own run has a DFU_GET_STATUS read right after the pad
        // STALL; it belongs to the next stage, not to the attempt.
        let text = "\
ffff888a38e0c240 100 S Co:1:005:0 s 21 01 0000 0000 0800 2048 = 00000000\n\
ffff888a38e0c240 200 C Co:1:005:0 -2 0\n\
ffff888a38e0c240 300 S Co:1:005:0 s 00 00 0000 0000 0500 1280 = 00000000\n\
ffff888a38e0c240 400 C Co:1:005:0 -32 0\n\
ffff888a38e0c240 500 S Ci:1:005:0 s a1 03 0000 0000 0006 6 <\n\
ffff888a38e0c240 600 C Ci:1:005:0 0 6 = 05000000 0000\n";
        let c = cap(text);
        let g = group_attempts(&c, &Filter::default(), AttemptPlan::default());
        assert_eq!(g.attempts.len(), 1);
        assert_eq!(g.attempts[0].pad, Some(1));
        assert!(g.attempts[0].others.is_empty());
        assert_eq!(g.outside, vec![2]);
    }

    #[test]
    fn the_problem_list_is_capped_but_the_counts_are_exact() {
        let mut text = String::new();
        for _ in 0..(MAX_LISTED_PROBLEMS + 500) {
            text.push_str("nonsense\n");
        }
        let c = parse_reader(text.as_bytes(), DEFAULT_MAX_LINE_BYTES).unwrap();
        assert_eq!(c.errors(), MAX_LISTED_PROBLEMS + 500);
        assert_eq!(c.problems.len(), MAX_LISTED_PROBLEMS);
        assert_eq!(c.problems_not_listed, 500);
    }

    #[test]
    fn an_unterminated_line_stops_the_read() {
        let mut data = vec![b'x'; (1 << 20) + 64];
        data[0] = b'f';
        let c = parse_reader(&data[..], 1024).unwrap();
        // The cap is 1 MiB of line; the drain cap is 64 MiB, so a 1 MiB
        // unterminated line is reported as too long and reading ends at EOF.
        assert!(c.errors() > 0);
        assert_eq!(c.problems[0].code, "line-too-long");
    }

    #[test]
    fn address_stats_follow_first_appearance() {
        let text = "\
ffff888a0e7f4480 050 C Ci:1:007:0 0 0\n\
ffff888a0e7f4480 100 S Ci:1:005:0 s 80 06 0100 0000 0012 18 <\n\
ffff888a0e7f4480 200 C Ci:1:005:0 0 18 = 12010002 00000040 ac052712 00000203 0401\n";
        let c = cap(text);
        let stats = address_stats(&c);
        assert_eq!(stats[0].0.dev, 7, "1:007 is first in time");
        assert_eq!(stats[1].0.dev, 5);
        assert_eq!(stats[1].1.transfers, 1);
        assert_eq!(stats[0].1.events, 1);
    }
}
