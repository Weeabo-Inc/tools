//! traceview — read an a9pwn trace file and report what is actually in it.
//!
//! Two input dialects are understood:
//!
//! * **jsonl** — the live format, `a9pwn/INTERFACE.md` §5: one JSON object per
//!   line, `seq`, `stage`, `kind`, `t_micros` on every line, byte-stable key
//!   order.
//! * **legacy-a9ctl** — the pre-rewrite C++ tool's text log. `a9ctl/stage-setup.log`
//!   (the 384-timeout failure) is the project's regression fixture and the
//!   baseline every new trace is compared against, so this tool reads it.
//!
//! ## Contract
//!
//! 1. **Nothing here panics on bad input.** A line that cannot be understood is
//!    reported with its line number and an excerpt, and a summary is still
//!    produced from the lines that could be read. A viewer that dies on a
//!    truncated trace is a viewer that lies by omission about the rest of it.
//! 2. **Every derived number says where it came from.** Counts are computed from
//!    the fields on the lines, never from a9pwn's own `Counters` — the point of
//!    an independent read is that it can disagree with a9pwn. Where a field is
//!    absent from the file, the render says absent rather than zero (see
//!    `xfer_micros` on the legacy dialect), because "0 observed" and "not
//!    observed" are different measurements and this project has been burned by
//!    conflating them.
//! 3. **Absence is never upgraded to a fact.** No PWND line in a trace is
//!    reported as "no PWND marker in this file", never as "the device did not
//!    enter pwned DFU".

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Keys that must be present on every line (`INTERFACE.md` §5).
pub const REQUIRED_KEYS: [&str; 4] = ["seq", "stage", "kind", "t_micros"];

/// The field order frozen by `INTERFACE.md` §5 and `trace.rs`'s `Line` struct.
/// A line's keys must be a **subsequence** of this — serde skips absent optionals,
/// so a shorter list is fine, a reordered or unknown key is not.
pub const CONTRACT_KEY_ORDER: [&str; 18] = [
    "seq",
    "stage",
    "kind",
    "t_micros",
    "label",
    "detail",
    "status",
    "bm_request_type",
    "b_request",
    "w_value",
    "w_index",
    "w_length",
    "transferred",
    "requested",
    "xfer_micros",
    "libusb_rc",
    "abort_after_ms",
    "xfer_seq",
];

/// Stage names in the order the stage machine walks them (`types.rs` `Stage`).
pub const STAGE_ORDER: [&str; 5] = ["RESET", "SETUP", "SPRAY", "PATCH", "PWNED"];

/// The six transfer statuses (`types.rs` `XferStatus::as_str`).
pub const STATUS_ORDER: [&str; 6] = ["OK", "STALL", "TIMEOUT", "CANCELLED", "NO_DEVICE", "ERROR"];

/// `gaster.c:853` — `DFU_MAX_TRANSFER_SZ`.
pub const DFU_MAX_TRANSFER_SZ: u32 = 0x800;
/// `gaster.c:856` — `EP0_MAX_PACKET_SZ`, the "unstick" length.
pub const EP0_MAX_PACKET_SZ: u32 = 0x40;
const DFU_DNLOAD: u8 = 0x01;
const GET_DESCRIPTOR: u8 = 0x06;
/// `checkm8_usb_request_leak` length (`gaster.c:866`).
const LEAK_LEN: u32 = EP0_MAX_PACKET_SZ;
/// `checkm8_no_leak` length, `3 * EP0 + 1` (`gaster.c:886`).
const NO_LEAK_LEN: u32 = 3 * EP0_MAX_PACKET_SZ + 1;

// ---------------------------------------------------------------- input model

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Jsonl,
    LegacyA9ctl,
    Mixed,
    Unknown,
}

impl Default for Dialect {
    /// The honest default: nothing has been read yet.
    fn default() -> Self {
        Dialect::Unknown
    }
}

impl Dialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Dialect::Jsonl => "jsonl",
            Dialect::LegacyA9ctl => "legacy-a9ctl",
            Dialect::Mixed => "mixed (jsonl + legacy-a9ctl)",
            Dialect::Unknown => "unrecognised (no record-shaped line found)",
        }
    }
}

#[derive(Debug)]
pub enum LoadError {
    Io { path: PathBuf, err: std::io::Error },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io { path, err } => write!(f, "cannot read {}: {err}", path.display()),
        }
    }
}
impl std::error::Error for LoadError {}

/// A line this tool could not turn into a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadLine {
    pub line: usize,
    pub why: String,
    pub excerpt: String,
}

/// A transferred control request, from either dialect.
///
/// Fields the dialect does not carry stay `None`. They are **never** filled in
/// with the value the reference implementation would have used: an inferred
/// `w_length` is exactly the plausible-looking wrong value this project keeps
/// paying for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xfer {
    pub line: usize,
    pub seq: Option<u64>,
    pub stage: String,
    pub t_micros: Option<u64>,
    pub label: Option<String>,
    pub status: String,
    pub bm: Option<u8>,
    pub b: Option<u8>,
    pub w_value: Option<u32>,
    pub w_index: Option<u32>,
    pub w_length: Option<u32>,
    pub transferred: Option<u64>,
    pub requested: Option<u64>,
    pub micros: Option<u64>,
    pub libusb_rc: Option<i64>,
    pub abort_after_ms: Option<u32>,
    pub xfer_seq: Option<u64>,
    pub dialect: Dialect,
}

impl Xfer {
    /// `gaster.c:853`'s async `DFU_DNLOAD` of `DFU_MAX_TRANSFER_SZ`.
    ///
    /// Where the dialect carries the request fields this is structural. Where it
    /// does not (the legacy log states `abort_ms=N` and nothing else) the
    /// reported window is itself the evidence that this was the async attempt —
    /// the same rule `trace.rs` uses, restricted to fields that exist.
    pub fn is_setup_attempt(&self) -> bool {
        if self.abort_after_ms.is_some() {
            return true;
        }
        self.bm == Some(0x21) && self.b == Some(DFU_DNLOAD) && self.w_length == Some(DFU_MAX_TRANSFER_SZ)
    }

    /// `gaster.c:853`'s pad request: an OUT transfer with no window that is
    /// neither `DFU_DNLOAD` nor the `0x40` unstick. An explicit `pad` label wins.
    pub fn is_pad_request(&self) -> bool {
        if self.is_setup_attempt() {
            return false;
        }
        if let Some(l) = &self.label {
            if l.to_ascii_lowercase().contains("pad") {
                return true;
            }
        }
        match (self.bm, self.b, self.w_length) {
            (Some(bm), Some(b), Some(len)) => (bm & 0x80) == 0 && b != DFU_DNLOAD && len != EP0_MAX_PACKET_SZ,
            _ => false,
        }
    }

    /// `checkm8_usb_request_stall` (`gaster.c:890-894`).
    pub fn is_spray_stall_request(&self) -> bool {
        self.bm == Some(0x02) && self.b == Some(0x03) && self.w_index == Some(0x80)
    }

    /// `checkm8_usb_request_leak` / `checkm8_no_leak` (`gaster.c:866,886`).
    pub fn is_spray_leak_request(&self) -> bool {
        matches!(self.bm, Some(bm) if bm & 0x80 != 0)
            && self.b == Some(GET_DESCRIPTOR)
            && matches!(self.w_length, Some(l) if l == LEAK_LEN || l == NO_LEAK_LEN)
    }
}

/// A non-`xfer` line: `event`, `predicate`, `enumerated`, `reset`, … (`kind::*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub line: usize,
    pub seq: Option<u64>,
    pub stage: Option<String>,
    pub kind: String,
    pub t_micros: Option<u64>,
    pub label: Option<String>,
    pub detail: Option<String>,
    pub status: Option<String>,
}

/// A recognised line that is not a record — the legacy log's four header lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub line: usize,
    pub text: String,
}

// ------------------------------------------------------------------- summary

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The file or the run contradicts a documented pass condition.
    Alarm,
    /// Something is missing or unusual; read the surrounding numbers.
    Warn,
    /// A positive observation, or context a reader needs.
    Info,
}

impl Severity {
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Alarm => "ALARM",
            Severity::Warn => "WARN ",
            Severity::Info => "INFO ",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    pub severity: Severity,
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeqCheck {
    pub present: u64,
    pub absent: u64,
    pub first: Option<u64>,
    pub last: Option<u64>,
    /// `(line, previous, current)` for each place seq did not strictly increase.
    pub out_of_order: Vec<(usize, u64, u64)>,
    pub duplicates: u64,
    /// `(line, missing_count)` for each forward jump.
    pub gaps: Vec<(usize, u64)>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetupSummary {
    pub attempts: u64,
    pub windows_ordered: Vec<u32>,
    pub windows_distinct: Vec<u32>,
    pub windows_unreported: u64,
    /// Consecutive attempts that used the *same* window. gaster advances the
    /// window on every failed attempt (`gaster.c:857`), so any non-zero value
    /// means the advance did not fire at least once.
    pub repeats_back_to_back: u64,
    /// Smallest `p` with `windows[i] == windows[i % p]` for all `i`, when at
    /// least two full cycles fit. `Some(1)` is a fully pinned sweep.
    pub period: Option<usize>,
    pub pad_requests: u64,
    pub pad_stall: u64,
    pub pad_timeout: u64,
    pub pad_error: u64,
    pub pad_ok: u64,
    pub pad_cancelled: u64,
    pub pad_other: u64,
    pub pad_sizes_distinct: Vec<u32>,
    pub abort_full: u64,
    pub abort_timeouts: u64,
    pub early_cancels: u64,
    /// How many setup attempts carried `xfer_micros` at all. The legacy log
    /// carries none, so an "early cancels: 0" there is not a measurement of
    /// anything — this field is what makes that distinguishable.
    pub micros_present: u64,
    /// SETUP transfers that are neither the async attempt nor the pad request
    /// nor a spray request: the `0x40` unstick (`gaster.c:856`).
    pub other_transfers: u64,
}

impl SetupSummary {
    /// `trace.rs`'s own rule, re-derived from the file: at least two attempts and
    /// exactly one distinct window.
    pub fn pinned(&self) -> bool {
        self.attempts >= 2 && self.windows_distinct.len() == 1
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpraySummary {
    pub stall_requests: u64,
    pub stall_not_stalling: u64,
    pub leak_requests: u64,
    pub leak_not_zero: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResetSummary {
    pub attempted: u64,
    pub real: u64,
    pub pipe_cycle: u64,
    pub other_kinds: u64,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PredicateSummary {
    pub passed: BTreeMap<String, u64>,
    pub failed: BTreeMap<String, u64>,
    pub first_failure: Option<(usize, String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PwnedHit {
    pub line: usize,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub dialect: Dialect,
    pub lines_total: usize,
    pub lines_blank: usize,
    pub records: usize,
    pub xfers: Vec<Xfer>,
    pub events: Vec<Event>,
    pub notes: Vec<Note>,
    pub notes_total: usize,
    pub malformed: Vec<BadLine>,
    pub unrecognised: Vec<BadLine>,
    pub seq: SeqCheck,
    pub t_first: Option<u64>,
    pub t_last: Option<u64>,
    pub stage_status: BTreeMap<(String, String), u64>,
    pub key_order_violations: Vec<BadLine>,
    pub pwned_hit: Option<PwnedHit>,
    pub predicates: PredicateSummary,
    pub resets: ResetSummary,
    pub setup: SetupSummary,
    pub spray: SpraySummary,
    pub rounds: u64,
    pub max_round: Option<u32>,
    pub enumerated: Vec<String>,
    pub device_path: Vec<String>,
    pub open_failed: Vec<String>,
    pub events_by_kind: BTreeMap<String, u64>,
}

impl Summary {
    pub fn stage_total(&self, stage: &str) -> u64 {
        self.stage_status
            .iter()
            .filter(|((s, _), _)| s == stage)
            .map(|(_, v)| *v)
            .sum()
    }

    pub fn status_total(&self, status: &str) -> u64 {
        self.stage_status
            .iter()
            .filter(|((_, st), _)| st == status)
            .map(|(_, v)| *v)
            .sum()
    }

    pub fn stage_status(&self, stage: &str, status: &str) -> u64 {
        self.stage_status
            .get(&(stage.to_string(), status.to_string()))
            .copied()
            .unwrap_or(0)
    }

    /// Stages seen in the file, known stages first in stage-machine order, then
    /// anything unexpected, sorted.
    pub fn stages_seen(&self) -> Vec<String> {
        let mut known: Vec<String> = STAGE_ORDER
            .iter()
            .filter(|s| self.stage_status.keys().any(|(st, _)| st == *s))
            .map(|s| s.to_string())
            .collect();
        let mut extra: Vec<String> = self
            .stage_status
            .keys()
            .map(|(st, _)| st.clone())
            .filter(|s| !STAGE_ORDER.contains(&s.as_str()))
            .collect();
        extra.sort();
        extra.dedup();
        known.extend(extra);
        known
    }

    /// Statuses seen in the file, the six contract statuses first in
    /// `types.rs` order, then anything unexpected, sorted.
    pub fn statuses_seen(&self) -> Vec<String> {
        let mut known: Vec<String> = STATUS_ORDER
            .iter()
            .filter(|s| self.stage_status.keys().any(|(_, st)| st == *s))
            .map(|s| s.to_string())
            .collect();
        let mut extra: Vec<String> = self
            .stage_status
            .keys()
            .map(|(_, st)| st.clone())
            .filter(|s| !STATUS_ORDER.contains(&s.as_str()))
            .collect();
        extra.sort();
        extra.dedup();
        known.extend(extra);
        known
    }
}

// -------------------------------------------------------------------- parsing

fn hex32(d: &[u8]) -> String {
    let mut s = String::with_capacity(d.len() * 2);
    for b in d {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex32(&Sha256::digest(data))
}

fn excerpt(line: &str, max: usize) -> String {
    let t = line.trim_end();
    if t.chars().count() <= max {
        return t.to_string();
    }
    let cut: String = t.chars().take(max).collect();
    format!("{cut}…")
}

/// Top-level key names of a flat JSON object, in the order they appear.
///
/// Tracks string and escape state, so a `"seq"` inside a `detail` string is not
/// mistaken for a key, and an unterminated string (a trace truncated mid-write,
/// which is the normal way a trace gets truncated) returns `None` instead of a
/// half-parsed key list.
pub fn top_level_keys(raw: &str) -> Option<Vec<String>> {
    let cs: Vec<char> = raw.chars().collect();
    let mut i = 0usize;
    while i < cs.len() && cs[i].is_whitespace() {
        i += 1;
    }
    if i >= cs.len() || cs[i] != '{' {
        return None;
    }
    let mut keys = Vec::new();
    let mut depth = 0i32;
    while i < cs.len() {
        let c = cs[i];
        if c == '"' {
            let start = i + 1;
            let mut j = start;
            let mut escaped = false;
            while j < cs.len() {
                if escaped {
                    escaped = false;
                } else if cs[j] == '\\' {
                    escaped = true;
                } else if cs[j] == '"' {
                    break;
                }
                j += 1;
            }
            if j >= cs.len() {
                return None; // unterminated string => the line stops mid-token
            }
            let text: String = cs[start..j].iter().collect();
            let mut k = j + 1;
            while k < cs.len() && cs[k].is_whitespace() {
                k += 1;
            }
            if depth == 1 && k < cs.len() && cs[k] == ':' {
                keys.push(text);
            }
            i = j + 1;
            continue;
        }
        if c == '{' {
            depth += 1;
        } else if c == '}' {
            depth -= 1;
            if depth <= 0 {
                break;
            }
        }
        i += 1;
    }
    Some(keys)
}

/// `None` when the key list is exactly the contract; otherwise the reason.
pub fn key_order_problem(keys: &[String]) -> Option<String> {
    if keys.is_empty() {
        return Some("no top-level keys".to_string());
    }
    for (i, req) in REQUIRED_KEYS.iter().enumerate() {
        match keys.get(i) {
            Some(k) if k == req => {}
            Some(k) => {
                return Some(format!(
                    "required key {req} is at position {}, not {} (found {k})",
                    i + 1,
                    1
                ))
            }
            None => return Some(format!("missing required key {req}")),
        }
    }
    let mut idx = 0usize;
    for k in keys {
        match CONTRACT_KEY_ORDER[idx..].iter().position(|c| c == k) {
            Some(off) => idx += off + 1,
            None => return Some(format!("key {k:?} is not in the frozen field order")),
        }
    }
    None
}

/// `SETUP abort_ms=N -> STATUS len=L` — the legacy log's async attempt.
pub fn parse_legacy_abort(s: &str) -> Option<(u32, String, u64)> {
    let rest = s.trim().strip_prefix("SETUP abort_ms=")?;
    let (ms, rest) = rest.split_once(" -> ")?;
    let ms: u32 = ms.trim().parse().ok()?;
    let (status, rest) = rest.split_once(" len=")?;
    let len: u64 = rest.trim().parse().ok()?;
    Some((ms, status.trim().to_ascii_uppercase(), len))
}

/// `SETUP pad request (N bytes) -> STATUS len=L`.
pub fn parse_legacy_pad(s: &str) -> Option<(u32, String, u64)> {
    let rest = s.trim().strip_prefix("SETUP pad request (")?;
    let (bytes, rest) = rest.split_once(" bytes) -> ")?;
    let bytes: u32 = bytes.trim().parse().ok()?;
    let (status, rest) = rest.split_once(" len=")?;
    let len: u64 = rest.trim().parse().ok()?;
    Some((bytes, status.trim().to_ascii_uppercase(), len))
}

fn opt_u64(v: &Value, key: &str, bad: &mut Vec<String>) -> Option<u64> {
    match v.get(key) {
        None | Some(Value::Null) => None,
        Some(x) => match x.as_u64() {
            Some(n) => Some(n),
            None => {
                bad.push(format!("{key} is not a non-negative integer"));
                None
            }
        },
    }
}

fn opt_i64(v: &Value, key: &str, bad: &mut Vec<String>) -> Option<i64> {
    match v.get(key) {
        None | Some(Value::Null) => None,
        Some(x) => match x.as_i64() {
            Some(n) => Some(n),
            None => {
                bad.push(format!("{key} is not an integer"));
                None
            }
        },
    }
}

fn opt_str(v: &Value, key: &str, bad: &mut Vec<String>) -> Option<String> {
    match v.get(key) {
        None | Some(Value::Null) => None,
        Some(x) => match x.as_str() {
            Some(s) => Some(s.to_string()),
            None => {
                bad.push(format!("{key} is not a string"));
                None
            }
        },
    }
}

fn opt_byte(v: &Value, key: &str, bad: &mut Vec<String>) -> Option<u8> {
    match opt_u64(v, key, bad) {
        Some(n) if n <= u8::MAX as u64 => Some(n as u8),
        Some(n) => {
            bad.push(format!("{key}={n} does not fit u8"));
            None
        }
        None => None,
    }
}

fn opt_u32(v: &Value, key: &str, bad: &mut Vec<String>) -> Option<u32> {
    match opt_u64(v, key, bad) {
        Some(n) if n <= u32::MAX as u64 => Some(n as u32),
        Some(n) => {
            bad.push(format!("{key}={n} does not fit u32"));
            None
        }
        None => None,
    }
}

/// Read and summarise one trace file. Never panics; unreadable lines become
/// [`BadLine`]s on the returned summary, not errors.
pub fn load(path: &Path) -> Result<Summary, LoadError> {
    let bytes = fs::read(path).map_err(|err| LoadError::Io {
        path: path.to_path_buf(),
        err,
    })?;
    Ok(load_bytes(&path.display().to_string(), &bytes))
}

/// [`load`] for bytes already in hand (used by tests and by stdin users).
pub fn load_bytes(path: &str, bytes: &[u8]) -> Summary {
    let sha256 = sha256_hex(bytes);
    let text = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = text.lines().collect();

    // Pass 1 — which dialects are actually present?
    let mut n_json = 0usize;
    let mut n_legacy = 0usize;
    for l in &lines {
        let t = l.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('{') {
            n_json += 1;
        } else if parse_legacy_abort(t).is_some() || parse_legacy_pad(t).is_some() {
            n_legacy += 1;
        }
    }
    let dialect = match (n_json > 0, n_legacy > 0) {
        (true, true) => Dialect::Mixed,
        (true, false) => Dialect::Jsonl,
        (false, true) => Dialect::LegacyA9ctl,
        (false, false) => Dialect::Unknown,
    };

    let mut s = Summary {
        path: path.to_string(),
        bytes: bytes.len() as u64,
        sha256,
        dialect,
        lines_total: lines.len(),
        ..Default::default()
    };

    let mut last_seq: Option<(usize, u64)> = None;
    let mut events_by_kind: BTreeMap<String, u64> = BTreeMap::new();
    let mut setup = SetupSummary::default();
    let mut spray = SpraySummary::default();
    let mut resets = ResetSummary::default();

    for (idx, raw) in lines.iter().enumerate() {
        let n = idx + 1;
        let t = raw.trim();
        if t.is_empty() {
            s.lines_blank += 1;
            continue;
        }

        // Every line, in every dialect, is scanned for the success token: it is
        // the one thing a reader looks for first, and it may arrive as an event
        // detail rather than a record.
        if s.pwned_hit.is_none() && t.contains("PWND:[checkm8]") {
            s.pwned_hit = Some(PwnedHit {
                line: n,
                text: excerpt(t, 160),
            });
        }

        if t.starts_with('{') {
            match parse_jsonl_line(n, t) {
                Ok(parsed) => {
                    if let Some(prob) = key_order_problem(&top_level_keys(t).unwrap_or_default()) {
                        s.key_order_violations.push(BadLine {
                            line: n,
                            why: prob,
                            excerpt: excerpt(t, 120),
                        });
                    }
                    match parsed {
                        Parsed::Xfer(x) => {
                            note_seq(&mut s.seq, &mut last_seq, n, x.seq);
                            absorb_xfer(&mut s, &mut setup, &mut spray, x);
                        }
                        Parsed::Event(e) => {
                            note_seq(&mut s.seq, &mut last_seq, n, e.seq);
                            absorb_event(&mut s, &mut resets, &mut events_by_kind, e);
                        }
                    }
                }
                Err(why) => s.malformed.push(BadLine {
                    line: n,
                    why,
                    excerpt: excerpt(t, 120),
                }),
            }
            continue;
        }

        if let Some((ms, status, len)) = parse_legacy_abort(t) {
            absorb_xfer(
                &mut s,
                &mut setup,
                &mut spray,
                Xfer {
                    line: n,
                    seq: None,
                    stage: "SETUP".to_string(),
                    t_micros: None,
                    label: Some("async-abort".to_string()),
                    status,
                    bm: None, // not in this dialect; must not be invented
                    b: None,
                    w_value: None,
                    w_index: None,
                    w_length: None,
                    transferred: Some(len),
                    requested: None,
                    micros: None,
                    libusb_rc: None,
                    abort_after_ms: Some(ms),
                    xfer_seq: None,
                    dialect: Dialect::LegacyA9ctl,
                },
            );
            continue;
        }
        if let Some((bytes_len, status, len)) = parse_legacy_pad(t) {
            absorb_xfer(
                &mut s,
                &mut setup,
                &mut spray,
                Xfer {
                    line: n,
                    seq: None,
                    stage: "SETUP".to_string(),
                    t_micros: None,
                    label: Some("pad-request".to_string()),
                    status,
                    bm: None,
                    b: None,
                    w_value: None,
                    w_index: None,
                    w_length: Some(bytes_len),
                    transferred: Some(len),
                    requested: None,
                    micros: None,
                    libusb_rc: None,
                    abort_after_ms: None,
                    xfer_seq: None,
                    dialect: Dialect::LegacyA9ctl,
                },
            );
            continue;
        }

        if dialect == Dialect::LegacyA9ctl {
            s.notes_total += 1;
            if s.notes.len() < 20 {
                s.notes.push(Note {
                    line: n,
                    text: excerpt(t, 160),
                });
            }
        } else {
            s.unrecognised.push(BadLine {
                line: n,
                why: "not a JSON object and not a legacy a9ctl record".to_string(),
                excerpt: excerpt(t, 120),
            });
        }
    }

    s.events_by_kind = events_by_kind;
    s.resets = resets;
    finalise(&mut s, setup, spray);
    s
}

enum Parsed {
    Xfer(Xfer),
    Event(Event),
}

fn parse_jsonl_line(n: usize, t: &str) -> Result<Parsed, String> {
    let v: Value = serde_json::from_str(t).map_err(|e| format!("invalid JSON ({e})"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "top-level JSON value is not an object".to_string())?;
    let mut bad: Vec<String> = Vec::new();
    for k in REQUIRED_KEYS {
        if !obj.contains_key(k) {
            bad.push(format!("missing required key {k}"));
        }
    }
    let seq = opt_u64(&v, "seq", &mut bad);
    let stage = opt_str(&v, "stage", &mut bad);
    let kind = opt_str(&v, "kind", &mut bad);
    let t_micros = opt_u64(&v, "t_micros", &mut bad);
    if !bad.is_empty() {
        return Err(bad.join("; "));
    }
    let kind = kind.expect("checked present above");
    let stage_raw = stage.expect("checked present above");
    let stage_opt = if stage_raw == "-" { None } else { Some(stage_raw) };

    if kind == "xfer" {
        let status = opt_str(&v, "status", &mut bad);
        if status.is_none() {
            bad.push("xfer line without a status".to_string());
        }
        let x = Xfer {
            line: n,
            seq,
            stage: stage_opt.unwrap_or_else(|| "-".to_string()),
            t_micros,
            label: opt_str(&v, "label", &mut bad),
            status: status.unwrap_or_default(),
            bm: opt_byte(&v, "bm_request_type", &mut bad),
            b: opt_byte(&v, "b_request", &mut bad),
            w_value: opt_u32(&v, "w_value", &mut bad),
            w_index: opt_u32(&v, "w_index", &mut bad),
            w_length: opt_u32(&v, "w_length", &mut bad),
            transferred: opt_u64(&v, "transferred", &mut bad),
            requested: opt_u64(&v, "requested", &mut bad),
            micros: opt_u64(&v, "xfer_micros", &mut bad),
            libusb_rc: opt_i64(&v, "libusb_rc", &mut bad),
            abort_after_ms: opt_u32(&v, "abort_after_ms", &mut bad),
            xfer_seq: opt_u64(&v, "xfer_seq", &mut bad),
            dialect: Dialect::Jsonl,
        };
        if !bad.is_empty() {
            return Err(bad.join("; "));
        }
        return Ok(Parsed::Xfer(x));
    }

    if kind == "predicate" {
        if !obj.contains_key("label") {
            bad.push("predicate line without a label (the predicate code)".to_string());
        }
        if !obj.contains_key("status") {
            bad.push("predicate line without a PASS/FAIL status".to_string());
        }
    }
    let e = Event {
        line: n,
        seq,
        stage: stage_opt,
        kind,
        t_micros,
        label: opt_str(&v, "label", &mut bad),
        detail: opt_str(&v, "detail", &mut bad),
        status: opt_str(&v, "status", &mut bad),
    };
    if !bad.is_empty() {
        return Err(bad.join("; "));
    }
    Ok(Parsed::Event(e))
}

fn note_seq(sq: &mut SeqCheck, last: &mut Option<(usize, u64)>, line: usize, seq: Option<u64>) {
    let Some(seq) = seq else {
        sq.absent += 1;
        return;
    };
    sq.present += 1;
    sq.first.get_or_insert(seq);
    sq.last = Some(seq);
    if let Some((_, prev)) = *last {
        if seq <= prev {
            sq.out_of_order.push((line, prev, seq));
            if seq == prev {
                sq.duplicates += 1;
            }
        } else if seq > prev + 1 {
            sq.gaps.push((line, seq - prev - 1));
        }
    } else if seq != 1 {
        sq.gaps.push((line, seq - 1));
    }
    *last = Some((line, seq));
}

fn absorb_xfer(s: &mut Summary, setup: &mut SetupSummary, spray: &mut SpraySummary, x: Xfer) {
    s.records += 1;
    s.xfers.push(x.clone());
    *s.stage_status
        .entry((x.stage.clone(), x.status.clone()))
        .or_insert(0) += 1;

    if let Some(t) = x.t_micros {
        s.t_first = Some(s.t_first.map_or(t, |a| a.min(t)));
        s.t_last = Some(s.t_last.map_or(t, |a| a.max(t)));
    }

    if x.stage == "SETUP" {
        if x.is_setup_attempt() {
            setup.attempts += 1;
            match x.abort_after_ms {
                Some(w) => {
                    setup.windows_ordered.push(w);
                    if !setup.windows_distinct.contains(&w) {
                        setup.windows_distinct.push(w);
                    }
                }
                None => setup.windows_unreported += 1,
            }
            if let Some(m) = x.micros {
                setup.micros_present += 1;
                // A window of 0 ms is gaster's legitimate starting point and may
                // genuinely return in under a microsecond. A non-zero window that
                // returns in under 100 us did not wait.
                if x.status == "CANCELLED" && m < 100 && matches!(x.abort_after_ms, Some(w) if w >= 1)
                {
                    setup.early_cancels += 1;
                }
            }
            if x.status == "OK" {
                if let (Some(tr), Some(rq)) = (x.transferred, x.requested) {
                    if rq > 0 && tr >= rq {
                        setup.abort_full += 1;
                    }
                }
            }
            if x.status == "TIMEOUT" {
                setup.abort_timeouts += 1;
            }
        } else if x.is_pad_request() {
            setup.pad_requests += 1;
            if let Some(l) = x.w_length {
                if !setup.pad_sizes_distinct.contains(&l) {
                    setup.pad_sizes_distinct.push(l);
                }
            }
            match x.status.as_str() {
                "STALL" => setup.pad_stall += 1,
                "TIMEOUT" => setup.pad_timeout += 1,
                "ERROR" | "NO_DEVICE" => setup.pad_error += 1,
                "OK" => setup.pad_ok += 1,
                "CANCELLED" => setup.pad_cancelled += 1,
                _ => setup.pad_other += 1,
            }
        } else {
            setup.other_transfers += 1;
        }
    }

    if x.stage == "SPRAY" {
        if x.is_spray_stall_request() {
            spray.stall_requests += 1;
            if x.status != "STALL" {
                spray.stall_not_stalling += 1;
            }
        } else if x.is_spray_leak_request() {
            spray.leak_requests += 1;
            if x.transferred.unwrap_or(0) > 0 {
                spray.leak_not_zero += 1;
            }
        }
    }
}

fn absorb_event(
    s: &mut Summary,
    resets: &mut ResetSummary,
    kinds: &mut BTreeMap<String, u64>,
    e: Event,
) {
    s.records += 1;
    *kinds.entry(e.kind.clone()).or_insert(0) += 1;
    if let Some(t) = e.t_micros {
        s.t_first = Some(s.t_first.map_or(t, |a| a.min(t)));
        s.t_last = Some(s.t_last.map_or(t, |a| a.max(t)));
    }

    match e.kind.as_str() {
        "reset" => {
            resets.attempted += 1;
            if let Some(d) = &e.detail {
                resets.details.push(d.clone());
            }
        }
        "reset_real" => {
            resets.attempted += 1;
            resets.real += 1;
            if let Some(d) = &e.detail {
                resets.details.push(d.clone());
            }
        }
        "reset_pipe_cycle" => {
            resets.attempted += 1;
            resets.pipe_cycle += 1;
            if let Some(d) = &e.detail {
                resets.details.push(d.clone());
            }
        }
        "round" => {
            s.rounds += 1;
            if let Some(d) = &e.detail {
                if let Some(rest) = d.split("round=").nth(1) {
                    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    if let Ok(v) = num.parse::<u32>() {
                        s.max_round = Some(s.max_round.map_or(v, |a| a.max(v)));
                    }
                }
            }
        }
        "predicate" => match e.status.as_deref() {
            Some("FAIL") => {
                let code = e.label.clone().unwrap_or_else(|| "(no label)".to_string());
                *s.predicates.failed.entry(code.clone()).or_insert(0) += 1;
                if s.predicates.first_failure.is_none() {
                    s.predicates.first_failure =
                        Some((e.line, code, e.detail.clone().unwrap_or_default()));
                }
            }
            Some("PASS") => {
                let code = e.label.clone().unwrap_or_else(|| "(no label)".to_string());
                *s.predicates.passed.entry(code).or_insert(0) += 1;
            }
            other => {
                // A predicate line whose status is neither PASS nor FAIL is not a
                // measurement of the predicate; say so rather than guess.
                s.unrecognised.push(BadLine {
                    line: e.line,
                    why: format!("predicate line with status {other:?} (expected PASS or FAIL)"),
                    excerpt: e.detail.clone().unwrap_or_default(),
                });
            }
        },
        "enumerated" => {
            if let Some(d) = &e.detail {
                s.enumerated.push(d.clone());
            }
        }
        "device_path" => {
            if let Some(d) = &e.detail {
                s.device_path.push(d.clone());
            }
        }
        "open_failed" => {
            if let Some(d) = &e.detail {
                s.open_failed.push(d.clone());
            }
        }
        _ => {}
    }
}

fn finalise(s: &mut Summary, mut setup: SetupSummary, spray: SpraySummary) {
    setup.repeats_back_to_back = 0;
    for w in setup.windows_ordered.windows(2) {
        if w[0] == w[1] {
            setup.repeats_back_to_back += 1;
        }
    }
    setup.period = smallest_period(&setup.windows_ordered);
    s.setup = setup;
    s.spray = spray;
    s.xfers.sort_by_key(|x| x.line);
    s.events.sort_by_key(|e| e.line);
}

/// Smallest `p` with `seq[i] == seq[i % p]` for every `i`, when at least two full
/// cycles fit. Exact repetition only: a near-period is not a period.
pub fn smallest_period(seq: &[u32]) -> Option<usize> {
    let n = seq.len();
    if n < 2 {
        return None;
    }
    (1..=n / 2).find(|&p| (p..n).all(|i| seq[i] == seq[i % p]))
}

/// Run-length encode, for rendering a long sweep compactly and exactly.
pub fn runs(seq: &[u32]) -> Vec<(u32, usize)> {
    let mut out: Vec<(u32, usize)> = Vec::new();
    for &v in seq {
        match out.last_mut() {
            Some((last, n)) if *last == v => *n += 1,
            _ => out.push((v, 1)),
        }
    }
    out
}

// --------------------------------------------------------------------- flags

impl Summary {
    /// Signals a reader must not miss. Ordered alarm-first.
    pub fn flags(&self) -> Vec<Flag> {
        let mut out: Vec<Flag> = Vec::new();
        let mut push = |severity: Severity, text: String| out.push(Flag { severity, text });

        if !self.malformed.is_empty() {
            push(
                Severity::Alarm,
                format!(
                    "{} malformed line(s): this file is NOT a complete trace, and every count below is over the lines that did parse",
                    self.malformed.len()
                ),
            );
        }
        if !self.unrecognised.is_empty() {
            push(
                Severity::Warn,
                format!(
                    "{} line(s) recognised as neither dialect (see the list below)",
                    self.unrecognised.len()
                ),
            );
        }
        if !self.key_order_violations.is_empty() {
            push(
                Severity::Warn,
                format!(
                    "{} line(s) break the frozen field order of INTERFACE.md §5 — a reader that indexes by position, or a byte-diff against another run, is not safe on this file",
                    self.key_order_violations.len()
                ),
            );
        }
        if !self.seq.out_of_order.is_empty() {
            push(
                Severity::Warn,
                format!(
                    "seq is not strictly increasing at {} line(s) ({} duplicate(s)) — either two runs were concatenated or the tracer was reused",
                    self.seq.out_of_order.len(),
                    self.seq.duplicates
                ),
            );
        }
        if !self.seq.gaps.is_empty() {
            let missing: u64 = self.seq.gaps.iter().map(|(_, m)| *m).sum();
            push(
                Severity::Warn,
                format!("seq has {missing} missing value(s) in {} gap(s)", self.seq.gaps.len()),
            );
        }

        let su = &self.setup;
        if su.pad_timeout > 0 && su.pad_stall == 0 {
            push(
                Severity::Alarm,
                format!(
                    "SETUP pad requests never STALLed: {} TIMEOUT, 0 STALL. gaster.c:853 makes STALL the pass condition; a TIMEOUT is the device NAKing, which is the failure this rewrite exists to name (a9pwn verdict PAD_TIMEOUT_NOT_STALL)",
                    su.pad_timeout
                ),
            );
        }
        if su.pad_stall > 0 {
            push(
                Severity::Info,
                format!(
                    "SETUP pad request STALLed {} time(s) — gaster.c:853's pass condition was reached",
                    su.pad_stall
                ),
            );
        }
        if su.pinned() {
            push(
                Severity::Alarm,
                format!(
                    "PINNED SWEEP: {} attempts used exactly one abort window {:?}. gaster.c:857 advances the window every failed attempt, so a single window means the modulus collapsed (usb_timeout == abort_min) and the sweep cannot converge",
                    su.attempts, su.windows_distinct
                ),
            );
        } else if su.repeats_back_to_back > 0 {
            push(
                Severity::Warn,
                format!(
                    "{} attempt(s) reused the previous abort window — the advance in gaster.c:857 did not fire every time",
                    su.repeats_back_to_back
                ),
            );
        }
        if su.early_cancels > 0 {
            push(
                Severity::Alarm,
                format!(
                    "{} async abort(s) returned CANCELLED in under 100 us on a window of 1 ms or more: the transfer never waited, so it never reached the wire (the a9ctl defect this project replaced)",
                    su.early_cancels
                ),
            );
        }
        if su.windows_unreported > 0 {
            push(
                Severity::Warn,
                format!(
                    "{} SETUP attempt(s) carry no abort window — the sweep cannot be audited from this file",
                    su.windows_unreported
                ),
            );
        }
        if su.attempts > 0 && su.pad_requests == 0 && su.other_transfers == 0 {
            push(
                Severity::Info,
                format!(
                    "{} SETUP attempt(s) and no pad request: the first clause of gaster.c:853 (transferred < overwrite_pad) never held, so the pad branch was never reached",
                    su.attempts
                ),
            );
        }
        if su.micros_present == 0 && su.attempts > 0 {
            push(
                Severity::Info,
                format!(
                    "this dialect carries no xfer_micros, so the {} SETUP attempt(s) cannot be checked for a cancel that did not wait its window; absence here is not evidence of correct timing",
                    su.attempts
                ),
            );
        }

        let r = &self.resets;
        if r.attempted > 0 && r.real == 0 {
            if r.pipe_cycle > 0 {
                push(
                    Severity::Alarm,
                    format!(
                        "{} reset(s) attempted, 0 delivered as a real bus reset, {} recorded as pipe-cycle only. checkm8 cannot fire through a pipe cycle (research/RESET-OPTIONS.md)",
                        r.attempted, r.pipe_cycle
                    ),
                );
            } else {
                push(
                    Severity::Warn,
                    format!(
                        "{} reset(s) attempted with no reset_real and no reset_pipe_cycle line: delivery was never recorded, which is not the same as no delivery",
                        r.attempted
                    ),
                );
            }
        }
        if r.real > 0 {
            push(
                Severity::Info,
                format!("{} reset(s) recorded as genuinely delivered", r.real),
            );
        }

        if self.enumerated.is_empty() && self.records > 0 {
            push(
                Severity::Warn,
                "no `enumerated` event in this trace: the discovery record is absent, so \"no device\" and \"nobody looked\" cannot be told apart from this file alone".to_string(),
            );
        }
        if !self.open_failed.is_empty() {
            push(
                Severity::Warn,
                format!("{} open failure(s) recorded", self.open_failed.len()),
            );
        }
        if let Some(h) = &self.pwned_hit {
            push(
                Severity::Info,
                format!("PWND:[checkm8] present at line {} — the success token is in this trace", h.line),
            );
        } else {
            push(
                Severity::Info,
                "no PWND:[checkm8] token anywhere in this file. That is a statement about the FILE, not about the device: a9pwn's own verdict line is the authority on the device.".to_string(),
            );
        }
        for (code, n) in &self.predicates.failed {
            push(
                Severity::Warn,
                format!("reference predicate {code} failed {n} time(s)"),
            );
        }
        if self.records == 0 {
            push(
                Severity::Alarm,
                "no records parsed from this file at all — nothing below is a measurement".to_string(),
            );
        }

        out.sort_by_key(|f| f.severity);
        out
    }
}

// --------------------------------------------------------------------- render

/// Stable, greppable, no colour. The same shape every time so two runs can be
/// diffed by eye or by line number.
pub fn render(s: &Summary) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "traceview {VERSION} — a9pwn trace summary (reads a file; sends nothing, touches no hardware)"
    );
    let _ = writeln!(o, "  file            : {}", s.path);
    let _ = writeln!(o, "  bytes           : {}", s.bytes);
    let _ = writeln!(o, "  sha256          : {}", s.sha256);
    let _ = writeln!(o, "  dialect         : {}", s.dialect.as_str());
    let _ = writeln!(
        o,
        "  lines           : {} total, {} blank, {} record(s), {} malformed, {} unrecognised",
        s.lines_total,
        s.lines_blank,
        s.records,
        s.malformed.len(),
        s.unrecognised.len()
    );

    let sq = &s.seq;
    if sq.present == 0 && sq.absent == 0 {
        let _ = writeln!(o, "  seq             : no seq field in this dialect");
    } else {
        let _ = writeln!(
            o,
            "  seq             : {} present, {} absent, range {}..{}",
            sq.present,
            sq.absent,
            sq.first.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
            sq.last.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
        );
    }
    match (s.t_first, s.t_last) {
        (Some(a), Some(b)) => {
            let _ = writeln!(
                o,
                "  t_micros span   : {a} .. {b}  ({:.3} s)",
                (b.saturating_sub(a)) as f64 / 1_000_000.0
            );
        }
        _ => {
            let _ = writeln!(o, "  t_micros span   : absent from this dialect");
        }
    }
    let key_total = s.records;
    if s.key_order_violations.is_empty() {
        let _ = writeln!(o, "  field order     : contract-ok on all {key_total} record line(s)");
    } else {
        let _ = writeln!(
            o,
            "  field order     : {} of {key_total} record line(s) OUT OF CONTRACT",
            s.key_order_violations.len()
        );
    }
    // The one thing a reader looks for first, stated before anything else and
    // stated as a fact about the file rather than about the device.
    match &s.pwned_hit {
        Some(h) => {
            let _ = writeln!(
                o,
                "  pwned token     : FOUND at line {} — PWND:[checkm8] is in this file",
                h.line
            );
        }
        None => {
            let _ = writeln!(
                o,
                "  pwned token     : not present anywhere in this file (a statement about the file, not about the device)"
            );
        }
    }

    // ---- transfers per stage/status
    let stages = s.stages_seen();
    let statuses = s.statuses_seen();
    let _ = writeln!(o, "\n  transfers per stage (derived from this file, not from a9pwn's counters)");
    if stages.is_empty() {
        let _ = writeln!(o, "    (no transfer records)");
    } else {
        let mut head = String::from("    stage     ");
        for st in &statuses {
            let _ = write!(head, "{st:>11}");
        }
        let _ = write!(head, "{:>8}", "total");
        let _ = writeln!(o, "{head}");
        for st in &stages {
            let mut row = format!("    {st:<10}");
            for status in &statuses {
                let _ = write!(row, "{:>11}", s.stage_status(st, status));
            }
            let _ = write!(row, "{:>8}", s.stage_total(st));
            let _ = writeln!(o, "{row}");
        }
        let mut row = String::from("    TOTAL     ");
        for status in &statuses {
            let _ = write!(row, "{:>11}", s.status_total(status));
        }
        let mut total = 0u64;
        for st in &stages {
            total += s.stage_total(st);
        }
        let _ = write!(row, "{total:>8}");
        let _ = writeln!(o, "{row}");
    }

    // ---- SETUP
    let su = &s.setup;
    let _ = writeln!(o, "\n  SETUP abort sweep");
    let _ = writeln!(o, "    attempts            : {}", su.attempts);
    if su.attempts > 0 {
        let _ = writeln!(o, "    windows in order    : {}", render_sweep(su));
        let _ = writeln!(
            o,
            "    distinct windows    : {} -> {:?}",
            su.windows_distinct.len(),
            su.windows_distinct
        );
        let _ = writeln!(
            o,
            "    back-to-back repeats: {}",
            su.repeats_back_to_back
        );
        let _ = writeln!(
            o,
            "    pinned sweep        : {}   (a9pwn's rule: attempts>=2 and exactly 1 distinct window)",
            if su.pinned() { "YES" } else { "no" }
        );
        let _ = writeln!(o, "    windows unreported  : {}", su.windows_unreported);
    }
    let _ = writeln!(
        o,
        "    pad requests        : {}  STALL={} TIMEOUT={} ERROR/NO_DEVICE={} OK={} CANCELLED={} other={}",
        su.pad_requests, su.pad_stall, su.pad_timeout, su.pad_error, su.pad_ok, su.pad_cancelled, su.pad_other
    );
    let _ = writeln!(o, "    pad sizes (distinct): {:?}", su.pad_sizes_distinct);
    let _ = writeln!(
        o,
        "    abort completed full: {}   abort timed out: {}",
        su.abort_full, su.abort_timeouts
    );
    let _ = writeln!(
        o,
        "    early cancels       : {}   (CANCELLED in <100 us on a window >=1 ms); xfer_micros present on {}/{} attempt(s)",
        su.early_cancels, su.micros_present, su.attempts
    );
    let _ = writeln!(
        o,
        "    other SETUP traffic : {}   (the 0x40 unstick, gaster.c:856)",
        su.other_transfers
    );

    // ---- SPRAY
    let sp = &s.spray;
    if sp.stall_requests > 0 || sp.leak_requests > 0 {
        let _ = writeln!(o, "\n  SPRAY");
        let _ = writeln!(
            o,
            "    stall requests      : {}  (of which did NOT stall: {})",
            sp.stall_requests, sp.stall_not_stalling
        );
        let _ = writeln!(
            o,
            "    leak/no-leak reads  : {}  (of which returned >0 bytes: {})",
            sp.leak_requests, sp.leak_not_zero
        );
    }

    // ---- resets
    let r = &s.resets;
    if r.attempted > 0 {
        let _ = writeln!(o, "\n  resets");
        let _ = writeln!(
            o,
            "    attempted={} real={} pipe_cycle={} delivery_unrecorded={}",
            r.attempted,
            r.real,
            r.pipe_cycle,
            r.attempted.saturating_sub(r.real + r.pipe_cycle)
        );
    }

    // ---- rounds and events
    if s.rounds > 0 {
        let _ = writeln!(
            o,
            "\n  rounds                : {}{}",
            s.rounds,
            s.max_round.map(|m| format!(" (max round={m})")).unwrap_or_default()
        );
    }
    if !s.events_by_kind.is_empty() {
        let _ = writeln!(o, "\n  events by kind");
        for (k, n) in &s.events_by_kind {
            let _ = writeln!(o, "    {k:<20} {n}");
        }
    }

    // ---- discovery
    if !s.enumerated.is_empty() || !s.device_path.is_empty() || !s.open_failed.is_empty() {
        let _ = writeln!(o, "\n  discovery");
        for d in &s.enumerated {
            let _ = writeln!(o, "    enumerated : {d}");
        }
        for d in &s.device_path {
            let _ = writeln!(o, "    path len   : {d}");
        }
        for d in &s.open_failed {
            let _ = writeln!(o, "    open failed: {d}");
        }
    }

    // ---- predicates
    if !s.predicates.passed.is_empty() || !s.predicates.failed.is_empty() {
        let _ = writeln!(o, "\n  reference predicates");
        let mut codes: Vec<&String> = s
            .predicates
            .passed
            .keys()
            .chain(s.predicates.failed.keys())
            .collect();
        codes.sort();
        codes.dedup();
        for code in codes {
            let p = s.predicates.passed.get(code).copied().unwrap_or(0);
            let f = s.predicates.failed.get(code).copied().unwrap_or(0);
            let _ = writeln!(o, "    {code:<32} PASS={p} FAIL={f}");
        }
        if let Some((line, code, detail)) = &s.predicates.first_failure {
            let _ = writeln!(o, "    first failure: line {line} {code} | {}", excerpt(detail, 140));
        }
    }

    // ---- notes
    if !s.notes.is_empty() {
        let _ = writeln!(o, "\n  non-record lines ({} total)", s.notes_total);
        for n in &s.notes {
            let _ = writeln!(o, "    line {:<6} {}", n.line, n.text);
        }
    }

    // ---- flags
    let flags = s.flags();
    let _ = writeln!(o, "\n  signals (ALARM = contradicts a documented pass condition)");
    if flags.is_empty() {
        let _ = writeln!(o, "    (none)");
    }
    for f in &flags {
        let _ = writeln!(o, "    [{}] {}", f.severity.tag(), f.text);
    }

    // ---- bad lines
    render_bad_lines(&mut o, "malformed lines", &s.malformed, 10);
    render_bad_lines(&mut o, "unrecognised lines", &s.unrecognised, 10);
    render_bad_lines(&mut o, "field-order violations", &s.key_order_violations, 5);
    if !s.seq.out_of_order.is_empty() {
        let _ = writeln!(o, "\n  seq out of order");
        for (line, prev, cur) in s.seq.out_of_order.iter().take(10) {
            let _ = writeln!(o, "    line {line}: seq={cur} after seq={prev}");
        }
    }
    if !s.seq.gaps.is_empty() {
        let _ = writeln!(o, "\n  seq gaps");
        for (line, missing) in s.seq.gaps.iter().take(10) {
            let _ = writeln!(o, "    line {line}: {missing} value(s) missing");
        }
    }

    let _ = writeln!(
        o,
        "\n  reading: every number above is derived from the fields on the lines of this file.\n           Absent fields are reported as absent, never as zero. This tool has not\n           touched the device and does not know anything the file does not say."
    );
    o
}

fn render_sweep(su: &SetupSummary) -> String {
    let w = &su.windows_ordered;
    if w.is_empty() {
        return "(none reported)".to_string();
    }
    if let Some(p) = su.period {
        if p < w.len() && p > 0 {
            return format!(
                "{:?} x {}  (exact period {p} over {} attempt(s))",
                &w[..p],
                w.len() / p,
                w.len()
            );
        }
    }
    let shown: Vec<String> = w.iter().take(24).map(|v| v.to_string()).collect();
    if w.len() <= 24 {
        format!("[{}]", shown.join(", "))
    } else {
        format!("[{}] … +{} more", shown.join(", "), w.len() - 24)
    }
}

fn render_bad_lines(o: &mut String, title: &str, lines: &[BadLine], limit: usize) {
    if lines.is_empty() {
        return;
    }
    let _ = writeln!(o, "\n  {title} ({} total)", lines.len());
    for b in lines.iter().take(limit) {
        let _ = writeln!(o, "    line {:<6} {} | {}", b.line, b.why, b.excerpt);
    }
    if lines.len() > limit {
        let _ = writeln!(o, "    … +{} more", lines.len() - limit);
    }
}

// ----------------------------------------------------------------- JSON form

/// The same measurements as [`render`], as one JSON object, for diffing two runs
/// or for embedding in a report. Keys are stable.
pub fn to_json(s: &Summary) -> Value {
    let su = &s.setup;
    let stage_status: Vec<Value> = s
        .stage_status
        .iter()
        .map(|((st, status), n)| json!({"stage": st, "status": status, "count": n}))
        .collect();
    let bad = |v: &Vec<BadLine>| -> Value {
        Value::Array(
            v.iter()
                .map(|b| json!({"line": b.line, "why": b.why, "excerpt": b.excerpt}))
                .collect(),
        )
    };
    let flags: Vec<Value> = s
        .flags()
        .iter()
        .map(|f| json!({"severity": f.severity.tag().trim(), "text": f.text}))
        .collect();

    json!({
        "tool": "traceview",
        "version": VERSION,
        "schema": 1,
        "file": s.path,
        "bytes": s.bytes,
        "sha256": s.sha256,
        "dialect": s.dialect.as_str(),
        "lines": {
            "total": s.lines_total,
            "blank": s.lines_blank,
            "records": s.records,
            "malformed": s.malformed.len(),
            "unrecognised": s.unrecognised.len(),
        },
        "seq": {
            "present": s.seq.present,
            "absent": s.seq.absent,
            "first": s.seq.first,
            "last": s.seq.last,
            "out_of_order": s.seq.out_of_order.len(),
            "duplicates": s.seq.duplicates,
            "gaps": s.seq.gaps.len(),
        },
        "t_micros": {"first": s.t_first, "last": s.t_last},
        "key_order_violations": s.key_order_violations.len(),
        "stage_status": stage_status,
        "setup": {
            "attempts": su.attempts,
            "windows_ordered": su.windows_ordered,
            "windows_distinct": su.windows_distinct,
            "period": su.period,
            "repeats_back_to_back": su.repeats_back_to_back,
            "pinned": su.pinned(),
            "windows_unreported": su.windows_unreported,
            "pad_requests": su.pad_requests,
            "pad_stall": su.pad_stall,
            "pad_timeout": su.pad_timeout,
            "pad_error": su.pad_error,
            "pad_ok": su.pad_ok,
            "pad_cancelled": su.pad_cancelled,
            "pad_other": su.pad_other,
            "pad_sizes_distinct": su.pad_sizes_distinct,
            "abort_full": su.abort_full,
            "abort_timeouts": su.abort_timeouts,
            "early_cancels": su.early_cancels,
            "micros_present": su.micros_present,
            "other_transfers": su.other_transfers,
        },
        "spray": {
            "stall_requests": s.spray.stall_requests,
            "stall_not_stalling": s.spray.stall_not_stalling,
            "leak_requests": s.spray.leak_requests,
            "leak_not_zero": s.spray.leak_not_zero,
        },
        "resets": {
            "attempted": s.resets.attempted,
            "real": s.resets.real,
            "pipe_cycle": s.resets.pipe_cycle,
        },
        "rounds": s.rounds,
        "max_round": s.max_round,
        "enumerated": s.enumerated,
        "device_path": s.device_path,
        "open_failed": s.open_failed,
        "predicates": {
            "passed": s.predicates.passed,
            "failed": s.predicates.failed,
            "first_failure": s.predicates.first_failure.as_ref().map(|(l, c, d)| json!({"line": l, "code": c, "detail": d})),
        },
        "events_by_kind": s.events_by_kind,
        "pwned_marker": s.pwned_hit.as_ref().map(|h| json!({"line": h.line, "text": h.text})),
        "malformed": bad(&s.malformed),
        "unrecognised": bad(&s.unrecognised),
        "field_order_problems": bad(&s.key_order_violations),
        "flags": flags,
    })
}

// ----------------------------------------------------------------- unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smallest_period_finds_exact_repetition_only() {
        assert_eq!(smallest_period(&[4, 5, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3]), Some(6));
        assert_eq!(smallest_period(&[3, 3, 3, 3]), Some(1));
        assert_eq!(smallest_period(&[1, 2, 3]), None);
        assert_eq!(smallest_period(&[1]), None);
        assert_eq!(smallest_period(&[]), None);
        // A near-period is not a period, and the longest legal period must fit
        // twice: [1,2,3,4] over 4 values is not two cycles of anything.
        assert_eq!(smallest_period(&[1, 2, 3, 4]), None);
    }

    #[test]
    fn runs_are_exact() {
        assert_eq!(runs(&[1, 1, 2, 3, 3, 3]), vec![(1, 2), (2, 1), (3, 3)]);
        assert_eq!(runs(&[]), Vec::<(u32, usize)>::new());
    }

    #[test]
    fn top_level_keys_ignores_keys_inside_string_values() {
        let line = r#"{"seq":1,"stage":"SETUP","kind":"event","t_micros":5,"detail":"{\"seq\":99,\"kind\":\"fake\"}"}"#;
        let keys = top_level_keys(line).expect("keys");
        assert_eq!(keys, vec!["seq", "stage", "kind", "t_micros", "detail"]);
        assert!(key_order_problem(&keys).is_none());
    }

    #[test]
    fn top_level_keys_rejects_a_truncated_line_instead_of_guessing() {
        assert!(top_level_keys(r#"{"seq":2,"stage":"SET"#).is_none());
        assert!(top_level_keys("not json").is_none());
        assert_eq!(top_level_keys("{}"), Some(vec![]));
    }

    #[test]
    fn key_order_violations_are_detected() {
        let ok = ["seq", "stage", "kind", "t_micros", "status"];
        assert!(key_order_problem(&ok.map(String::from)).is_none());
        let swapped = ["stage", "seq", "kind", "t_micros"];
        assert!(key_order_problem(&swapped.map(String::from)).is_some());
        let out_of_order = ["seq", "stage", "kind", "t_micros", "status", "label"];
        assert!(key_order_problem(&out_of_order.map(String::from)).is_some());
        let unknown = ["seq", "stage", "kind", "t_micros", "mystery"];
        assert!(key_order_problem(&unknown.map(String::from)).is_some());
        let missing = ["seq", "stage", "kind"];
        assert!(key_order_problem(&missing.map(String::from)).is_some());
    }

    #[test]
    fn legacy_line_parsers_read_exactly_what_the_log_says() {
        assert_eq!(
            parse_legacy_abort("    SETUP abort_ms=4 -> Cancelled len=0"),
            Some((4, "CANCELLED".to_string(), 0))
        );
        assert_eq!(
            parse_legacy_pad("    SETUP pad request (1280 bytes) -> Timeout len=0"),
            Some((1280, "TIMEOUT".to_string(), 0))
        );
        assert_eq!(parse_legacy_abort("  device : CPID 0x8000"), None);
        assert_eq!(parse_legacy_pad("SETUP pad request (x bytes) -> Timeout len=0"), None);
    }

    #[test]
    fn setup_recognition_matches_trace_rs_rules() {
        let mut x = Xfer {
            line: 1,
            seq: None,
            stage: "SETUP".into(),
            t_micros: None,
            label: Some("async-abort".into()),
            status: "CANCELLED".into(),
            bm: Some(0x21),
            b: Some(0x01),
            w_value: Some(0),
            w_index: Some(0),
            w_length: Some(0x800),
            transferred: Some(0),
            requested: Some(0x800),
            micros: Some(3100),
            libusb_rc: None,
            abort_after_ms: Some(4),
            xfer_seq: Some(1),
            dialect: Dialect::Jsonl,
        };
        assert!(x.is_setup_attempt() && !x.is_pad_request());

        // The 0x40 unstick is neither.
        x.label = Some("unstick".into());
        x.abort_after_ms = None;
        x.w_length = Some(0x40);
        x.b = Some(0x01);
        assert!(!x.is_setup_attempt() && !x.is_pad_request());

        // The pad request is bm=0x00 b=0x00 wLength=1280 with no window.
        x.label = Some("pad-request".into());
        x.bm = Some(0x00);
        x.b = Some(0x00);
        x.w_length = Some(1280);
        assert!(!x.is_setup_attempt() && x.is_pad_request());

        // Structural recognition with no helpful label at all.
        x.label = Some("t7".into());
        assert!(x.is_pad_request());
    }

    #[test]
    fn spray_signatures_are_recognised_from_the_reference_request() {
        let base = Xfer {
            line: 1,
            seq: None,
            stage: "SPRAY".into(),
            t_micros: None,
            label: None,
            status: "STALL".into(),
            bm: Some(0x02),
            b: Some(0x03),
            w_value: None,
            w_index: Some(0x80),
            w_length: Some(0),
            transferred: Some(0),
            requested: Some(0),
            micros: None,
            libusb_rc: None,
            abort_after_ms: None,
            xfer_seq: None,
            dialect: Dialect::Jsonl,
        };
        assert!(base.is_spray_stall_request());
        let leak = Xfer {
            bm: Some(0x80),
            b: Some(0x06),
            w_index: Some(0x0A),
            w_length: Some(0x40),
            ..base.clone()
        };
        assert!(leak.is_spray_leak_request());
        let no_leak = Xfer {
            w_length: Some(0xC1),
            ..leak.clone()
        };
        assert!(no_leak.is_spray_leak_request());
        let clr = Xfer {
            bm: Some(0x21),
            b: Some(0x04),
            w_length: Some(0xC1),
            ..base.clone()
        };
        assert!(!clr.is_spray_leak_request() && !clr.is_spray_stall_request());
    }

    #[test]
    fn a_type_error_in_a_field_is_malformed_not_silently_absent() {
        let bytes = br#"{"seq":1,"stage":"SETUP","kind":"xfer","t_micros":5,"status":"OK","w_length":"1280"}
"#;
        let s = load_bytes("t.jsonl", bytes);
        assert_eq!(s.records, 0);
        assert_eq!(s.malformed.len(), 1);
        assert!(
            s.malformed[0].why.contains("w_length"),
            "{}",
            s.malformed[0].why
        );
    }

    #[test]
    fn sha256_matches_the_published_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
