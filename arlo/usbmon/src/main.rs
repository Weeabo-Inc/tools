//! usbmon — command-line view over the kernel's usbmon `u` text captures.
//!
//! Reads a file. Opens no device, needs no root, links no libusb. The debugfs
//! node is root-only; `tools/arlo/usbmon-capture.sh` reads it under sudo and
//! leaves a text file, and this tool is what makes that file an instrument.
//!
//! Every block of output carries its epistemic label: `[MEASURED]` (a value read
//! from the file), `[INSPECTED]` (a structural check over the file), `[INFERRED]`
//! (arithmetic or grouping this tool performed, not something the kernel said),
//! `[ERROR]`/`[WARNING]`/`[BOUNDARY]` (problems).

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use usbmon::*;

/// Output that does not panic when the reader goes away. `println!` panics on a
/// broken pipe, so `usbmon ... | head` aborted with exit 101 — a report must be
/// able to end in a pipe, and the exit code must stay the analysis verdict
/// rather than an I/O accident.
macro_rules! out {
    ($($arg:tt)*) => {{ let _ = write!(io::stdout(), $($arg)*); }};
}
macro_rules! outln {
    () => {{ let _ = writeln!(io::stdout()); }};
    ($($arg:tt)*) => {{ let _ = writeln!(io::stdout(), $($arg)*); }};
}

fn main() {
    let code = run();
    // Flush explicitly: a closed stdout pipe must not turn a report into a panic.
    let _ = io::stdout().flush();
    std::process::exit(code);
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Command {
    Summary,
    List,
    Attempts,
    Report,
    Json,
}

impl Command {
    fn parse(s: &str) -> Option<Command> {
        Some(match s {
            "summary" => Command::Summary,
            "list" => Command::List,
            "attempts" => Command::Attempts,
            "report" => Command::Report,
            "json" => Command::Json,
            _ => return None,
        })
    }
}

struct Cli {
    command: Command,
    file: Option<PathBuf>,
    filter: Filter,
    status_expansion: Option<String>,
    strict: bool,
    force: bool,
    expect_sha256: Option<String>,
    hash: bool,
    max_line_bytes: usize,
    plan: AttemptPlan,
    gaps_ms: u64,
    top: usize,
    redact: bool,
    host_log: Option<PathBuf>,
    no_host_log: bool,
    help: bool,
    version: bool,
}

impl Default for Cli {
    fn default() -> Self {
        Cli {
            command: Command::Summary,
            file: None,
            filter: Filter::default(),
            status_expansion: None,
            strict: false,
            force: false,
            expect_sha256: None,
            hash: true,
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            plan: AttemptPlan::default(),
            gaps_ms: 0,
            top: 0,
            redact: false,
            host_log: None,
            no_host_log: false,
            help: false,
            version: false,
        }
    }
}

const HELP: &str = r#"usbmon — read a Linux usbmon `u` text capture and report what the kernel recorded.

It reads a file. It opens no device, needs no root, and links no libusb.

usage:
  usbmon <FILE> [COMMAND] [OPTIONS]
  usbmon [COMMAND] <FILE> [OPTIONS]

commands (default: summary):
  summary    pairing, counts by device/request/status, descriptor lengths, non-OK completions
  list       one line per transfer (submit -> callback) in submit order
  attempts   group the SETUP tick: 0x800 DNLOAD -> 0x500 pad -> drain
  report     summary + attempts + non-OK completions: the whole story in one command
  json       the entire analysis as one JSON object (same as --json)

filters:
  --device BUS:ADDR     only URBs on this bus and device, e.g. --device 1:005
  --request NAME|NUM    DFU_DNLOAD, DNLOAD, 1, GET_DESCRIPTOR, 6, ...
  --endpoint EP         only this endpoint number
  --status NAME|NUM     OK | STALL (= -32 and -71) | TIMEOUT | CANCELLED | PENDING |
                        ECONNRESET | ESHUTDOWN | EREMOTEIO | EPIPE | EPROTO | a code
  --dir in|out          only IN or OUT transfers
  --type control|bulk|interrupt

options:
  --setup-len HEX       attempt-start DNLOAD wLength (default 0x800)
  --pad-len HEX         pad-request wLength (default 0x500)
  --drain-len HEX       drain DNLOAD wLength that closes a tick (default 0x40)
  --gaps-ms N           list: only transfers at least N ms after the previous event on the
                        same address (how a device absence shows up)
  --top N               limit rows in list/report descriptors (0 = no limit, the default)
  --strict              exit 6 if the file carried any warning (including a boundary completion)
  --force               print the analysis even when there are structural errors (exit stays 4)
  --expect-sha256 HEX   refuse to analyse unless the file hashes to HEX
  --no-sha256           do not hash the file (the report then cannot be pinned to bytes)
  --max-line-bytes N    reject a line longer than N (default 1048576)
  --redact-data         do not print captured data bytes
  --host-log FILE       join a9pwn's JSONL host trace (per-transfer stage/label and the
                        abort window the host asked for). Auto-discovers FILE.jsonl
  --no-host-log         never read a sibling host trace
  --json                same as the `json` command
  -h, --help            this text
  -V, --version

exit codes:
  0  read, parsed clean, at least one URB matched
  2  usage error
  3  the file could not be read
  4  structural errors: this is not usbmon `u` output the tool can trust
  5  parsed clean but nothing matched (empty file, or a filter that selected nothing)
  6  --strict and the file carried warnings
  7  --expect-sha256 mismatch

what this cannot say:
  * A submit with no callback line means "not in this file", never "the device refused".
  * usbmon's text interface prints at most 32 bytes of data per line (DATA_MAX,
    drivers/usb/mon/mon_text.c), so a 198-byte read shows 32 bytes and the tool says so
    instead of implying the payload.
  * usbmon timestamps are 32-bit microseconds and wrap every 4096 s; a backwards step is
    reported, never corrected silently.
"#;

fn run() -> i32 {
    let cli = match parse_args(std::env::args().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usbmon: {e}");
            eprintln!("usbmon: try `usbmon --help`");
            return EXIT_USAGE;
        }
    };
    if cli.help {
        out!("{HELP}");
        return EXIT_OK;
    }
    if cli.version {
        outln!("{TOOL} {TOOL_VERSION}");
        return EXIT_OK;
    }
    let Some(path) = cli.file.clone() else {
        eprintln!("usbmon: no capture file given");
        eprintln!("usbmon: try `usbmon --help`");
        return EXIT_USAGE;
    };

    let cap = match parse_path(&path, cli.max_line_bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usbmon: cannot read {}: {e}", path.display());
            return EXIT_IO;
        }
    };

    let json_mode = cli.command == Command::Json;

    // In JSON mode stdout carries the document and nothing else, so a reader can
    // pipe it straight into a parser. Prose goes to stderr, or nowhere.
    let mut host = match load_host_log(&cli, &path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("usbmon: {e}");
            return EXIT_IO;
        }
    };
    if let Some(h) = host.as_mut() {
        h.join = join_host(&cap, &h.xfers);
    }
    if !json_mode {
        // Header: the report is pinned to these bytes, or says it is not.
        print_header(&cli, &cap);
        print_host_header(&cli, &host, &path);
    }

    if let Some(want) = &cli.expect_sha256 {
        if !want.eq_ignore_ascii_case(&cap.sha256) {
            if json_mode {
                // stdout stays parseable JSON even on this failure, so
                // `usbmon ... json | jq` reports the mismatch instead of an
                // empty stream.
                let doc = json!({
                    "tool": TOOL, "schema": SCHEMA,
                    "error": "expect-sha256-mismatch",
                    "expected": want, "actual": cap.sha256,
                    "exit_code": EXIT_SHA_MISMATCH,
                });
                if let Ok(t) = serde_json::to_string_pretty(&doc) {
                    outln!("{t}");
                }
            } else {
                outln!("[INSPECTED] --expect-sha256 mismatch: the report above describes the file, but");
                outln!("            the bytes are not the ones you pinned. Refusing to analyse.");
                outln!("            expected {want}");
                outln!("            actual   {}", cap.sha256);
            }
            return EXIT_SHA_MISMATCH;
        }
        if !json_mode {
            outln!("[INSPECTED] --expect-sha256 matched");
        }
    }

    let errors = cap.errors();
    let host_warning_count = host
        .as_ref()
        .map(|h| {
            h.problems.len()
                + h.join.disagreements.len()
                + usize::from(!h.join.ok)
        })
        .unwrap_or(0);
    let warnings = cap.warnings() + host_warning_count;
    let boundaries = cap.unmatched_completions.len();
    let matched = Matched::new(&cli.filter, &cap);
    if errors > 0 && !cli.force {
        if json_mode {
            print_json(&cli, &cap, &matched, &host);
        } else {
            print_problems(&cap, true);
            outln!();
            outln!(
                "[INSPECTED] REFUSING to summarise: {errors} structural error(s). Nothing in this file"
            );
            outln!("            is trustworthy until they are explained (use --force to print the");
            outln!("            analysis anyway; the exit code stays {EXIT_STRUCTURAL}).");
        }
        return EXIT_STRUCTURAL;
    }

    if json_mode {
        print_json(&cli, &cap, &matched, &host);
    } else {
        // Scope: what the filters selected, and what they excluded.
        print_scope(&cli, &cap, &matched);
        match cli.command {
            Command::Summary => print_summary(&cli, &cap, &matched, &host),
            Command::List => print_list(&cli, &cap, &matched, &host),
            Command::Attempts => print_attempts(&cli, &cap, &matched, &host),
            Command::Report => {
                print_summary(&cli, &cap, &matched, &host);
                outln!();
                print_attempts(&cli, &cap, &matched, &host);
            }
            Command::Json => unreachable!("handled above"),
        }
        // Problems after the body: the reader sees the data first, then every
        // reason to distrust it.
        if errors > 0 || warnings > 0 {
            outln!();
            if let Some(h) = host {
                for d in &h.join.disagreements {
                    outln!("[WARNING] host/wire CONTRADICTION: {d}");
                }
                for d in &h.join.divergences {
                    outln!("[INFERRED] host/wire divergence (expected for a cancelled control transfer): {d}");
                }
                for p in &h.problems {
                    outln!("[WARNING] host trace {p}");
                }
            }
            print_problems(&cap, false);
        }
        if matched.is_empty(cli.command) && errors == 0 {
            outln!();
            print_nothing_matched(&cli, &cap, &matched);
        }
    }

    // Order matters: a file with structural errors is not "parsed clean", so
    // exit 4 outranks the no-match exit even under --force (and --force must
    // never turn a 4 into a 5).
    if errors > 0 {
        return EXIT_STRUCTURAL;
    }
    if matched.is_empty(cli.command) {
        return EXIT_NO_URBS;
    }
    if cli.strict && warnings > 0 {
        if !json_mode {
            outln!();
            outln!(
                "[INSPECTED] --strict: {warnings} warning(s) (including {boundaries} boundary \
                 completion(s)) — exit {EXIT_STRICT_WARNINGS}"
            );
        }
        return EXIT_STRICT_WARNINGS;
    }
    if errors > 0 {
        return EXIT_STRUCTURAL;
    }
    EXIT_OK
}

fn parse_args<I: Iterator<Item = String>>(mut it: I) -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut command_seen = false;
    while let Some(a) = it.next() {
        let need = |it: &mut I, what: &str| -> Result<String, String> {
            it.next().ok_or_else(|| format!("{what} needs a value"))
        };
        match a.as_str() {
            "-h" | "--help" => cli.help = true,
            "-V" | "--version" => cli.version = true,
            "--json" => {
                cli.command = Command::Json;
                command_seen = true;
            }
            "--strict" => cli.strict = true,
            "--force" => cli.force = true,
            "--redact-data" => cli.redact = true,
            "--host-log" => cli.host_log = Some(PathBuf::from(need(&mut it, "--host-log")?)),
            "--no-host-log" => cli.no_host_log = true,
            "--no-sha256" => cli.hash = false,
            "--device" => {
                let v = need(&mut it, "--device")?;
                let (bus, dev) = parse_device(&v)?;
                cli.filter.device = Some((bus, dev));
            }
            "--request" => {
                let v = need(&mut it, "--request")?;
                cli.filter.request = Some(parse_request(&v)?);
            }
            "--endpoint" => {
                let v = need(&mut it, "--endpoint")?;
                cli.filter.endpoint = Some(parse_ep(&v)?);
            }
            "--status" => {
                let v = need(&mut it, "--status")?;
                let (codes, expansion) = parse_status(&v)?;
                cli.status_expansion = Some(expansion);
                cli.filter.status = Some(codes);
            }
            "--dir" => {
                let v = need(&mut it, "--dir")?;
                cli.filter.dir = Some(match v.to_ascii_lowercase().as_str() {
                    "in" | "i" => Dir::In,
                    "out" | "o" => Dir::Out,
                    other => return Err(format!("--dir must be in|out, saw {other:?}")),
                });
            }
            "--type" => {
                let v = need(&mut it, "--type")?;
                cli.filter.xfer = Some(match v.to_ascii_lowercase().as_str() {
                    "control" | "c" => XferType::Control,
                    "bulk" | "b" => XferType::Bulk,
                    "interrupt" | "int" | "i" => XferType::Interrupt,
                    other => return Err(format!("--type must be control|bulk|interrupt, saw {other:?}")),
                });
            }
            "--setup-len" => {
                let v = need(&mut it, "--setup-len")?;
                cli.plan.setup_len = parse_u16_hex(&v, "--setup-len")?;
            }
            "--pad-len" => {
                let v = need(&mut it, "--pad-len")?;
                cli.plan.pad_len = parse_u16_hex(&v, "--pad-len")?;
            }
            "--drain-len" => {
                let v = need(&mut it, "--drain-len")?;
                cli.plan.drain_len = parse_u16_hex(&v, "--drain-len")?;
            }
            "--gaps-ms" => {
                let v = need(&mut it, "--gaps-ms")?;
                cli.gaps_ms = v
                    .parse()
                    .map_err(|e| format!("--gaps-ms must be a whole number of ms: {e}"))?;
            }
            "--top" => {
                let v = need(&mut it, "--top")?;
                cli.top = v
                    .parse()
                    .map_err(|e| format!("--top must be a whole number: {e}"))?;
            }
            "--expect-sha256" => {
                cli.expect_sha256 = Some(need(&mut it, "--expect-sha256")?);
            }
            "--max-line-bytes" => {
                let v = need(&mut it, "--max-line-bytes")?;
                cli.max_line_bytes = v
                    .parse()
                    .map_err(|e| format!("--max-line-bytes must be a whole number: {e}"))?;
                if cli.max_line_bytes < 64 {
                    return Err("--max-line-bytes below 64 would reject real usbmon lines".into());
                }
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            s => {
                if let Some(c) = Command::parse(s) {
                    cli.command = c;
                    command_seen = true;
                } else if cli.file.is_none() {
                    cli.file = Some(PathBuf::from(s));
                } else {
                    return Err(format!(
                        "unexpected argument {s:?} (command already set: {command_seen})"
                    ));
                }
            }
        }
    }
    if cli.command == Command::Json {
        cli.command = Command::Json;
    }
    Ok(cli)
}

fn parse_device(v: &str) -> Result<(u32, u32), String> {
    let (b, d) = v
        .split_once(':')
        .ok_or_else(|| format!("--device must be BUS:ADDR (e.g. 1:005), saw {v:?}"))?;
    let bus: u32 = b
        .parse()
        .map_err(|e| format!("--device bus {b:?} is not a number: {e}"))?;
    let dev: u32 = d
        .parse()
        .map_err(|e| format!("--device address {d:?} is not a number: {e}"))?;
    Ok((bus, dev))
}

fn parse_request(v: &str) -> Result<RequestMatch, String> {
    if let Ok(n) = v.parse::<u8>() {
        return Ok(RequestMatch::Number(n));
    }
    if let Some(hex) = v.strip_prefix("0x") {
        return u8::from_str_radix(hex, 16)
            .map(RequestMatch::Number)
            .map_err(|e| format!("--request {v:?} is not a hex request code: {e}"));
    }
    // `-1`, `" 6"`, `"6 "` used to be silently rewritten into an unmatchable
    // name (`1`, `6`, `6`) while the scope line claimed the rewritten filter.
    // A value that is not a plain name is a usage error, not a guess.
    if !v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!(
            "--request {v:?} is neither a request code nor a plain request name              (letters, digits and _ only; use 0xNN for a hex code)"
        ));
    }
    if v.is_empty() {
        return Err("--request needs a value".into());
    }
    Ok(RequestMatch::Name(v.to_ascii_uppercase()))
}

fn parse_ep(v: &str) -> Result<u32, String> {
    // Decimal by default: endpoints are numbers, and `--endpoint 10` meaning 16
    // was a trap. Hex needs the explicit prefix (`0x81` for the IN direction).
    match v.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16)
            .map_err(|e| format!("--endpoint {v:?} is not a hex number: {e}")),
        None => v
            .parse::<u32>()
            .map_err(|e| format!("--endpoint {v:?} is not a decimal number: {e}")),
    }
}

fn parse_u16_hex(v: &str, what: &str) -> Result<u16, String> {
    let s = v.strip_prefix("0x").unwrap_or(v);
    let n = u16::from_str_radix(s, 16).map_err(|e| format!("{what} {v:?} is not hex: {e}"))?;
    Ok(n)
}

/// Status filters are expansions, and the expansion is printed: `--status STALL`
/// is two errnos on Linux (-32 EPIPE for a control STALL that reaches this host,
/// -71 EPROTO for a transaction error), never one silently chosen code.
fn parse_status(v: &str) -> Result<(Vec<Option<i64>>, String), String> {
    let up = v.to_ascii_uppercase();
    let codes: Vec<Option<i64>> = match up.as_str() {
        "OK" => vec![Some(0)],
        "STALL" => vec![Some(-32), Some(-71)],
        "EPIPE" => vec![Some(-32)],
        "EPROTO" => vec![Some(-71)],
        "TIMEOUT" | "ETIMEDOUT" => vec![Some(-110)],
        "CANCELLED" | "CANCELED" | "UNLINKED" | "ENOENT" => vec![Some(-2)],
        "ECONNRESET" => vec![Some(-104)],
        "ESHUTDOWN" => vec![Some(-108)],
        "EREMOTEIO" => vec![Some(-121)],
        "PENDING" | "NONE" => vec![None],
        other => vec![Some(
            other
                .parse::<i64>()
                .map_err(|e| format!("--status {v:?} is not a name or a code: {e}"))?,
        )],
    };
    let expansion = codes
        .iter()
        .map(|c| match c {
            Some(c) => format!("{c} {}", errno_name(*c).unwrap_or("?")),
            None => "no-callback-in-file".to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ");
    Ok((codes, expansion))
}

// ---------------------------------------------------------------------------
// What the filters selected
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Matched {
    transfers: Vec<usize>,
    /// Completions with no submit line in this file that the filter can apply
    /// to. A `--request` filter can never match one of these: there is no setup
    /// on the wire for it.
    boundary: Vec<usize>,
    events: Vec<usize>,
    /// transfer index by submit-line event index, built once. `list` used to do
    /// a linear scan per event, which is quadratic on a long capture.
    by_submit: std::collections::BTreeMap<usize, usize>,
    /// Selected transfer indices as a set, for the same reason.
    set: std::collections::BTreeSet<usize>,
}

impl Matched {
    fn new(f: &Filter, cap: &Capture) -> Matched {
        let transfers: Vec<usize> = cap
            .transfers
            .iter()
            .enumerate()
            .filter(|(_, t)| f.matches_transfer(cap, t))
            .map(|(i, _)| i)
            .collect();
        let events: Vec<usize> = cap
            .events
            .iter()
            .enumerate()
            .filter(|(_, e)| f.matches_event(e))
            .map(|(i, _)| i)
            .collect();
        let boundary: Vec<usize> = cap
            .unmatched_completions
            .iter()
            .copied()
            .filter(|&i| {
                let ev = &cap.events[i];
                if f.request.is_some() {
                    return false;
                }
                if !f.matches_event(ev) {
                    return false;
                }
                match &f.status {
                    Some(want) => want.contains(&ev.status),
                    None => true,
                }
            })
            .collect();
        let by_submit = cap
            .transfers
            .iter()
            .enumerate()
            .map(|(i, t)| (t.submit, i))
            .collect();
        let set = transfers.iter().copied().collect();
        Matched {
            transfers,
            boundary,
            events,
            by_submit,
            set,
        }
    }
    fn has(&self, transfer: usize) -> bool {
        self.set.contains(&transfer)
    }
    /// "Nothing matched" is about URBs the filter selected, never about the
    /// unfiltered event count. A `--request`/`--status` filter that matches no
    /// transfer must exit 5 like `--device` does, or a gate reading `$?` would
    /// report the capture contains a request it does not.
    fn is_empty(&self, _cmd: Command) -> bool {
        self.transfers.is_empty() && self.boundary.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Header / scope / problems
// ---------------------------------------------------------------------------

fn print_header(cli: &Cli, cap: &Capture) {
    outln!("{TOOL} {TOOL_VERSION} — reads a Linux usbmon `u` text capture. Reads a file; opens no device.");
    outln!("file       : {}", cli.file.as_ref().map(|p| p.display().to_string()).unwrap_or_default());
    outln!("bytes      : {}", cap.bytes);
    if cli.hash {
        outln!("sha256     : {}", cap.sha256);
    } else {
        outln!("sha256     : not computed (--no-sha256)");
    }
    outln!(
        "[INSPECTED] {} lines, {} events, {} structural error(s), {} warning(s), {} boundary completion(s)",
        cap.lines,
        cap.events.len(),
        cap.errors(),
        cap.warnings(),
        cap.unmatched_completions.len()
    );
    outln!(
        "            grammar: usbmon \"u\" text (drivers/usb/mon/mon_text.c); displayed data is capped at {} B by the kernel",
        KERNEL_DATA_MAX
    );
}

fn print_scope(cli: &Cli, cap: &Capture, m: &Matched) {
    // Device-level, not address-level: the point of `--device` is that another
    // device's URBs must not reach a count, so the scope line names the devices
    // included and how many events each contributed. Endpoints appear in the
    // per-address table in `summary`.
    let addresses = address_stats(cap);
    let mut devices: Vec<((u32, u32), u64)> = Vec::new();
    for (a, s) in &addresses {
        match devices.iter_mut().find(|(d, _)| *d == (a.bus, a.dev)) {
            Some((_, ev)) => *ev += s.events,
            None => devices.push(((a.bus, a.dev), s.events)),
        }
    }
    let parts: Vec<String> = devices
        .iter()
        .map(|((bus, dev), ev)| format!("{bus}:{dev:03} {ev}"))
        .collect();
    let filter_desc = describe_filter(cli);
    let what = if filter_desc.is_empty() {
        format!("all devices ({})", devices.len())
    } else {
        filter_desc
    };
    // The count is of URBs the filter selected, and it is split into paired
    // transfers and submit-less completions so neither hides the other.
    outln!(
        "scope      : {} — selected {} of {} transfer(s) and {} of {} boundary completion(s); events per device in file: {}",
        what,
        m.transfers.len(),
        cap.transfers.len(),
        m.boundary.len(),
        cap.unmatched_completions.len(),
        parts.join(", ")
    );
}

fn describe_filter(cli: &Cli) -> String {
    let mut parts = Vec::new();
    if let Some((bus, dev)) = cli.filter.device {
        parts.push(format!("--device {bus}:{dev:03}"));
    }
    if let Some(r) = &cli.filter.request {
        match r {
            RequestMatch::Number(n) => parts.push(format!("--request {n}")),
            RequestMatch::Name(n) => parts.push(format!("--request {n}")),
        }
    }
    if let Some(ep) = cli.filter.endpoint {
        parts.push(format!("--endpoint {ep}"));
    }
    if let Some(d) = cli.filter.dir {
        parts.push(format!("--dir {}", d.name().to_ascii_lowercase()));
    }
    if let Some(x) = cli.filter.xfer {
        parts.push(format!("--type {}", x.name()));
    }
    if let Some(exp) = &cli.status_expansion {
        parts.push(format!("--status ({exp})"));
    }
    parts.join(" ")
}

fn print_problems(cap: &Capture, errors_only: bool) {
    if cap.problems_not_listed > 0 {
        outln!(
            "[INSPECTED] {} problem(s) were counted but not listed (the list is capped at {} so a \
             corrupt file cannot exhaust memory); the header counts are exact",
            cap.problems_not_listed,
            MAX_LISTED_PROBLEMS
        );
    }
    for p in &cap.problems {
        if errors_only && p.severity != Severity::Error {
            continue;
        }
        let label = if p.is_boundary() {
            "BOUNDARY".to_string()
        } else {
            p.severity.label().to_string()
        };
        outln!(
            "[{label}] line {} {}: {}",
            p.line_no, p.code, p.detail
        );
        if !p.excerpt.is_empty() {
            outln!("           | {}", p.excerpt);
        }
    }
}

fn print_nothing_matched(cli: &Cli, cap: &Capture, m: &Matched) {
    let desc = describe_filter(cli);
    if !desc.is_empty() {
        outln!(
            "[MEASURED] no transfer matches {desc}: 0 of {} transfer(s) selected.",
            cap.transfers.len()
        );
        outln!(
            "           addresses present in this file: {}",
            address_stats(cap)
                .iter()
                .map(|(a, _)| a.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        outln!(
            "           exit {EXIT_NO_URBS}: a filter that selects nothing must not read as success."
        );
        return;
    }
    if cli.command == Command::Attempts {
        outln!(
            "[MEASURED] 0 attempt(s): no control-OUT class request 1 with wLength 0x{:04x} in this \
             file's scope.",
            cli.plan.setup_len
        );
        outln!("           that is a finding, not a failure to read: use `list` to see what the file does contain.");
        return;
    }
    outln!("[MEASURED] URB count: 0 — this file records nothing ({} bytes, {} lines).", cap.bytes, cap.lines);
    outln!("           If this was a negative control (an offline command must produce zero URBs),");
    outln!("           this is its pass condition, and it is reported as exit {EXIT_NO_URBS} so it can");
    outln!("           never be confused with a successful analysis.");
    outln!("           If you expected traffic: check that the capture was started before the command,");
    outln!("           that the bus number is right, and that the usbmon node was opened under sudo.");
    let _ = m;
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/// key -> (count, first line, min/max elapsed)
#[derive(Default)]
struct Tally {
    count: u64,
    first_line: u64,
    min_us: Option<i64>,
    max_us: Option<i64>,
}

impl Tally {
    fn add(&mut self, line: u64, us: Option<i64>) {
        if self.count == 0 {
            self.first_line = line;
        }
        self.count += 1;
        if let Some(u) = us {
            self.min_us = Some(self.min_us.map_or(u, |m| m.min(u)));
            self.max_us = Some(self.max_us.map_or(u, |m| m.max(u)));
        }
    }
    fn us_span(&self) -> String {
        match (self.min_us, self.max_us) {
            (Some(a), Some(b)) if a == b => us_label(a),
            (Some(a), Some(b)) => format!("{}..{}", us_label(a), us_label(b)),
            _ => "n/a".into(),
        }
    }
}

fn print_summary(cli: &Cli, cap: &Capture, m: &Matched, host: &Option<HostCtx>) {
    // ---- devices ----
    let stats = address_stats(cap);
    if !stats.is_empty() {
        outln!("[MEASURED] addresses in first-appearance order (counts are for the whole file):");
        let rows: Vec<Vec<String>> = stats
            .iter()
            .map(|(a, s)| {
                vec![
                    a.to_string(),
                    format!("{} events", s.events),
                    format!("{} transfer(s)", s.transfers),
                    format!("first t={}", s.first_ts),
                    format!("last  t={}", s.last_ts),
                ]
            })
            .collect();
        for l in table(&rows) {
            outln!("           {l}");
        }
    }

    // ---- pairing ----
    let complete = m
        .transfers
        .iter()
        .filter(|i| cap.transfers[**i].completion.is_some())
        .count();
    let pending = m.transfers.len() - complete;
    outln!(
        "[MEASURED] transfers: {} selected ({} with a callback in this file, {} with none); \
         boundary completions selected: {} of {} in file",
        m.transfers.len(),
        complete,
        pending,
        m.boundary.len(),
        cap.unmatched_completions.len()
    );

    // ---- by request: the FULL setup packet is the key ----
    // Grouping by (bm, b) alone merges requests that differ only in wLength, and
    // on this wire that means SPRAY's stall primitive `02 03 0000 0080 0000`
    // would be counted with PATCH's 48-byte overflow `02 03 0000 0080 0030`.
    let mut by_req: Vec<(String, Tally)> = Vec::new();
    for &i in &m.transfers {
        let t = &cap.transfers[i];
        let label = match cap.setup_of(t) {
            Some(s) => format!("{} setup={}", request_label(&s), s.wire()),
            None => format!("{} {}", t.xfer.name(), t.dir.name().to_ascii_lowercase()),
        };
        tally_push(&mut by_req, label, cap.events[t.submit].line_no, cap.elapsed_us(t));
    }
    if !by_req.is_empty() {
        outln!(
            "[MEASURED] by request (key = the FULL setup packet: bm b wValue wIndex wLength — two \
             requests that differ only in wLength are different rows):"
        );
        for (k, v) in &by_req {
            outln!(
                "           {:<62} x{:<5} first #{}  elapsed {}",
                k,
                v.count,
                v.first_line,
                v.us_span()
            );
        }
    }

    // ---- by status ----
    let mut by_status: Vec<(String, Tally)> = Vec::new();
    for &i in &m.transfers {
        let t = &cap.transfers[i];
        let label = match cap.status_of(t) {
            Some(c) => status_label(c),
            None => "no callback in this file".to_string(),
        };
        tally_push(&mut by_status, label, cap.events[t.submit].line_no, cap.elapsed_us(t));
    }
    if !by_status.is_empty() {
        outln!("[MEASURED] by status (selected transfers):");
        for (k, v) in &by_status {
            let note = k
                .split(' ')
                .next()
                .and_then(|c| c.parse::<i64>().ok())
                .and_then(status_note)
                .unwrap_or("");
            outln!("           {:<26} x{:<5} {}", k, v.count, note);
        }
    }

    // ---- bytes ----
    // "short" is status 0 with fewer bytes than requested; a cancelled transfer
    // that moved 0 bytes is a different thing and is counted separately, so the
    // two are never added into one number.
    let (mut req_bytes, mut moved_bytes, mut short_ok) = (0u64, 0u64, 0u64);
    let mut incomplete_err = 0u64;
    let (mut in_req, mut in_moved, mut out_req, mut out_moved) = (0u64, 0u64, 0u64, 0u64);
    for &i in &m.transfers {
        let t = &cap.transfers[i];
        let req = cap.events[t.submit].length as u64;
        let moved = t
            .completion
            .map(|c| cap.events[c].length as u64)
            .unwrap_or(0);
        req_bytes += req;
        moved_bytes += moved;
        match cap.status_of(t) {
            Some(0) if moved < req => short_ok += 1,
            Some(_) if moved < req => incomplete_err += 1,
            _ => {}
        }
        match t.dir {
            Dir::In => {
                in_req += req;
                in_moved += moved;
            }
            Dir::Out => {
                out_req += req;
                out_moved += moved;
            }
        }
    }
    outln!(
        "[MEASURED] bytes: requested {req_bytes} B, callback-reported transferred {moved_bytes} B; \
         {short_ok} short transfer(s) at status 0, {incomplete_err} non-OK transfer(s) that moved \
         fewer bytes than requested"
    );
    outln!(
        "           IN  {in_moved}/{in_req} B moved (what the device sent)   OUT {out_moved}/{out_req} B \
         moved (what the device accepted)"
    );

    // ---- control-OUT data stages: the E3(b) view ----
    let mut outs: Vec<(String, Tally)> = Vec::new();
    for &i in &m.transfers {
        let t = &cap.transfers[i];
        if t.dir != Dir::Out || t.xfer != XferType::Control {
            continue;
        }
        let Some(s) = cap.setup_of(t) else { continue };
        let moved = t.completion.map(|c| cap.events[c].length).unwrap_or(0);
        let status = match cap.status_of(t) {
            Some(c) => status_label(c),
            None => "no-callback".into(),
        };
        let host_label = host
            .as_ref()
            .filter(|h| h.join.ok)
            .and_then(|h| host_for(h, i))
            .map(|hx| format!("  [host {}/{}]", hx.stage, hx.label))
            .unwrap_or_default();
        let key = format!(
            "{} {} setup={} -> {}/{} B  {}{}",
            t.addr,
            request_label(&s),
            s.wire(),
            moved,
            cap.events[t.submit].length,
            status,
            host_label
        );
        tally_push(&mut outs, key, cap.events[t.submit].line_no, cap.elapsed_us(t));
    }
    if !outs.is_empty() {
        outln!(
            "[MEASURED] control-OUT data stages (key = full setup packet; bytes the device accepted, \
             by status):"
        );
        for (k, v) in &outs {
            outln!("           {k}  x{}  elapsed {}", v.count, v.us_span());
        }
    }

    // ---- descriptors ----
    let reads = descriptor_reads(cap);
    let selected: Vec<&DescriptorRead> = reads
        .iter()
        .filter(|r| m.has(r.transfer))
        .collect();
    if !selected.is_empty() {
        let mut groups: Vec<(String, Tally)> = Vec::new();
        for r in &selected {
            let status = match r.status {
                Some(c) => status_label(c),
                None => "no-callback".into(),
            };
            let key = format!(
                "{} {:<44} req {:<5} -> {:>5} B  {}",
                r.addr,
                descriptor_target(r.setup.w_value, r.setup.w_index),
                r.requested,
                r.transferred,
                status
            );
            tally_push(&mut groups, key, r.line_no, None);
        }
        outln!("[MEASURED] GET_DESCRIPTOR reads (device, target, requested -> transferred, status):");
        for (k, v) in &groups {
            outln!("           {k}  x{}", v.count);
        }

        // Device descriptors, decoded only from bytes the capture fully printed.
        let mut devs: Vec<(String, Tally)> = Vec::new();
        for r in &selected {
            if (r.setup.w_value >> 8) as u8 != 1 || r.status != Some(0) {
                continue;
            }
            let Some(d) = decode_device_descriptor(&r.data) else {
                continue;
            };
            let key = format!(
                "{} bcdUSB 0x{:04x} idVendor 0x{:04x} idProduct 0x{:04x} bcdDevice 0x{:04x} \
                 iManufacturer {} iProduct {} iSerialNumber {}",
                r.addr, d.bcd_usb, d.id_vendor, d.id_product, d.bcd_device,
                d.i_manufacturer, d.i_product, d.i_serial_number
            );
            tally_push(&mut devs, key, r.line_no, None);
        }
        if !devs.is_empty() {
            outln!("[MEASURED] device descriptors decoded from the captured 18 B (all 18 were printed):");
            for (k, v) in &devs {
                outln!("           {k}  x{}", v.count);
            }
        }

        // The one-line screen for "did the serial descriptor change length?"
        // The key keeps wIndex and status: on this device a stock read is
        // idx=4 lang=0x0409 at 198 B while gaster's leak probe is idx=4
        // lang=0x000a at 0 B cancelled, and conflating those two would be a
        // wrong value wearing a measured count.
        let mut per_dev: Vec<(Address, Vec<(u8, u16, u32, String, u64)>)> = Vec::new();
        for r in &selected {
            if (r.setup.w_value >> 8) as u8 != 3 {
                continue;
            }
            let idx = (r.setup.w_value & 0xff) as u8;
            let lang = r.setup.w_index;
            let status = match r.status {
                Some(c) => status_label(c),
                None => "no-callback".into(),
            };
            let entry = (idx, lang, r.transferred, status, 1u64);
            match per_dev.iter_mut().find(|(a, _)| *a == r.addr) {
                Some((_, v)) => match v.iter_mut().find(|e| {
                    e.0 == entry.0 && e.1 == entry.1 && e.2 == entry.2 && e.3 == entry.3
                }) {
                    Some(e) => e.4 += 1,
                    None => v.push(entry),
                },
                None => per_dev.push((r.addr, vec![entry])),
            }
        }
        if !per_dev.is_empty() {
            outln!("[MEASURED] STRING descriptor reads by device (index, langid, transferred B, status):");
            for (a, v) in &per_dev {
                let mut v = v.clone();
                v.sort_by_key(|(i, l, n, _, _)| (*i, *l, std::cmp::Reverse(*n)));
                let desc = v
                    .iter()
                    .map(|(i, l, n, st, c)| format!("idx {i} lang 0x{l:04x} {n} B x{c} {st}"))
                    .collect::<Vec<_>>()
                    .join("; ");
                outln!("           {a}  {desc}");
            }
            outln!(
                "           (a device that re-enumerates with a different serial-string length is how the"
            );
            outln!("            pwn shows up in a capture; the tool states lengths, not verdicts)");
        }

        // ---- serial descriptor, keyed on the DECLARED index ----
        // The declared index moves across re-enumerations (iSerialNumber has been
        // seen as 4 and as 6 on this phone, with the marker following it), so
        // nothing here may key on a fixed index. The device descriptor on the
        // wire says which string index is the serial, and the STRING reads say
        // what that index returned.
        let devs_by_addr = |data: &[u8]| decode_device_descriptor(data);
        let mut per_addr: Vec<(Address, Vec<(u8, u64)>, Vec<(u8, u16, u32, String)>)> = Vec::new();
        for r in &selected {
            let entry = match per_addr.iter_mut().find(|(a, _, _)| *a == r.addr) {
                Some(e) => e,
                None => {
                    per_addr.push((r.addr, Vec::new(), Vec::new()));
                    per_addr.last_mut().unwrap()
                }
            };
            let (dtype, idx) = ((r.setup.w_value >> 8) as u8, (r.setup.w_value & 0xff) as u8);
            if dtype == 1 && r.status == Some(0) {
                if let Some(d) = devs_by_addr(&r.data) {
                    if !entry.1.iter().any(|(i, _)| *i == d.i_serial_number) {
                        entry.1.push((d.i_serial_number, r.line_no));
                    }
                }
            }
            if dtype == 3 {
                let status = match r.status {
                    Some(c) => status_label(c),
                    None => "no-callback".into(),
                };
                entry.2.push((idx, r.setup.w_index, r.transferred, status));
            }
        }
        let has_serial = per_addr
            .iter()
            .any(|(_, declared, reads)| !declared.is_empty() && !reads.is_empty());
        if has_serial {
            outln!(
                "[MEASURED] serial descriptor, keyed on the index the DEVICE DESCRIPTOR declares \
                 (no fixed index is assumed):"
            );
            for (a, declared, reads) in &per_addr {
                let decl = if declared.is_empty() {
                    "declared iSerialNumber: none read".to_string()
                } else {
                    format!(
                        "declared iSerialNumber={} (from device descriptor at {})",
                        declared
                            .iter()
                            .map(|(i, _)| i.to_string())
                            .collect::<Vec<_>>()
                            .join("/"),
                        declared
                            .iter()
                            .map(|(_, l)| format!("#{l}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                outln!("           {a}  {decl}");
                for idx in declared.iter().map(|(i, _)| *i) {
                    match reads.iter().find(|(i, _, _, _)| *i == idx) {
                        Some((_, lang, n, st)) => outln!(
                            "             read at declared idx {idx} (lang 0x{lang:04x}): {n} B  {st}"
                        ),
                        None => outln!(
                            "             read at declared idx {idx}: NOT IN THIS FILE — the capture \
                             does not show what the declared serial index returned"
                        ),
                    }
                }
            }
            // Data-driven length screen, per device, no fixed index: the longest
            // successful STRING read on each device, against the shortest such
            // maximum in the scope. The comparison is between *long* strings
            // (longer than the print window), so the 4-byte language-id list and
            // the 22/62-byte product strings do not become the baseline.
            let mut maxima: Vec<(Address, u32, u8, u64)> = Vec::new();
            for (a, _, reads) in &per_addr {
                let mut best: Option<(u32, u8, u64)> = None;
                for (idx, _, n, st) in reads {
                    if !st.starts_with("0 OK") || (*n as usize) <= KERNEL_DATA_MAX {
                        continue;
                    }
                    match &mut best {
                        Some(b) if b.0 >= *n => b.2 += 1,
                        Some(b) => {
                            *b = (*n, *idx, 1);
                        }
                        None => best = Some((*n, *idx, 1)),
                    }
                }
                if let Some((n, idx, c)) = best {
                    maxima.push((*a, n, idx, c));
                }
            }
            if !maxima.is_empty() {
                let baseline = maxima.iter().map(|(_, n, _, _)| *n).min().unwrap();
                outln!(
                    "[MEASURED] longest STRING read per device (only reads longer than the {KERNEL_DATA_MAX} B \
                     print window are considered, so the language-id list cannot be the baseline):"
                );
                for (a, n, idx, c) in &maxima {
                    let delta = *n as i64 - baseline as i64;
                    let note = if delta == 0 {
                        "same as the shortest longest-read in scope — no marker-length string here"
                            .to_string()
                    } else if delta == 30 {
                        "= +30 B: the length of ` PWND:[checkm8]` (15 UTF-16 units) appended to a \
                         serial string"
                            .to_string()
                    } else {
                        format!("+{delta} B vs the shortest longest-read in scope")
                    };
                    outln!("           {a}: {n} B at idx {idx} (x{c})  {note}");
                }
                outln!(
                    "[INFERRED] the marker TEXT is not in the capture — usbmon prints at most \
                     {KERNEL_DATA_MAX} bytes of a descriptor — so a marker-length read is a length \
                     signature, and the shortest longest-read is this capture's own stock baseline, \
                     not a hardcoded 198."
                );
            }
            for (a, _, reads) in &per_addr {
                let mut lengths: Vec<(u32, u8, u64)> = Vec::new();
                for (idx, _, n, st) in reads {
                    if st.starts_with("0 OK") {
                        match lengths.iter_mut().find(|(l, i, _)| *l == *n && *i == *idx) {
                            Some((_, _, c)) => *c += 1,
                            None => lengths.push((*n, *idx, 1)),
                        }
                    }
                }
                lengths.sort();
                if let (Some(min), Some(max)) = (lengths.first(), lengths.last()) {
                    let delta = max.0 as i64 - min.0 as i64;
                    outln!(
                        "           {a}: STRING reads {} B..{} B (delta {delta:+} B){}",
                        min.0,
                        max.0,
                        if delta >= 30 {
                            format!(
                                " — a +{delta} B read at idx {} is marker-length",
                                max.1
                            )
                        } else {
                            String::new()
                        }
                    );
                }
            }
        }
    }

    // ---- host log ----
    if let Some(h) = host {
        outln!(
            "[MEASURED host log] {}: {} xfer record(s); join {}",
            h.path.display(),
            h.xfers.len(),
            if h.join.ok { "OK" } else { "FAILED" }
        );
        outln!("           {}", h.join.detail);
        if h.join.ok {
            let mut stages: Vec<(String, u64)> = Vec::new();
            for hx in &h.xfers {
                match stages.iter_mut().find(|(k, _)| *k == hx.stage) {
                    Some((_, c)) => *c += 1,
                    None => stages.push((hx.stage.clone(), 1)),
                }
            }
            let desc = stages
                .iter()
                .map(|(k, c)| format!("{k} {c}"))
                .collect::<Vec<_>>()
                .join(", ");
            outln!("           transfers per stage (host): {desc}");
        }
        for p in &h.problems {
            outln!("[WARNING] host trace {p}");
        }
    }

    // ---- non-OK completions ----
    print_non_ok(cli, cap, m, 20);
}

fn tally_push(v: &mut Vec<(String, Tally)>, key: String, line: u64, us: Option<i64>) {
    match v.iter_mut().find(|(k, _)| *k == key) {
        Some((_, t)) => t.add(line, us),
        None => {
            let mut t = Tally::default();
            t.add(line, us);
            v.push((key, t));
        }
    }
}

fn print_non_ok(cli: &Cli, cap: &Capture, m: &Matched, default_cap: usize) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut total = 0usize;
    for &i in &m.transfers {
        let t = &cap.transfers[i];
        let Some(code) = cap.status_of(t) else { continue };
        if code == 0 {
            continue;
        }
        total += 1;
        let limit = if cli.top > 0 { cli.top } else { default_cap };
        if rows.len() >= limit {
            continue;
        }
        let req = cap.events[t.submit].length;
        let moved = cap.events[t.completion.unwrap()].length;
        let req_label = match cap.setup_of(t) {
            Some(s) => format!("{} wLen=0x{:04x}", request_label(&s), s.w_length),
            None => format!("{} {}", t.xfer.name(), t.dir.name().to_ascii_lowercase()),
        };
        rows.push(vec![
            format!("#{}", cap.events[t.submit].line_no),
            format!("t={}", cap.events[t.submit].timestamp_us),
            t.addr.to_string(),
            t.dir.name().to_string(),
            req_label,
            format!("{moved}/{req} B"),
            status_label(code),
            cap.elapsed_us(t).map(us_label).unwrap_or_else(|| "n/a".into()),
            status_note(code).unwrap_or("").to_string(),
        ]);
    }
    if rows.is_empty() {
        outln!("[MEASURED] non-OK completions: none among the selected transfers.");
        return;
    }
    let limit = if cli.top > 0 { cli.top } else { default_cap };
    outln!(
        "[MEASURED] non-OK completions in file order ({total} total, showing {}):",
        rows.len().min(limit)
    );
    for l in table(&rows) {
        outln!("           {l}");
    }
    if total > rows.len() {
        outln!(
            "           ... {} more (raise with --top N)",
            total - rows.len()
        );
    }
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

fn transfer_row(cap: &Capture, i: usize, redact: bool, host: &Option<HostCtx>) -> Vec<String> {
    let t = &cap.transfers[i];
    let sub = &cap.events[t.submit];
    let mut payload = String::new();
    let mut notes: Vec<String> = Vec::new();
    if let Some(s) = sub.setup {
        payload = format!("wLen=0x{:04x}", s.w_length);
        if s.kind() == 0 && s.b_request == 6 {
            payload = format!(
                "{} wLen=0x{:04x}",
                descriptor_target(s.w_value, s.w_index),
                s.w_length
            );
        } else if s.recipient() == 2 {
            let ep = (s.w_index & 0xff) as u8;
            payload = format!(
                "wIndex=0x{:04x} (endpoint 0x{ep:02x}) wLen=0x{:04x}",
                s.w_index, s.w_length
            );
        }
        if let Some(n) = standard_dir_note(&s) {
            notes.push(n);
        }
    }
    let req = match sub.setup {
        Some(s) => request_label(&s),
        None => format!("{} {}", t.xfer.name(), t.dir.name().to_ascii_lowercase()),
    };
    let (cline, status, moved) = match t.completion {
        Some(c) => (
            format!("#{}", cap.events[c].line_no),
            status_label(cap.events[c].status.unwrap_or(0)),
            cap.events[c].length,
        ),
        None => (
            "(none in file)".to_string(),
            "NO CALLBACK IN FILE".to_string(),
            cap
                .events
                .get(t.submit)
                .map(|_| 0)
                .unwrap_or(0),
        ),
    };
    if t.completion.is_none() {
        notes.push("not evidence of an abort: the callback is absent from this capture".into());
    }
    if let Some(c) = t.completion {
        let c_ev = &cap.events[c];
        if c_ev.data_capped_by_kernel() {
            notes.push(format!(
                "data {} of {} B shown; usbmon's text interface caps display at {} B",
                c_ev.data.len(),
                c_ev.length,
                KERNEL_DATA_MAX
            ));
        } else if c_ev.data_underprinted() {
            notes.push(format!(
                "data {} of {} B printed: below the kernel's min(length, {} B) display — the 32 B \
                 cap cannot explain this (a short scatter-gather first segment can; so can a \
                 capture truncated at a group boundary)",
                c_ev.data.len(),
                c_ev.length,
                KERNEL_DATA_MAX
            ));
        }
        if let Some(code) = c_ev.status {
            if code == 0 && c_ev.length < sub.length && sub.length > 0 {
                notes.push(format!("SHORT: {} of {} B", c_ev.length, sub.length));
            }
            if let Some(n) = status_note(code) {
                notes.push(n.to_string());
            }
        }
    }
    let mut data_col = String::new();
    if let Some(c) = t.completion {
        let c_ev = &cap.events[c];
        if c_ev.has_data() {
            data_col = if redact {
                format!("[{} B redacted]", c_ev.data.len())
            } else {
                hex_bytes(&c_ev.data)
            };
        }
    } else if sub.has_data() {
        data_col = if redact {
            format!("[{} B redacted]", sub.data.len())
        } else {
            hex_bytes(&sub.data)
        };
    }
    if let Some(h) = host {
        if h.join.ok {
            if let Some(hi) = h.join.wire_to_host.get(i).copied().flatten() {
                let hx = &h.xfers[hi];
                notes.insert(0, format!("host {}/{}", hx.stage, hx.label));
            }
        }
    }
    vec![
        format!("#{}", sub.line_no),
        sub.timestamp_us.to_string(),
        t.addr.to_string(),
        t.dir.name().to_string(),
        req,
        payload,
        format!("-> {cline}"),
        status,
        format!("{moved}/{} B", sub.length),
        cap.elapsed_us(t).map(us_label).unwrap_or_else(|| "n/a".into()),
        data_col,
        notes.join("; "),
    ]
}

fn print_list(cli: &Cli, cap: &Capture, m: &Matched, host: &Option<HostCtx>) {
    if cli.gaps_ms > 0 {
        print_gaps(cli, cap, m);
        return;
    }
    let boundary: std::collections::BTreeSet<usize> = m.boundary.iter().copied().collect();
    let limit = cli.top;
    let mut printed = 0usize;
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut boundaries_printed = 0usize;
    for (idx, ev) in cap.events.iter().enumerate() {
        if !cli.filter.matches_event(ev) {
            continue;
        }
        if boundary.contains(&idx) {
            rows.push(vec![
                format!("#{}", ev.line_no),
                ev.timestamp_us.to_string(),
                ev.addr.to_string(),
                ev.dir.name().to_string(),
                format!("{} {}", ev.xfer.name(), ev.dir.name().to_ascii_lowercase()),
                String::new(),
                "-> (this line)".into(),
                status_label(ev.status.unwrap_or(0)),
                format!("{}/{} B", ev.length, ev.length),
                "n/a".into(),
                if cli.redact {
                    format!("[{} B redacted]", ev.data.len())
                } else if ev.has_data() {
                    hex_bytes(&ev.data)
                } else {
                    String::new()
                },
                "BOUNDARY: no submit line in this file (capture incomplete for this URB)".into(),
            ]);
            boundaries_printed += 1;
            continue;
        }
        // Only the submit line that opened a selected transfer is a row.
        if ev.event != Event::Submit {
            continue;
        }
        let Some(&ti) = m.by_submit.get(&idx) else {
            continue;
        };
        if !m.has(ti) {
            continue;
        }
        if limit > 0 && printed >= limit {
            continue;
        }
        rows.push(transfer_row(cap, ti, cli.redact, host));
        printed += 1;
    }
    outln!(
        "[MEASURED] one line per transfer in submit order; `#` is the line number of the submit \
         line, `-> #n` the callback. {} transfer(s) selected ({} shown), {} boundary completion(s) \
         selected ({} shown).",
        m.transfers.len(),
        printed,
        m.boundary.len(),
        boundaries_printed
    );
    for l in table(&rows) {
        outln!("  {l}");
    }
    if limit > 0 && m.transfers.len() > printed {
        outln!(
            "  ... {} more transfer(s) not shown (--top {limit})",
            m.transfers.len() - printed
        );
    }
    outln!(
        "  columns: #submit t_us device dir request payload -> callback status moved/requested elapsed data notes"
    );
}

/// The device-absence view: only transfers that follow a gap of at least N ms on
/// the same address. This is how "the phone left the bus" is visible without
/// reading 236 lines.
fn print_gaps(cli: &Cli, cap: &Capture, m: &Matched) {
    let mut last_ts: std::collections::BTreeMap<Address, u64> = std::collections::BTreeMap::new();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut hits = 0usize;
    for &i in &m.transfers {
        let t = &cap.transfers[i];
        let ts = cap.events[t.submit].timestamp_us;
        if let Some(prev) = last_ts.get(&t.addr) {
            let gap = ts as i128 - *prev as i128;
            // i128: `--gaps-ms u64::MAX` used to wrap to a negative threshold and
            // pass everything, which contradicts the header it prints.
            if gap >= (cli.gaps_ms as i128) * 1000 {
                hits += 1;
                let req = match cap.setup_of(t) {
                    Some(s) => format!("{} wLen=0x{:04x}", request_label(&s), s.w_length),
                    None => format!("{} {}", t.xfer.name(), t.dir.name().to_ascii_lowercase()),
                };
                rows.push(vec![
                    format!("#{}", cap.events[t.submit].line_no),
                    t.addr.to_string(),
                    format!("gap {}", us_label(gap as i64)),
                    format!("t={ts}"),
                    req,
                    match cap.status_of(t) {
                        Some(c) => status_label(c),
                        None => "no-callback".into(),
                    },
                ]);
            }
        }
        last_ts.insert(t.addr, ts);
    }
    outln!(
        "[MEASURED] gap view: {} transfer(s) at least {} ms after the previous transfer on the same \
         address.",
        hits, cli.gaps_ms
    );
    if rows.is_empty() {
        outln!("           no such gap in the selected scope — the device never went quiet that long.");
    }
    for l in table(&rows) {
        outln!("  {l}");
    }
}

// ---------------------------------------------------------------------------
// attempts
// ---------------------------------------------------------------------------

fn print_attempts(cli: &Cli, cap: &Capture, m: &Matched, host: &Option<HostCtx>) {
    let g = group_attempts(cap, &cli.filter, cli.plan);
    outln!(
        "[INFERRED] grouping rule: an attempt starts at a control-OUT class request 1 (DFU_DNLOAD) \
         with wLength == 0x{:04x} and continues while the next transfer is a pad (OUT, wLength == \
         0x{:04x}), a drain (class DNLOAD, wLength == 0x{:04x}) or a DFU_GET_STATUS probe; the first \
         other transfer closes the tick, and a tick never spans a device change.",
        cli.plan.setup_len, cli.plan.pad_len, cli.plan.drain_len
    );
    outln!(
        "           the lengths are arguments (--setup-len/--pad-len/--drain-len), not facts about the device."
    );
    outln!(
        "[MEASURED] {} attempt(s); {} selected transfer(s) outside any attempt",
        g.attempts.len(),
        g.outside.len()
    );

    for a in &g.attempts {
        let abort = &cap.transfers[a.abort];
        outln!(
            "  attempt {}  {}  start t={}  (#{})",
            a.index,
            a.addr,
            cap.events[abort.submit].timestamp_us,
            cap.events[abort.submit].line_no
        );
        let mut rows: Vec<Vec<String>> = Vec::new();
        rows.push(attempt_row(cap, "abort", a.abort, cli.redact, host));
        if let Some(p) = a.pad {
            rows.push(attempt_row(cap, "pad", p, cli.redact, host));
        }
        for (n, d) in a.drains.iter().enumerate() {
            rows.push(attempt_row(cap, if n == 0 { "drain" } else { "" }, *d, cli.redact, host));
        }
        for o in &a.others {
            rows.push(attempt_row(cap, "other", *o, cli.redact, host));
        }
        for l in table(&rows) {
            outln!("    {l}");
        }
        if let Some(h) = host.as_ref().filter(|h| h.join.ok) {
            for (what, ti) in [("abort", Some(a.abort)), ("pad", a.pad)] {
                let Some(ti) = ti else { continue };
                if let Some(hx) = host_for(h, ti) {
                    outln!(
                        "    [MEASURED host log] {}: stage={} label={} status={} transferred={}/{} \
                         xfer_micros={} abort_after_ms={}",
                        what,
                        hx.stage,
                        hx.label,
                        hx.status,
                        hx.transferred,
                        hx.w_length,
                        hx.xfer_micros
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "absent".into()),
                        hx.abort_after_ms
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "n/a".into()),
                    );
                }
            }
        }
        outln!("    [INFERRED] abort: {}", abort_verdict(cap, a));
        outln!("    [INFERRED] pad  : {}", pad_verdict(cap, a));
    }

    // The two instruments, side by side, each labelled. The wire cannot show an
    // abort window that never fired: a 4 ms window whose transfer completed in
    // 935 us leaves no trace of the 4 ms. Only the host log knows the number.
    if let Some(h) = host {
        if h.join.ok && !g.attempts.is_empty() {
            let windows: Vec<String> = g
                .attempts
                .iter()
                .map(|a| {
                    host_for(h, a.abort)
                        .and_then(|hx| hx.abort_after_ms)
                        .map(|w| format!("{w} ms"))
                        .unwrap_or_else(|| "n/a".into())
                })
                .collect();
            let wire: Vec<String> = g
                .attempts
                .iter()
                .map(|a| {
                    cap.elapsed_us(&cap.transfers[a.abort])
                        .map(us_label)
                        .unwrap_or_else(|| "n/a".into())
                })
                .collect();
            let host_us: Vec<String> = g
                .attempts
                .iter()
                .map(|a| {
                    host_for(h, a.abort)
                        .and_then(|hx| hx.xfer_micros)
                        .map(|v| format!("{v} us"))
                        .unwrap_or_else(|| "n/a".into())
                })
                .collect();
            let suspect = !h.join.disagreements.is_empty();
            outln!(
                "[{} host log] abort windows in order: {} — a host parameter from abort_after_ms \
                 ({}); the wire cannot show a window that never fired{}",
                if suspect { "SUSPECT" } else { "MEASURED" },
                windows.join(", "),
                h.path.display(),
                if suspect {
                    " — AND the host/wire disagreements listed below mean these windows are \
                     attached to the wrong record; do not quote them"
                } else {
                    ""
                }
            );
            outln!(
                "[MEASURED wire]      abort elapsed in order: {}   [MEASURED host log] xfer_micros: {}",
                wire.join(", "),
                host_us.join(", ")
            );
            let mut deltas = Vec::new();
            for i in 0..cap.transfers.len() {
                if let Some(hi) = h.join.wire_to_host.get(i).copied().flatten() {
                    let hx = &h.xfers[hi];
                    if let (Some(host_us), Some(wire_us)) = (hx.xfer_micros, cap.elapsed_us(&cap.transfers[i])) {
                        deltas.push(host_us as i64 - wire_us);
                    }
                }
            }
            if !deltas.is_empty() {
                let n = deltas.len();
                let sum: i64 = deltas.iter().sum();
                let min = *deltas.iter().min().unwrap();
                let max = *deltas.iter().max().unwrap();
                outln!(
                    "[INFERRED] host minus wire elapsed over {n} matched transfer(s): min {min:+} us, \
                     mean {:+.0} us, max {max:+} us — the host measures libusb submit->callback, the \
                     wire measures the kernel's URB submit->callback; the delta is host-side \
                     overhead, not device time",
                    sum as f64 / n as f64
                );
            }
        }
    }

    // The part of the capture that is not the SETUP sweep: PATCH, the leak
    // reads, CLRSTATUS, enumeration. Grouped, because one line per transfer of
    // 200 transfers is not an answer.
    if !g.outside.is_empty() {
        let mut groups: Vec<(String, Tally)> = Vec::new();
        for &i in &g.outside {
            let t = &cap.transfers[i];
            let req = match cap.setup_of(t) {
                Some(s) => format!("{} wLen=0x{:04x}", request_label(&s), s.w_length),
                None => format!("{} {}", t.xfer.name(), t.dir.name().to_ascii_lowercase()),
            };
            let moved = t.completion.map(|c| cap.events[c].length).unwrap_or(0);
            let status = match cap.status_of(t) {
                Some(c) => status_label(c),
                None => "no-callback".into(),
            };
            let key = format!(
                "{} {} {} -> {moved}/{} B {}",
                t.addr,
                req,
                t.dir.name(),
                cap.events[t.submit].length,
                status
            );
            tally_push(&mut groups, key, cap.events[t.submit].line_no, cap.elapsed_us(t));
        }
        outln!("[MEASURED] outside any attempt (grouped by device, request, length, status):");
        for (k, v) in &groups {
            outln!("           {k}  x{}  elapsed {}", v.count, v.us_span());
        }
        if cli.command == Command::Attempts && cli.top == 0 && groups.len() > 20 {
            outln!("           ({} distinct group(s); use `list` for every transfer)", groups.len());
        }
    }
    let _ = m;
}

fn host_for<'a>(h: &'a HostCtx, transfer: usize) -> Option<&'a HostXfer> {
    if !h.join.ok {
        return None;
    }
    h.join
        .wire_to_host
        .get(transfer)
        .copied()
        .flatten()
        .map(|hi| &h.xfers[hi])
}

fn attempt_row(cap: &Capture, role: &str, i: usize, redact: bool, host: &Option<HostCtx>) -> Vec<String> {
    let mut r = transfer_row(cap, i, redact, host);
    let mut with_role = vec![format!("{role:<5}")];
    with_role.append(&mut r);
    with_role
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn transfer_json(cap: &Capture, i: usize, redact: bool, host: &Option<HostCtx>) -> Value {
    let t = &cap.transfers[i];
    let sub = &cap.events[t.submit];
    let comp = t.completion.map(|c| &cap.events[c]);
    let setup = sub.setup.map(|s| {
        json!({
            "bmRequestType": format!("0x{:02x}", s.bm_request_type),
            "bRequest": format!("0x{:02x}", s.b_request),
            "wValue": format!("0x{:04x}", s.w_value),
            "wIndex": format!("0x{:04x}", s.w_index),
            "wLength": format!("0x{:04x}", s.w_length),
            "name": request_name(&s),
            "kind": s.kind_name(),
            "recipient": s.recipient_name(),
            "descriptor": if s.kind() == 0 && s.b_request == 6 {
                Value::String(descriptor_target(s.w_value, s.w_index))
            } else {
                Value::Null
            },
        })
    });
    json!({
        "tag": format!("{:x}", t.tag),
        "device": t.addr.to_string(),
        "bus": t.addr.bus,
        "dev": t.addr.dev,
        "ep": t.addr.ep,
        "type": t.xfer.name(),
        "dir": t.dir.name(),
        "submit": {
            "line": sub.line_no,
            "t_us": sub.timestamp_us,
            "status": sub.status,
            "length": sub.length,
            "request": match sub.setup { Some(s) => Value::String(request_label(&s)), None => Value::Null },
            "setup": setup,
            "setup_unavailable": sub.setup_unavailable.map(|c| c.to_string()),
            "data_flag": sub.data_flag.map(|c| c.to_string()),
            "data_hex": data_json(sub, redact),
        },
        "completion": comp.map(|c| json!({
            "line": c.line_no,
            "t_us": c.timestamp_us,
            "status": c.status,
            "errno": c.status.and_then(errno_name),
            "usb_note": c.status.and_then(status_note),
            "length": c.length,
            "data_flag": c.data_flag.map(|x| x.to_string()),
            "data_hex": data_json(c, redact),
            "data_printed_bytes": c.data.len(),
            "capped_by_usbmon_display": c.data_capped_by_kernel(),
            "underprinted_vs_declared": c.data_underprinted(),
        })),
        "elapsed_us": cap.elapsed_us(t),
        "short": comp.map(|c| c.status == Some(0) && c.length < sub.length).unwrap_or(false),
        "host_log": host
            .as_ref()
            .filter(|h| h.join.ok)
            .and_then(|h| host_for(h, i))
            .map(|hx| json!({
                "stage": hx.stage,
                "label": hx.label,
                "status": hx.status,
                "xfer_micros": hx.xfer_micros,
                "abort_after_ms": hx.abort_after_ms,
            }))
            .unwrap_or(Value::Null),
    })
}

/// The host trace, as data: every value here came from a9pwn's own log, not from
/// the wire, and the key names say so.
fn host_json(cli: &Cli, host: &Option<HostCtx>) -> Value {
    let _ = cli;
    match host {
        None => Value::Null,
        Some(h) => json!({
            "path": h.path.display().to_string(),
            "xfer_records": h.xfers.len(),
            "join_ok": h.join.ok,
            "join_detail": h.join.detail,
            "matched": h.join.matched,
            "host_total": h.join.host_total,
            "wire_control_total": h.join.wire_control_total,
            "wire_transfers_not_in_host_trace": h.join.skipped,
            "problems": h.problems,
        }),
    }
}

fn data_json(ev: &EventLine, redact: bool) -> Value {
    if !ev.has_data() {
        return Value::Null;
    }
    if redact {
        return Value::String(format!("<{} bytes redacted by --redact-data>", ev.data.len()));
    }
    Value::String(hex_bytes(&ev.data))
}

fn print_json(cli: &Cli, cap: &Capture, m: &Matched, host: &Option<HostCtx>) {
    let problems: Vec<Value> = cap
        .problems
        .iter()
        .map(|p| {
            json!({
                "line": p.line_no,
                "severity": p.severity.label(),
                "code": p.code,
                "boundary": p.is_boundary(),
                "detail": p.detail,
                "excerpt": p.excerpt,
            })
        })
        .collect();

    let addresses: Vec<Value> = address_stats(cap)
        .iter()
        .map(|(a, s)| {
            json!({
                "device": a.to_string(), "events": s.events, "transfers": s.transfers,
                "first_t_us": s.first_ts, "last_t_us": s.last_ts,
            })
        })
        .collect();

    let transfers: Vec<Value> = m
        .transfers
        .iter()
        .map(|&i| transfer_json(cap, i, cli.redact, host))
        .collect();

    let reads_raw = descriptor_reads(cap);
    let reads: Vec<Value> = reads_raw
        .iter()
        .filter(|r| m.has(r.transfer))
        .map(|r| {
            let dev = decode_device_descriptor(&r.data);
            json!({
                "line": r.line_no,
                "device": r.addr.to_string(),
                "wValue": format!("0x{:04x}", r.setup.w_value),
                "wIndex": format!("0x{:04x}", r.setup.w_index),
                "target": descriptor_target(r.setup.w_value, r.setup.w_index),
                "requested": r.requested,
                "transferred": r.transferred,
                "status": r.status,
                "data_printed_bytes": r.data.len(),
                "truncated_by_usbmon": r.data_truncated,
                "device_descriptor": dev.map(|d| json!({
                    "bcdUSB": format!("0x{:04x}", d.bcd_usb),
                    "idVendor": format!("0x{:04x}", d.id_vendor),
                    "idProduct": format!("0x{:04x}", d.id_product),
                    "bcdDevice": format!("0x{:04x}", d.bcd_device),
                    "iManufacturer": d.i_manufacturer,
                    "iProduct": d.i_product,
                    "iSerialNumber": d.i_serial_number,
                })),
            })
        })
        .collect();

    let g = group_attempts(cap, &cli.filter, cli.plan);
    let attempts: Vec<Value> = g
        .attempts
        .iter()
        .map(|a| {
            json!({
                "index": a.index,
                "device": a.addr.to_string(),
                "start_t_us": a.start_ts,
                "abort": transfer_json(cap, a.abort, cli.redact, host),
                "abort_verdict": abort_verdict(cap, a),
                "pad": a.pad.map(|i| transfer_json(cap, i, cli.redact, host)),
                "pad_verdict": pad_verdict(cap, a),
                "drains": a.drains.iter().map(|&i| transfer_json(cap, i, cli.redact, host)).collect::<Vec<_>>(),
                "others": a.others.iter().map(|&i| transfer_json(cap, i, cli.redact, host)).collect::<Vec<_>>(),
            })
        })
        .collect();

    // Serial-descriptor facts, per device, keyed on the declared index.
    let mut serial: Vec<Value> = Vec::new();
    for (addr, declared, reads) in serial_view(cap, &reads_raw) {
        serial.push(json!({
            "device": addr.to_string(),
            "declared_iSerialNumber": declared.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            "declared_from_lines": declared.iter().map(|(_, l)| *l).collect::<Vec<_>>(),
            "string_reads": reads.iter().map(|(i, lang, n, st)| json!({
                "index": i, "langid": format!("0x{lang:04x}"), "transferred": n, "status": st,
                "is_declared_index": declared.iter().any(|(d, _)| d == i),
            })).collect::<Vec<_>>(),
        }));
    }

    let errs = cap.errors();
    let doc = json!({
        "tool": TOOL,
        "tool_version": TOOL_VERSION,
        "schema": SCHEMA,
        "file": {
            "path": cli.file.as_ref().map(|p| p.display().to_string()),
            "bytes": cap.bytes,
            "sha256": if cli.hash { Value::String(cap.sha256.clone()) } else { Value::Null },
        },
        "parse": {
            "lines": cap.lines,
            "events": cap.events.len(),
            "errors": errs,
            "warnings": cap.warnings(),
            "boundary_completions": cap.unmatched_completions.len(),
            "problems": problems,
        },
        "scope": {
            "filter": describe_filter(cli),
            "matched_transfers": m.transfers.len(),
            "matched_events": m.events.len(),
            "addresses": addresses,
        },
        "attempts": {
            "plan": {
                "setup_len": cli.plan.setup_len,
                "pad_len": cli.plan.pad_len,
                "drain_len": cli.plan.drain_len,
            },
            "items": attempts,
            "outside_count": g.outside.len(),
            "host_log": host_json(cli, host),
        },
        "descriptor_reads": reads,
        "serial_descriptor": serial,
        "transfers": transfers,
        "problems_not_listed": cap.problems_not_listed,
        "exit_code": expected_exit(cli, cap, m),
    });
    match serde_json::to_string_pretty(&doc) {
        Ok(s) => outln!("{s}"),
        Err(e) => eprintln!("usbmon: could not serialise JSON: {e}"),
    }
}

fn expected_exit(cli: &Cli, cap: &Capture, m: &Matched) -> i32 {
    if cap.errors() > 0 && !cli.force {
        return EXIT_STRUCTURAL;
    }
    if m.is_empty(cli.command) {
        return EXIT_NO_URBS;
    }
    if cli.strict && cap.warnings() > 0 {
        return EXIT_STRICT_WARNINGS;
    }
    if cap.errors() > 0 {
        return EXIT_STRUCTURAL;
    }
    EXIT_OK
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

/// The optional second instrument: a9pwn's own JSONL trace. Everything read
/// from it is labelled `[MEASURED host log]` and kept separate from wire values,
/// because the two instruments do not measure the same interval: the host times
/// libusb submit->callback, the kernel times URB submit->callback.
struct HostCtx {
    path: PathBuf,
    xfers: Vec<HostXfer>,
    join: HostJoin,
    problems: Vec<String>,
}

fn load_host_log(cli: &Cli, capture: &Path) -> Result<Option<HostCtx>, String> {
    if cli.no_host_log {
        return Ok(None);
    }
    let (path, explicit) = match &cli.host_log {
        Some(p) => (p.clone(), true),
        None => {
            // The capture script names a capture `X.txt` and the matching trace
            // is `X.jsonl`; `X.txt.jsonl` is also accepted, because a caller may
            // have written it that way. Nothing else is guessed.
            let mut candidates: Vec<PathBuf> = Vec::new();
            if let Some(stem) = capture.with_extension("jsonl").to_str() {
                candidates.push(PathBuf::from(stem));
            }
            let mut with_suffix = capture.as_os_str().to_os_string();
            with_suffix.push(".jsonl");
            candidates.push(PathBuf::from(with_suffix));
            match candidates.into_iter().find(|p| p.exists()) {
                Some(p) => (p, false),
                None => return Ok(None),
            }
        }
    };
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("cannot read host trace {}: {e}", path.display()))?;
    let (xfers, problems) = parse_host_jsonl(&text);
    if xfers.is_empty() {
        if explicit {
            return Err(format!(
                "host trace {} has no `xfer` records this tool can read",
                path.display()
            ));
        }
        // An auto-discovered sibling with nothing usable in it is not a host
        // log; saying "join OK 0/0" would be a claim about nothing.
        eprintln!(
            "usbmon: sibling {} has no readable `xfer` records; continuing without a host log",
            path.display()
        );
        return Ok(None);
    }
    Ok(Some(HostCtx {
        path,
        xfers,
        join: HostJoin {
            wire_to_host: Vec::new(),
            matched: 0,
            host_total: 0,
            wire_control_total: 0,
            skipped: 0,
            ok: false,
            detail: String::new(),
            disagreements: Vec::new(),
            divergences: Vec::new(),
        },
        problems,
    }))
}

fn print_host_header(cli: &Cli, host: &Option<HostCtx>, capture: &Path) {
    if cli.no_host_log {
        outln!("host log   : disabled by --no-host-log");
        return;
    }
    match host {
        None => {
            outln!(
                "host log   : none (no {}.jsonl sibling; --host-log FILE to name one)",
                capture.display()
            );
        }
        Some(h) => {
            outln!(
                "host log   : {} ({} xfer record(s)){}",
                h.path.display(),
                h.xfers.len(),
                if h.problems.is_empty() {
                    String::new()
                } else {
                    format!(", {} unreadable line(s)", h.problems.len())
                }
            );
            if !h.join.ok {
                // Nothing from this trace may reach a per-attempt value.
                outln!(
                    "[WARNING] host log join FAILED: {} — no host value is attached to any transfer",
                    h.join.detail
                );
            }
        }
    }
}

/// Per device: the serial indices its device descriptor declares, and every
/// STRING read it performed. Deliberately index-agnostic — the declared index
/// moves across re-enumerations on real hardware.
#[allow(clippy::type_complexity)]
fn serial_view(
    cap: &Capture,
    reads: &[DescriptorRead],
) -> Vec<(Address, Vec<(u8, u64)>, Vec<(u8, u16, u32, String)>)> {
    let _ = cap;
    let mut per_addr: Vec<(Address, Vec<(u8, u64)>, Vec<(u8, u16, u32, String)>)> = Vec::new();
    for r in reads {
        let entry = match per_addr.iter_mut().find(|(a, _, _)| *a == r.addr) {
            Some(e) => e,
            None => {
                per_addr.push((r.addr, Vec::new(), Vec::new()));
                per_addr.last_mut().unwrap()
            }
        };
        let (dtype, idx) = ((r.setup.w_value >> 8) as u8, (r.setup.w_value & 0xff) as u8);
        if dtype == 1 && r.status == Some(0) {
            if let Some(d) = decode_device_descriptor(&r.data) {
                if !entry.1.iter().any(|(i, _)| *i == d.i_serial_number) {
                    entry.1.push((d.i_serial_number, r.line_no));
                }
            }
        }
        if dtype == 3 {
            let status = match r.status {
                Some(c) => status_label(c),
                None => "no-callback".into(),
            };
            entry.2.push((idx, r.setup.w_index, r.transferred, status));
        }
    }
    per_addr
        .into_iter()
        .filter(|(_, d, r)| !d.is_empty() && !r.is_empty())
        .collect()
}

/// Left-aligned, two-space-separated, widths from the content.
fn table(rows: &[Vec<String>]) -> Vec<String> {
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    let mut w = vec![0usize; cols];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    rows.iter()
        .map(|r| {
            let mut s = String::new();
            for (i, c) in r.iter().enumerate() {
                if i > 0 {
                    s.push_str("  ");
                }
                s.push_str(c);
                if i + 1 < r.len() {
                    for _ in c.chars().count()..w[i] {
                        s.push(' ');
                    }
                }
            }
            s.trim_end().to_string()
        })
        .collect()
}
