//! `traceview` CLI. Reads one trace file and prints a summary. Read-only: it
//! opens no USB device and writes only to stdout.
//!
//! Exit codes (stable; a script may branch on them):
//!   0  read and summarised — note that this is **not** a statement that the run
//!      succeeded; a failed run reads fine. The signals section says what the
//!      trace contains.
//!   2  bad arguments
//!   3  the file cannot be read
//!   4  no records parsed at all
//!   5  `--expect-sha256` did not match the file
//!   6  `--strict` and the file has malformed/unrecognised lines, field-order
//!      violations, or a non-monotonic `seq`

use std::path::PathBuf;
use std::process::ExitCode;

use traceview::{load, render, to_json, VERSION};

const USAGE: &str = "\
traceview — read an a9pwn trace file and report what is actually in it

USAGE:
    traceview [OPTIONS] <TRACE>

ARGS:
    <TRACE>    trace file: a9pwn JSONL (INTERFACE.md §5), or a legacy a9ctl text
               log such as a9ctl/stage-setup.log. The dialect is detected.

OPTIONS:
    --json                 print the same measurements as one JSON object
    --expect-sha256 <HEX>  refuse to summarise unless the file hashes to HEX
                           (case-insensitive). Use this to pin the report to
                           exact bytes: a summary of a file that has since been
                           edited is worthless, and this makes that detectable.
    --strict               exit 6 on malformed/unrecognised lines, field-order
                           violations, or a non-monotonic seq
    -h, --help             print this help
    -V, --version          print the version

EXIT CODES:
    0 read · 2 usage · 3 unreadable · 4 no records · 5 sha mismatch · 6 strict

This tool reads a file. It does not open a USB device, does not run a9pwn, and
does not know anything the file does not say.";

struct Args {
    path: Option<PathBuf>,
    json: bool,
    expect: Option<String>,
    strict: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        path: None,
        json: false,
        expect: None,
        strict: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("traceview {VERSION}");
                std::process::exit(0);
            }
            "--json" => a.json = true,
            "--strict" => a.strict = true,
            "--expect-sha256" => {
                a.expect = Some(
                    it.next()
                        .ok_or_else(|| "--expect-sha256 needs a hexadecimal argument".to_string())?,
                );
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option {other:?}\n\n{USAGE}"));
            }
            other => {
                if a.path.is_some() {
                    return Err(format!("more than one trace file given ({other:?})\n\n{USAGE}"));
                }
                a.path = Some(PathBuf::from(other));
            }
        }
    }
    if a.path.is_none() {
        return Err(format!("no trace file given\n\n{USAGE}"));
    }
    Ok(a)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("traceview: {e}");
            return ExitCode::from(2);
        }
    };
    let path = args.path.expect("checked by parse_args");

    let summary = match load(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("traceview: {e}");
            return ExitCode::from(3);
        }
    };

    if let Some(expect) = &args.expect {
        let expect = expect.trim().to_ascii_lowercase();
        if expect != summary.sha256 {
            eprintln!(
                "traceview: SHA-256 mismatch — refusing to summarise\n  expected {expect}\n  actual   {}",
                summary.sha256
            );
            return ExitCode::from(5);
        }
    }

    if args.json {
        match serde_json::to_string_pretty(&to_json(&summary)) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("traceview: cannot serialise summary: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        print!("{}", render(&summary));
    }

    if summary.records == 0 {
        eprintln!("traceview: no records parsed from {}", summary.path);
        return ExitCode::from(4);
    }

    let problems = summary.malformed.len()
        + summary.unrecognised.len()
        + summary.key_order_violations.len()
        + summary.seq.out_of_order.len()
        + summary.seq.gaps.len();
    if args.strict && problems > 0 {
        eprintln!("traceview: --strict: {problems} structural problem(s) in {}", summary.path);
        return ExitCode::from(6);
    }

    ExitCode::SUCCESS
}
