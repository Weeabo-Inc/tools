//! Integration tests for traceview.
//!
//! Two of these are deliberately anchored to a file **outside this crate**:
//! `a9ctl/stage-setup.log` is the project's own 384-timeout failure log, named by
//! `HANDOFF.md` §10, `a9pwn/src/trace.rs` and `a9pwn/src/verdict.rs` as the
//! regression signature. A viewer tested only against fixtures written by its own
//! author proves that the author is self-consistent, not that the tool reads the
//! real artefact. If that file moves, this suite fails and says where it looked.

use std::path::{Path, PathBuf};
use std::process::Command;

use traceview::{load, render, to_json, Dialect, Severity};

fn fx(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// `tools/arlo/traceview` -> workspace root -> `a9ctl/stage-setup.log`.
fn real_384_timeout_log() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("a9ctl")
        .join("stage-setup.log")
}

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&dir).expect("create target tmp dir");
    dir.join(name)
}

// ------------------------------------------------------- the real fixture

#[test]
fn real_384_timeout_log_renders_its_signature() {
    let path = real_384_timeout_log();
    assert!(
        path.is_file(),
        "the project's 384-timeout regression fixture is not at {}.\n\
         It is the log named by HANDOFF.md §10 and by a9pwn's trace.rs/verdict.rs\n\
         tests. If it moved, fix this path — this test exists to render the real\n\
         failure, not a stand-in written by traceview's author.",
        path.display()
    );
    let s = load(&path).expect("read the real fixture");

    assert_eq!(s.dialect, Dialect::LegacyA9ctl);
    assert_eq!(s.lines_total, 773);
    assert_eq!(s.records, 768, "384 async attempts + 384 pad requests");
    assert_eq!(s.notes_total, 4, "the log's four header lines");
    assert_eq!(s.lines_blank, 1);
    assert_eq!(s.malformed.len(), 0);
    assert_eq!(s.unrecognised.len(), 0);

    // The sweep
    assert_eq!(s.setup.attempts, 384);
    assert_eq!(s.setup.windows_ordered.len(), 384);
    assert_eq!(s.setup.windows_distinct, vec![4, 5, 0, 1, 2, 3]);
    assert_eq!(s.setup.period, Some(6), "the sweep is exactly periodic");
    assert_eq!(s.setup.repeats_back_to_back, 0, "the window advanced every attempt");
    assert!(!s.setup.pinned(), "six distinct windows is not a pinned sweep");
    assert_eq!(s.setup.windows_unreported, 0);

    // The pad request — the pass condition that never came
    assert_eq!(s.setup.pad_requests, 384);
    assert_eq!(s.setup.pad_timeout, 384);
    assert_eq!(s.setup.pad_stall, 0);
    assert_eq!(s.setup.pad_sizes_distinct, vec![1280]);

    // Absence of xfer_micros is itself the measurement: the legacy log does not
    // carry it, so "no early cancels" here is not evidence about timing.
    assert_eq!(s.setup.micros_present, 0);
    assert_eq!(s.setup.early_cancels, 0);

    assert_eq!(s.stage_status("SETUP", "CANCELLED"), 384);
    assert_eq!(s.stage_status("SETUP", "TIMEOUT"), 384);
    assert_eq!(s.stage_total("SETUP"), 768);

    // The render must be recognisable to someone who knows the log.
    let text = render(&s);
    assert!(text.contains("[4, 5, 0, 1, 2, 3] x 64"), "{text}");
    assert!(text.contains("STALL=0 TIMEOUT=384"), "{text}");
    assert!(text.contains("pad sizes (distinct): [1280]"), "{text}");
    assert!(text.contains("device : CPID 0x8000"), "{text}");
    assert!(text.contains("pinned sweep        : no"), "{text}");
    assert!(
        text.contains("pwned token     : not present anywhere in this file"),
        "the 384-timeout log contains no success token; the render must say that about the file, and must not claim anything about the device: {text}"
    );

    // And the two alarms the log is famous for.
    let flags = s.flags();
    assert!(
        flags
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("never STALLed")),
        "{flags:#?}"
    );
    assert!(
        !flags
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("PINNED SWEEP")),
        "this log's sweep is not pinned; flagging it would be a false alarm: {flags:#?}"
    );
}

/// The same failure signature, expressed in the live JSONL format, must produce
/// the same reading. This is what makes the legacy log usable as a baseline for
/// new runs.
#[test]
fn jsonl_replay_of_the_same_signature_agrees_with_the_legacy_log() {
    let path = tmp("generated-384-timeout.jsonl");
    write_generated_384(&path);

    let legacy = load(&real_384_timeout_log()).expect("legacy");
    let jsonl = load(&path).expect("generated");

    assert_eq!(jsonl.dialect, Dialect::Jsonl);
    assert_eq!(jsonl.setup.attempts, legacy.setup.attempts);
    assert_eq!(jsonl.setup.windows_ordered, legacy.setup.windows_ordered);
    assert_eq!(jsonl.setup.windows_distinct, legacy.setup.windows_distinct);
    assert_eq!(jsonl.setup.period, legacy.setup.period);
    assert_eq!(jsonl.setup.repeats_back_to_back, legacy.setup.repeats_back_to_back);
    assert_eq!(jsonl.setup.pinned(), legacy.setup.pinned());
    assert_eq!(jsonl.setup.pad_requests, legacy.setup.pad_requests);
    assert_eq!(jsonl.setup.pad_timeout, legacy.setup.pad_timeout);
    assert_eq!(jsonl.setup.pad_stall, legacy.setup.pad_stall);
    assert_eq!(jsonl.setup.pad_sizes_distinct, legacy.setup.pad_sizes_distinct);
    assert_eq!(
        jsonl.stage_status("SETUP", "CANCELLED"),
        legacy.stage_status("SETUP", "CANCELLED")
    );
    assert_eq!(
        jsonl.stage_status("SETUP", "TIMEOUT"),
        legacy.stage_status("SETUP", "TIMEOUT")
    );

    // The one place the dialects must differ, and it must be visible.
    assert_eq!(jsonl.setup.micros_present, 384);
    assert_eq!(legacy.setup.micros_present, 0);
    assert_eq!(jsonl.setup.early_cancels, 0, "windows 1..5 all waited their window");

    let text = render(&jsonl);
    assert!(text.contains("[4, 5, 0, 1, 2, 3] x 64"), "{text}");
    assert!(text.contains("xfer_micros present on 384/384 attempt(s)"), "{text}");
    assert!(
        jsonl
            .flags()
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("never STALLed")),
        "the generated replay must raise the same alarm as the real log"
    );
}

/// 384 rounds of `abort_ms -> Cancelled len=0` then `pad request (1280) -> Timeout`,
/// written as JSONL with the request fields the frozen contract carries.
fn write_generated_384(path: &Path) {
    let windows = [4u32, 5, 0, 1, 2, 3];
    let mut out = String::new();
    out.push_str(
        r#"{"seq":1,"stage":"-","kind":"enumerated","t_micros":100,"detail":"PID 0x1227=1"}"#,
    );
    out.push('\n');
    let mut seq = 2u64;
    let mut xseq = 1u64;
    for i in 0..384u64 {
        let w = windows[(i % 6) as usize];
        let t = 1000 + i * 100;
        // A real wait: a 0 ms window may legitimately return in under 1 us, and
        // gaster's starting point is 0, so this is not the a9ctl defect.
        let micros = if w == 0 { 0 } else { (w as u64) * 1000 + 5 };
        out.push_str(&format!(
            r#"{{"seq":{seq},"stage":"SETUP","kind":"xfer","t_micros":{t},"label":"async-abort","status":"CANCELLED","bm_request_type":33,"b_request":1,"w_value":0,"w_index":0,"w_length":2048,"transferred":0,"requested":2048,"xfer_micros":{micros},"libusb_rc":0,"abort_after_ms":{w},"xfer_seq":{xseq}}}"#
        ));
        out.push('\n');
        seq += 1;
        xseq += 1;
        out.push_str(&format!(
            r#"{{"seq":{seq},"stage":"SETUP","kind":"xfer","t_micros":{},"label":"pad-request","status":"TIMEOUT","bm_request_type":0,"b_request":0,"w_value":0,"w_index":0,"w_length":1280,"transferred":0,"requested":1280,"xfer_micros":5001,"libusb_rc":-7,"xfer_seq":{xseq}}}"#,
            t + 1
        ));
        out.push('\n');
        seq += 1;
        xseq += 1;
    }
    std::fs::write(path, out.as_bytes()).expect("write generated fixture");
}

// ------------------------------------------------------------- in-scope fixtures

#[test]
fn pinned_sweep_is_flagged_as_an_alarm() {
    let s = load(&fx("synthetic-pinned-sweep.jsonl")).expect("read");
    assert_eq!(s.malformed.len(), 0);
    assert_eq!(s.setup.attempts, 4);
    assert_eq!(s.setup.windows_distinct, vec![3]);
    assert_eq!(s.setup.repeats_back_to_back, 3);
    assert_eq!(s.setup.period, Some(1));
    assert!(s.setup.pinned(), "4 attempts, 1 window");
    assert_eq!(s.setup.pad_timeout, 4);
    assert_eq!(s.setup.pad_stall, 0);

    let text = render(&s);
    assert!(text.contains("pinned sweep        : YES"), "{text}");
    assert!(text.contains("[3] x 4"), "{text}");
    let flags = s.flags();
    assert!(
        flags
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("PINNED SWEEP")),
        "{flags:#?}"
    );
    // The predicate failure the stage machine recorded is surfaced too.
    assert_eq!(s.predicates.failed.get("abort_window_can_vary"), Some(&1));
    assert!(text.contains("abort_window_can_vary"), "{text}");
}

#[test]
fn early_cancel_is_distinguished_from_a_legitimate_zero_window() {
    let s = load(&fx("synthetic-early-cancel.jsonl")).expect("read");
    assert_eq!(s.setup.attempts, 2);
    assert_eq!(s.setup.windows_ordered, vec![5, 0]);
    assert_eq!(s.setup.windows_distinct, vec![5, 0]);
    assert_eq!(s.setup.period, None, "two different windows is not a period");
    assert_eq!(s.setup.repeats_back_to_back, 0);
    assert_eq!(s.setup.micros_present, 2);
    assert_eq!(
        s.setup.early_cancels, 1,
        "the 5 ms window cancelled after 12 us did not wait; the 0 ms window is allowed to"
    );
    assert!(
        s.flags()
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("never waited")),
        "{:#?}",
        s.flags()
    );
}

#[test]
fn happy_path_trace_reports_the_pwned_token_and_no_alarms() {
    let s = load(&fx("synthetic-pwned-run.jsonl")).expect("read");
    assert_eq!(s.malformed.len(), 0);
    assert_eq!(s.unrecognised.len(), 0);
    assert_eq!(s.key_order_violations.len(), 0);
    assert_eq!(s.seq.out_of_order.len(), 0);
    assert_eq!(s.seq.gaps.len(), 0);
    assert_eq!(s.seq.first, Some(1));
    assert_eq!(s.seq.last, Some(17));

    let hit = s.pwned_hit.as_ref().expect("PWND token");
    assert_eq!(hit.line, 17);
    assert!(hit.text.contains("PWND:[checkm8]"));

    assert_eq!(s.setup.attempts, 1);
    assert_eq!(s.setup.pad_requests, 1);
    assert_eq!(s.setup.pad_stall, 1, "the pass condition was reached");
    assert_eq!(s.setup.pad_timeout, 0);
    assert_eq!(s.setup.pad_sizes_distinct, vec![1280]);
    assert!(!s.setup.pinned());

    assert_eq!(s.spray.stall_requests, 1);
    assert_eq!(s.spray.stall_not_stalling, 0);
    assert_eq!(s.spray.leak_requests, 2);
    assert_eq!(s.spray.leak_not_zero, 0, "both reads returned zero bytes");

    assert_eq!(s.resets.attempted, 2);
    assert_eq!(s.resets.real, 2);
    assert_eq!(s.resets.pipe_cycle, 0);
    assert_eq!(s.rounds, 2);
    assert_eq!(s.max_round, Some(1));
    assert_eq!(s.predicates.failed.len(), 0);
    assert_eq!(
        s.predicates.passed.len(),
        4,
        "dfu_set_state_wait_reset, setup_pad_stall, checkm8_usb_request_stall, patch_overflow_stall"
    );
    assert_eq!(s.enumerated.len(), 1);
    assert_eq!(s.device_path.len(), 1);

    let flags = s.flags();
    let alarms: Vec<&str> = flags
        .iter()
        .filter(|f| f.severity == Severity::Alarm)
        .map(|f| f.text.as_str())
        .collect();
    assert!(alarms.is_empty(), "a clean run must not raise alarms: {alarms:#?}");

    let text = render(&s);
    assert!(
        text.contains("pwned token     : FOUND at line 17"),
        "the success token must be the first thing the reader sees: {text}"
    );
    assert!(text.contains("STALL=1 TIMEOUT=0"), "{text}");
}

#[test]
fn truncated_and_bad_lines_degrade_without_panicking() {
    let s = load(&fx("synthetic-malformed.jsonl")).expect("read");
    // 3 records survived: the clean line, and the two that parse but are
    // structurally wrong.
    assert_eq!(s.records, 3);
    assert_eq!(s.malformed.len(), 3, "{:#?}", s.malformed);
    assert_eq!(s.malformed[0].line, 2);
    assert!(s.malformed[0].why.contains("invalid JSON"), "{:?}", s.malformed[0]);
    assert_eq!(s.malformed[1].line, 6);
    assert!(
        s.malformed[1].why.contains("missing required key kind"),
        "{:?}",
        s.malformed[1]
    );
    assert_eq!(s.malformed[2].line, 7);
    assert!(
        s.malformed[2].why.contains("without a status"),
        "{:?}",
        s.malformed[2]
    );
    assert_eq!(s.unrecognised.len(), 1);
    assert_eq!(s.unrecognised[0].line, 3);

    // seq: 1, then 4 (a gap), then 3 (out of order).
    assert_eq!(s.seq.gaps.len(), 1);
    assert_eq!(s.seq.gaps[0].1, 2);
    assert_eq!(s.seq.out_of_order.len(), 1);
    assert_eq!(s.seq.out_of_order[0], (5, 4, 3));

    let text = render(&s);
    assert!(text.contains("malformed lines (3 total)"), "{text}");
    assert!(text.contains("unrecognised lines (1 total)"), "{text}");
    assert!(
        s.flags()
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("NOT a complete trace")),
        "{:#?}",
        s.flags()
    );
}

#[test]
fn field_order_violation_is_reported() {
    let s = load(&fx("synthetic-malformed.jsonl")).expect("read");
    assert_eq!(s.key_order_violations.len(), 1);
    assert_eq!(s.key_order_violations[0].line, 4);
    assert!(
        s.key_order_violations[0].why.contains("required key seq"),
        "{:?}",
        s.key_order_violations[0]
    );
    let text = render(&s);
    assert!(text.contains("OUT OF CONTRACT"), "{text}");
}

#[test]
fn all_bad_file_yields_no_records() {
    let s = load(&fx("synthetic-all-bad.jsonl")).expect("read");
    assert_eq!(s.records, 0);
    assert_eq!(s.malformed.len(), 2);
    assert!(
        s.flags()
            .iter()
            .any(|f| f.severity == Severity::Alarm && f.text.contains("no records parsed")),
        "{:#?}",
        s.flags()
    );
}

#[test]
fn every_stage_with_transfers_gets_a_row_in_the_table() {
    // Guards a whole-table rendering failure, not just a number: a row that is
    // computed and never printed looks exactly like a stage that never ran, and
    // a stray newline inside a row looks like a gap in the table.
    let s = load(&fx("synthetic-pwned-run.jsonl")).expect("read");
    let text = render(&s);
    let stages = s.stages_seen();
    assert!(stages.contains(&"SETUP".to_string()), "{stages:?}");

    let lines: Vec<&str> = text.lines().collect();
    let head = lines
        .iter()
        .position(|l| l.starts_with("    stage") && l.contains("total"))
        .expect("table header row");
    for (i, st) in stages.iter().enumerate() {
        let row = lines.get(head + 1 + i).copied().unwrap_or("");
        assert!(
            row.starts_with(&format!("    {st}")),
            "line {} should be the row for stage {st}, got {row:?} (a blank line here means the table is mis-rendered)",
            head + 1 + i
        );
    }
    let total_row = lines.get(head + 1 + stages.len()).copied().unwrap_or("");
    assert!(
        total_row.starts_with("    TOTAL"),
        "the TOTAL row must follow the stage rows directly, got {total_row:?}"
    );

    // And the row must carry the stage's own numbers: SETUP ran two transfers
    // in this fixture (one aborted attempt, one pad STALL).
    let setup_row = lines
        .iter()
        .find(|l| l.starts_with("    SETUP"))
        .expect("SETUP row");
    let nums: Vec<u64> = setup_row
        .split_whitespace()
        .skip(1)
        .filter_map(|t| t.parse().ok())
        .collect();
    assert_eq!(
        nums.last().copied(),
        Some(s.stage_total("SETUP")),
        "the row's total column must be the stage's total: {setup_row}"
    );
    assert_eq!(nums.last().copied(), Some(2), "SETUP ran two transfers: {setup_row}");
    assert!(nums.iter().any(|n| *n > 0), "the row must not be all zeroes: {setup_row}");
}

#[test]
fn json_output_carries_the_same_numbers_as_the_text_render() {
    let s = load(&fx("synthetic-pwned-run.jsonl")).expect("read");
    let v = to_json(&s);
    assert_eq!(v["tool"], "traceview");
    assert_eq!(v["schema"], 1);
    assert_eq!(v["sha256"], s.sha256);
    assert_eq!(v["setup"]["pad_stall"], 1);
    assert_eq!(v["setup"]["pad_timeout"], 0);
    assert_eq!(v["spray"]["leak_requests"], 2);
    assert_eq!(v["resets"]["real"], 2);
    assert_eq!(v["pwned_marker"]["line"], 17);
    assert_eq!(v["malformed"].as_array().map(|a| a.len()), Some(0));
    assert!(v["flags"].is_array());
    // Round-trips: a consumer can parse it without a schema.
    let text = serde_json::to_string_pretty(&v).expect("serialise");
    let back: serde_json::Value = serde_json::from_str(&text).expect("re-parse");
    assert_eq!(back, v);
}

// --------------------------------------------------------------------- the CLI

fn run_cli(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_traceview"))
        .args(args)
        .output()
        .expect("run traceview");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn cli_exit_codes_are_the_documented_ones() {
    let good = fx("synthetic-pwned-run.jsonl");
    let good = good.to_str().expect("utf-8 path");

    let (code, stdout, stderr) = run_cli(&[good]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("PWND:[checkm8]"), "{stdout}");

    // --strict on a trace with structural problems
    let bad = fx("synthetic-malformed.jsonl");
    let bad = bad.to_str().expect("utf-8 path");
    let (code, stdout, _) = run_cli(&["--strict", bad]);
    assert_eq!(code, 6, "{stdout}");
    let (code, _, _) = run_cli(&[bad]);
    assert_eq!(code, 0, "without --strict a damaged trace still summarises");

    // no records at all
    let allbad = fx("synthetic-all-bad.jsonl");
    let (code, _, stderr) = run_cli(&[allbad.to_str().expect("utf-8 path")]);
    assert_eq!(code, 4, "{stderr}");

    // unreadable
    let (code, _, _) = run_cli(&["E:\\Reverseing\\Arlo\\tools\\arlo\\traceview\\no-such-trace.jsonl"]);
    assert_eq!(code, 3);

    // usage
    let (code, _, _) = run_cli(&[]);
    assert_eq!(code, 2);
    let (code, _, _) = run_cli(&["--nonsense", good]);
    assert_eq!(code, 2);

    // --expect-sha256 pins the read to exact bytes
    let bytes = std::fs::read(&good).expect("read fixture");
    let sha = traceview::sha256_hex(&bytes);
    let (code, stdout, _) = run_cli(&["--expect-sha256", &sha, good]);
    assert_eq!(code, 0);
    assert!(stdout.contains(&sha), "{stdout}");
    let (code, _, stderr) = run_cli(&["--expect-sha256", &"0".repeat(64), good]);
    assert_eq!(code, 5);
    assert!(stderr.contains("refusing to summarise"), "{stderr}");
}
