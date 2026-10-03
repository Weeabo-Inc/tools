//! Integration tests for the `usbmon` binary: exit codes, the exact ground truth
//! of the E4 gold capture, and a doctored copy for every rejection rule.
//!
//! HOUSE RULE THIS FILE EXISTS FOR: a check earns trust by having been shown to
//! fail. So every "detects X" test has a positive control (the real capture) and
//! a negative control (a doctored copy that must be rejected), and the gold
//! ground truth is pinned to the fixture's sha256 so the assertions cannot drift
//! onto other bytes.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// The reference checkm8 pwn capture, hand-verified by the Lead. Every number
/// below was read off these exact bytes; `--expect-sha256` proves it.
const GOLD_SHA: &str = "d66021f45cf01d9a0ff9df02062fa5d114524aed7570dcbc6c7ec8e0914926fa";
/// e0-ident.txt, from the fixture's own .meta file.
const E0_SHA: &str = "f531814717410e5d3c238ac987d1f5fde8907065d3deaca12c6852fdf0e7e0f8";

fn manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn repo_root() -> PathBuf {
    manifest().join("..").join("..").join("..")
}
fn fixture(name: &str) -> PathBuf {
    repo_root().join("a9pwn-traces").join("linux").join(name)
}
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_usbmon")
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

/// Collapse runs of whitespace so a table row can be asserted without pinning
/// column padding (alignment is presentation, not evidence).
fn flat(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Run {
    /// Match against the whitespace-collapsed output.
    fn assert_flat(&self, needle: &str) -> &Self {
        let hay = flat(&self.out);
        let want = flat(needle);
        assert!(
            hay.contains(&want),
            "expected (whitespace-collapsed) to contain {want:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.out,
            self.err
        );
        self
    }
    fn assert_not_flat(&self, needle: &str) -> &Self {
        let hay = flat(&self.out);
        let want = flat(needle);
        assert!(
            !hay.contains(&want),
            "expected (whitespace-collapsed) NOT to contain {want:?}\n--- stdout ---\n{}",
            self.out
        );
        self
    }
    fn assert_contains(&self, needle: &str) -> &Self {
        assert!(
            self.out.contains(needle),
            "expected output to contain {needle:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.out,
            self.err
        );
        self
    }
    fn assert_not_contains(&self, needle: &str) -> &Self {
        assert!(
            !self.out.contains(needle),
            "expected output NOT to contain {needle:?}\n--- stdout ---\n{}",
            self.out
        );
        self
    }
}

fn run(args: &[&str]) -> Run {
    let o = Command::new(bin())
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("could not run {}: {e}", bin()));
    Run {
        code: o.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&o.stdout).into_owned(),
        err: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn tmp_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("usbmon-tests-{}", std::process::id()));
    std::fs::create_dir_all(&d).expect("create temp dir");
    d
}

fn tmp(name: &str, content: &[u8]) -> PathBuf {
    let p = tmp_dir().join(name);
    std::fs::write(&p, content).expect("write temp fixture");
    p
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Read a real fixture. A missing fixture FAILS the test: a silently skipped
/// positive control is how a suite goes green while proving nothing.
fn real(name: &str) -> String {
    let p = fixture(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "fixture {} is required by this suite and could not be read: {e}",
            p.display()
        )
    })
}

fn json_of(run: &Run) -> Value {
    serde_json::from_str(&run.out).unwrap_or_else(|e| {
        panic!(
            "output was not valid JSON: {e}\n--- stdout ---\n{}",
            run.out
        )
    })
}

// ---------------------------------------------------------------------------
// The E4 gold capture: a successful checkm8 pwn, start to finish
// ---------------------------------------------------------------------------

#[test]
fn gold_capture_parses_clean_and_is_pinned_to_its_bytes() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "report", "--expect-sha256", &GOLD_SHA.to_uppercase()]);
    assert_eq!(r.code, 0, "gold capture must parse clean\n{}", r.out);
    r.assert_contains("236 lines, 236 events, 0 structural error(s)");
    r.assert_contains("1 warning(s), 1 boundary completion(s)");
    r.assert_contains("--expect-sha256 matched");
}

#[test]
fn gold_ground_truth_setup_pad_stall_is_reproduced_exactly() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "report", "--device", "1:005"]);
    assert_eq!(r.code, 0);
    // pad: setup 00 00 0000 0000 0500, submitted 177811285, -32 at 177812174.
    r.assert_flat("pad #57 177811285 1:005:0 OUT GET_STATUS(0) wLen=0x0500");
    r.assert_flat("-> #58 -32 EPIPE 0/1280 B 889 us");
    r.assert_contains("[INFERRED] pad  : PAD STALL (EPIPE)");
}

#[test]
fn gold_ground_truth_aborted_dnload_and_completed_windows_are_reproduced() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "attempts", "--device", "1:005"]);
    assert_eq!(r.code, 0);
    // The aborted 2048-byte DNLOAD: 177811111 -> 177811228 = 117 us, status -2.
    r.assert_flat("abort #55 177811111 1:005:0 OUT DFU_DNLOAD(1) wLen=0x0800 -> #56 -2 ENOENT 0/2048 B 117 us");
    r.assert_contains("[INFERRED] abort: UNLINKED (ENOENT) after 0 B of 2048 — cancelled");
    // Two windows that completed the whole download: 992 us and 974 us, each
    // followed by a 64-byte drain.
    r.assert_flat("abort #47 177808811 1:005:0 OUT DFU_DNLOAD(1) wLen=0x0800 -> #48 0 OK 2048/2048 B 992 us");
    r.assert_flat("abort #51 177809950 1:005:0 OUT DFU_DNLOAD(1) wLen=0x0800 -> #52 0 OK 2048/2048 B 974 us");
    r.assert_flat("drain #49 177809864 1:005:0 OUT DFU_DNLOAD(1) wLen=0x0040 -> #50 0 OK 64/64 B 68 us");
    r.assert_flat("drain #53 177810979 1:005:0 OUT DFU_DNLOAD(1) wLen=0x0040 -> #54 0 OK 64/64 B 74 us");
    r.assert_contains("[INFERRED] abort: COMPLETED 2048/2048 B — this window let the whole download through");
    r.assert_contains("3 attempt(s)");
}

#[test]
fn gold_ground_truth_patch_leak_reads_and_clrstatus_are_reproduced() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "report", "--device", "1:005"]);
    assert_eq!(r.code, 0);
    // Two SET_FEATURE(EP0) requests that differ ONLY in wLength: SPRAY's stall
    // primitive (wLength 0) and PATCH's 48-byte overflow (wLength 48). Grouping
    // by (bm, b) merges them into one misleading row; the full setup packet keeps
    // them apart, and each carries its own latency.
    r.assert_flat("SET_FEATURE(3) setup=02 03 0000 0080 0000 x1 first #87 elapsed 158 us");
    r.assert_flat(
        "1:005:0 SET_FEATURE(3) setup=02 03 0000 0080 0000 -> 0/0 B -32 EPIPE x1 elapsed 158 us",
    );
    // The two leak reads: wIndex 0x000a, cancelled at 1191 us and 1250 us.
    r.assert_contains("lang=0x000a");
    r.assert_contains("1.191 ms");
    r.assert_contains("1.250 ms");
    // DFU_CLRSTATUS with wLength 193: -71 EPROTO after 64 bytes.
    r.assert_flat("DFU_CLRSTATUS(4) setup=21 04 0000 0000 00c1 -> 64/193 B -71 EPROTO");
    r.assert_contains("263 us");
}

#[test]
fn gold_ground_truth_reenumeration_and_serial_length_change_are_visible() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "summary"]);
    assert_eq!(r.code, 0);
    // 1:005 -> 1:006 -> 1:007, with the hub and address 0 in the same capture.
    for addr in ["1:005:0", "1:006:0", "1:007:0", "1:000:0", "1:001:0", "1:001:1"] {
        r.assert_contains(addr);
    }
    // Stock serial-string read 198 B; the pwned device advertises iSerialNumber 6
    // and its string 6 read returns 228 B (the capture cannot show the 30 bytes
    // behind that, because usbmon's text interface prints 32).
    r.assert_contains("idx 4 lang 0x0409 198 B x5 0 OK");
    r.assert_contains("idx 6 lang 0x0409 228 B x3 0 OK");
    r.assert_contains("iSerialNumber 4");
    r.assert_contains("iSerialNumber 6");
}

#[test]
fn gold_boundary_completion_is_named_and_never_paired() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "summary"]);
    r.assert_contains("118 selected (117 with a callback in this file, 1 with none)");
    r.assert_contains("boundary completions selected: 1 of 1 in file");
    r.assert_contains("[BOUNDARY] line 94 unmatched-completion");
}

#[test]
fn strict_flag_turns_the_gold_boundary_warning_into_exit_6() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "summary", "--strict"]);
    assert_eq!(r.code, 6, "a boundary completion is a warning, and --strict must fail on it");
    r.assert_contains("--strict: 1 warning(s)");
}

#[test]
fn device_filter_selects_only_that_device() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "json", "--device", "1:007"]);
    assert_eq!(r.code, 0);
    let v = json_of(&r);
    let transfers = v["transfers"].as_array().expect("transfers array");
    assert_eq!(transfers.len(), 15, "1:007 carries 15 transfers in the gold capture");
    for t in transfers {
        assert_eq!(
            t["device"].as_str().unwrap(),
            "1:007:0",
            "a --device filter that bleeds another device's URBs is a wrong-value generator"
        );
    }
    assert_eq!(v["scope"]["matched_transfers"].as_u64().unwrap(), 15);
    // The whole file is 118, and 1:005 is 33: if these three ever collapse into
    // one number, the filter stopped filtering.
    let all = json_of(&run(&[&p, "json"]));
    assert_eq!(all["transfers"].as_array().unwrap().len(), 118);
    let d5 = json_of(&run(&[&p, "json", "--device", "1:005"]));
    assert_eq!(d5["transfers"].as_array().unwrap().len(), 33);
}

#[test]
fn device_filter_with_no_match_exits_5_and_lists_what_is_present() {
    let p = path_str(&fixture("e0-ident.txt"));
    let r = run(&[&p, "summary", "--device", "1:099"]);
    assert_eq!(r.code, 5);
    r.assert_contains("no transfer matches --device 1:099");
    r.assert_contains("addresses present in this file: 1:005:0");
}

#[test]
fn json_attempts_reproduce_the_pad_verdict() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "json", "--device", "1:005"]);
    let v = json_of(&r);
    assert_eq!(v["schema"].as_u64().unwrap(), 1);
    assert_eq!(v["parse"]["lines"].as_u64().unwrap(), 236);
    assert_eq!(v["parse"]["errors"].as_u64().unwrap(), 0);
    let items = v["attempts"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[2]["pad_verdict"].as_str().unwrap(), "PAD STALL (EPIPE)");
    assert_eq!(items[2]["pad"]["completion"]["status"].as_i64().unwrap(), -32);
    assert_eq!(items[2]["pad"]["completion"]["errno"].as_str().unwrap(), "EPIPE");
    assert_eq!(items[2]["pad"]["completion"]["length"].as_u64().unwrap(), 0);
    assert_eq!(items[2]["pad"]["submit"]["length"].as_u64().unwrap(), 1280);
    assert_eq!(items[2]["pad"]["submit"]["setup"]["wLength"].as_str().unwrap(), "0x0500");
    assert_eq!(items[2]["pad"]["submit"]["request"].as_str().unwrap(), "GET_STATUS(0)");
    assert_eq!(items[2]["abort"]["completion"]["status"].as_i64().unwrap(), -2);
    assert_eq!(items[2]["abort"]["elapsed_us"].as_i64().unwrap(), 117);
    assert_eq!(items[0]["abort"]["elapsed_us"].as_i64().unwrap(), 992);
    assert_eq!(items[1]["abort"]["elapsed_us"].as_i64().unwrap(), 974);
}

// ---------------------------------------------------------------------------
// e0-ident: the real two-URB capture
// ---------------------------------------------------------------------------

#[test]
fn e0_ident_reports_two_short_serial_reads() {
    let p = path_str(&fixture("e0-ident.txt"));
    let r = run(&[&p, "summary", "--expect-sha256", E0_SHA]);
    assert_eq!(r.code, 0);
    r.assert_contains("4 lines, 4 events, 0 structural error(s), 0 warning(s)");
    r.assert_contains("STRING(3) idx=4 lang=0x0409 (en-US)");
    r.assert_contains("req 255   ->   198 B  0 OK  x2");
    r.assert_contains("elapsed 116 us..149 us");
    r.assert_contains("2 short transfer(s) at status 0");
}

#[test]
fn e0_ident_list_shows_the_32_byte_display_cap() {
    let p = path_str(&fixture("e0-ident.txt"));
    let r = run(&[&p, "list"]);
    assert_eq!(r.code, 0);
    r.assert_contains("data 32 of 198 B shown; usbmon's text interface caps display at 32 B");
    r.assert_contains("c6034300 50004900");
}

// ---------------------------------------------------------------------------
// The negative control: an offline command must produce zero URBs
// ---------------------------------------------------------------------------

#[test]
fn empty_capture_exits_5_with_the_negative_control_statement() {
    let p = path_str(&fixture("neg-selftest.txt"));
    let r = run(&[&p, "summary"]);
    assert_eq!(r.code, 5, "zero URBs must never look like success");
    r.assert_contains("URB count: 0");
    r.assert_contains("negative control");
    r.assert_contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

// ---------------------------------------------------------------------------
// Doctored fixtures: every rule must be shown to fail
// ---------------------------------------------------------------------------

/// The e0 capture with one field changed. Returns the doctored file path.
fn doctor_e0(name: &str, f: impl Fn(&str) -> String) -> PathBuf {
    let good = real("e0-ident.txt");
    let bad = f(&good);
    assert_ne!(good, bad, "the doctor produced an identical file, so the control proves nothing");
    tmp(name, bad.as_bytes())
}

#[test]
fn doctored_byte_count_is_rejected_loudly() {
    // 198 -> 300, which is more than the 255 the submit asked for: impossible.
    let p = doctor_e0("doctored-count.txt", |s| {
        s.replace("0 198 =", "0 300 =").replace("0 300 = c6034300", "0 300 = c6034300")
    });
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4, "a wrong byte count must be exit 4\n{}", r.out);
    r.assert_contains("transferred-exceeds-requested");
    r.assert_contains("REFUSING to summarise");
    // And the real file must still pass — the negative control did not break the parser.
    let ok = run(&[&path_str(&fixture("e0-ident.txt")), "summary"]);
    assert_eq!(ok.code, 0);
}

#[test]
fn doctored_data_beyond_the_kernel_cap_is_rejected() {
    // 48 printed bytes: usbmon's DATA_MAX is 32, so this line cannot exist.
    let p = doctor_e0("doctored-data.txt", |s| {
        s.replace(
            "56003a00\n",
            "56003a00 00000000 00000000 00000000\n",
        )
    });
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("data-too-large");
}

#[test]
fn doctored_data_longer_than_declared_length_is_rejected() {
    let p = doctor_e0("doctored-data-len.txt", |s| s.replace("0 198 =", "0 4 ="));
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("data-exceeds-length");
}

#[test]
fn truncated_line_is_rejected() {
    let p = doctor_e0("doctored-truncated.txt", |s| {
        // Drop the length field but keep the line break.
        s.replace("00ff 255 <\n", "00ff\n")
    });
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("truncated-line");
}

#[test]
fn unmatched_callback_is_detected_never_absorbed() {
    // Retag the last completion only: the first URB still pairs, so the file is
    // otherwise valid and the single boundary is the thing under test.
    let p = doctor_e0("doctored-unmatched.txt", |s| {
        s.replace("ffff888a0e7f4480 23337198", "deadbeefdeadbeef 23337198")
    });
    let r = run(&[&path_str(&p), "summary"]);
    // Default exit 0: a submit-before-capture is indistinguishable from this
    // doctoring, and calling every real capture an error is worse than saying so.
    assert_eq!(r.code, 0, "{}", r.out);
    r.assert_contains("boundary completions selected: 1 of 1 in file");
    r.assert_contains("[BOUNDARY] line 4 unmatched-completion");
    r.assert_contains("1 with a callback in this file, 1 with none");
    // ...but it is counted, and --strict is a hard failure.
    let strict = run(&[&path_str(&p), "summary", "--strict"]);
    assert_eq!(strict.code, 6);
}

#[test]
fn callback_before_its_submit_leaves_zero_paired_transfers() {
    // The hostile case: the file contains S and C lines, but every C comes
    // before its S and no tag ever gets a submit. Nothing may pair silently.
    let p = doctor_e0("doctored-reordered.txt", |s| {
        let lines: Vec<&str> = s.lines().collect();
        let retag = |l: &str, tag: &str| format!("{tag} {}", &l[l.find(' ').unwrap() + 1..]);
        format!(
            "{}\n{}\n{}\n{}\n",
            retag(lines[1], "feed000000000001"),
            retag(lines[0], "feed000000000002"),
            retag(lines[3], "feed000000000003"),
            retag(lines[2], "feed000000000004")
        )
    });
    let r = run(&[&path_str(&p), "summary"]);
    r.assert_contains("0 with a callback in this file, 2 with none");
    r.assert_contains("boundary completions selected: 2 of 2 in file");
    let strict = run(&[&path_str(&p), "summary", "--strict"]);
    assert_eq!(strict.code, 6);
}

#[test]
fn duplicate_submit_while_open_is_rejected() {
    let p = doctor_e0("doctored-duplicate.txt", |s| {
        // Insert a second submit for a tag that is already outstanding.
        let lines: Vec<&str> = s.lines().collect();
        format!("{}\n{}\n{}\n{}\n{}\n", lines[0], lines[1], lines[0], lines[2], lines[3])
    });
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("duplicate-submit");
}

#[test]
fn callback_on_the_wrong_device_is_rejected() {
    let p = doctor_e0("doctored-wrong-dev.txt", |s| s.replace("C Ci:1:005:0 0 198", "C Ci:1:006:0 0 198"));
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("completion-attrs-mismatch");
}

#[test]
fn binary_garbage_is_rejected_without_panicking() {
    let mut bytes = Vec::new();
    for i in 0..2048u32 {
        bytes.push((i % 251) as u8);
    }
    let p = tmp("garbage.bin", &bytes);
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4, "garbage must not look like a clean empty capture\n{}", r.out);
    assert!(r.code != 101, "a panic is not a rejection");
}

#[test]
fn huge_line_is_rejected_with_a_bounded_read() {
    let mut text = String::from("ffff888a0e7f4480 23337012 C Ci:1:005:0 0 0 ");
    text.push_str(&"a".repeat(3 << 20));
    let p = tmp("huge-line.txt", text.as_bytes());
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("line-too-long");
}

#[test]
fn backwards_timestamps_are_reported_and_never_silently_corrected() {
    let p = doctor_e0("doctored-backwards.txt", |s| {
        s.replace("23336863 S", "23337012 S").replace("23337012 C", "23336000 C")
    });
    let r = run(&[&path_str(&p), "summary"]);
    r.assert_contains("timestamp-backwards");
    r.assert_contains("-1.012 ms");
    let strict = run(&[&path_str(&p), "summary", "--strict"]);
    assert_eq!(strict.code, 6);
}

#[test]
fn iso_and_t_node_lines_are_rejected_with_a_reason() {
    let p = tmp(
        "iso.txt",
        b"ffff888a0e7f4480 100 C Zi:1:005:1 0:0:0 0\n",
    );
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("iso-unsupported");
    let p = tmp("tnode.txt", b"ffff888a0e7f4480 100 C Ci:005:0 0 0\n");
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("t-node-format");
}

#[test]
fn empty_line_inside_a_capture_is_rejected() {
    let p = doctor_e0("doctored-blank.txt", |s| s.replace("\n\n", "\n").replacen("\n", "\n\n", 1));
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("empty-line");
}

#[test]
fn force_prints_the_analysis_but_still_fails() {
    let p = doctor_e0("doctored-force.txt", |s| s.replace("0 198 =", "0 300 ="));
    let r = run(&[&path_str(&p), "summary", "--force"]);
    assert_eq!(r.code, 4, "--force changes what is printed, never the verdict");
    r.assert_contains("transferred-exceeds-requested");
    r.assert_contains("by status");
}

// ---------------------------------------------------------------------------
// Gates, usage, and the tool's own contract
// ---------------------------------------------------------------------------

#[test]
fn sha_pin_mismatch_is_exit_7() {
    let p = path_str(&fixture("e0-ident.txt"));
    let r = run(&[&p, "summary", "--expect-sha256", "deadbeef"]);
    assert_eq!(r.code, 7);
    r.assert_contains("--expect-sha256 mismatch");
    r.assert_not_contains("by request");
}

#[test]
fn missing_file_is_exit_3_and_usage_error_is_exit_2() {
    let r = run(&["/nonexistent/definitely-not-here.txt", "summary"]);
    assert_eq!(r.code, 3);
    assert!(r.err.contains("cannot read"), "stderr: {}", r.err);
    let r = run(&["--bogus-flag"]);
    assert_eq!(r.code, 2);
    let r = run(&[]);
    assert_eq!(r.code, 2);
}

#[test]
fn help_and_version_are_available() {
    let r = run(&["--help"]);
    assert_eq!(r.code, 0);
    r.assert_contains("exit codes:");
    r.assert_contains("DATA_MAX");
    let r = run(&["--version"]);
    assert_eq!(r.code, 0);
    r.assert_contains("usbmon 0.1.0");
}

#[test]
fn synthetic_fixture_is_a_clean_positive_control() {
    let p = path_str(&manifest().join("tests/fixtures/synthetic-setup-tick.txt"));
    let r = run(&[&p, "report"]);
    assert_eq!(r.code, 0, "synthetic fixture must be clean\n{}", r.out);
    r.assert_contains("0 structural error(s), 0 warning(s)");
    r.assert_contains("PAD STALL (EPIPE)");
    r.assert_contains("884 us");
}

#[test]
fn binary_links_no_usb_library() {
    // This tool must never be able to open the device. A dynamic dependency on
    // libusb would be the first step there, so assert there is none.
    let out = Command::new("ldd").arg(bin()).output();
    match out {
        Ok(o) => {
            let deps = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            assert!(
                !deps.contains("libusb") && !deps.contains("libusb-1.0"),
                "usbmon must not link libusb:\n{deps}"
            );
        }
        Err(_) => eprintln!("ldd unavailable; skipped the dynamic-dependency check"),
    }
}

/// House rule: the ground-truth predicates must be falsifiable. Doctor the gold
/// capture's pad status and show the same assertions the tests above rely on now
/// fail — if this test ever passes on the doctored file, the predicate is blind.
#[test]
fn gold_predicates_are_falsified_by_a_doctored_pad_status() {
    let good = real("e4-gaster-1.txt");
    let doctored = good.replace(
        "ffff888a38e0c240 177812174 C Co:1:005:0 -32 0",
        "ffff888a38e0c240 177812174 C Co:1:005:0 -110 0",
    );
    assert_ne!(good, doctored, "the pad line must have been found and changed");
    let p = tmp("doctored-gold-pad.txt", doctored.as_bytes());
    let r = run(&[&path_str(&p), "attempts", "--device", "1:005"]);
    r.assert_contains("PAD TIMEOUT (ETIMEDOUT)");
    r.assert_not_flat("PAD STALL (EPIPE)");
    // ...and the real file still shows the STALL, so the difference is the
    // doctoring and not a parser mood.
    let real_run = run(&[&path_str(&fixture("e4-gaster-1.txt")), "attempts", "--device", "1:005"]);
    real_run.assert_contains("PAD STALL (EPIPE)");
}

// ---------------------------------------------------------------------------
// Reviewer findings (B1/M1/m1..m5) — every one has a negative control
// ---------------------------------------------------------------------------

#[test]
fn request_filter_that_matches_nothing_exits_5() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "summary", "--request", "SET_ADDRESS"]);
    assert_eq!(r.code, 5, "a filter that selects nothing must not read as success\n{}", r.out);
    r.assert_contains("selected 0 of 118 transfer(s)");
    let j = json_of(&run(&[&p, "json", "--request", "SET_ADDRESS"]));
    assert_eq!(j["scope"]["matched_transfers"].as_u64().unwrap(), 0);
    assert_eq!(j["exit_code"].as_i64().unwrap(), 5);
    // and the same filter that DOES match still exits 0 (positive control)
    let ok = run(&[&p, "summary", "--request", "SET_ADDRESS"]);
    assert_eq!(ok.code, 5);
    let ok = run(&[&p, "summary", "--request", "DFU_DNLOAD"]);
    assert_eq!(ok.code, 0);
}

#[test]
fn status_filter_that_matches_nothing_exits_5() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "summary", "--status", "ETIMEDOUT"]);
    assert_eq!(r.code, 5, "-110 occurs nowhere in this file\n{}", r.out);
    r.assert_contains("selected 0 of 118 transfer(s)");
    assert_eq!(run(&[&p, "summary", "--status", "STALL"]).code, 0);
}

#[test]
fn list_with_a_no_match_request_filter_prints_no_boundary_rows() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "list", "--request", "999"]);
    assert_eq!(r.code, 5);
    // the list body must claim no rows and no boundary rows; the file-level
    // problems block still reports the boundary completion, which is right.
    r.assert_contains("0 transfer(s) selected (0 shown), 0 boundary completion(s) selected (0 shown)");
}

#[test]
fn spray_stall_and_patch_overflow_stay_separate_end_to_end() {
    // The two SET_FEATURE(EP0) requests differ only in wLength. A summary that
    // groups by (bm, b) reports one merged count; this must be two rows.
    let text = "\
ffff888a00000001 1000000 S Co:1:005:0 s 02 03 0000 0080 0000 0\n\
ffff888a00000001 1000156 C Co:1:005:0 -32 0\n\
ffff888a00000002 2000000 S Co:1:005:0 s 02 03 0000 0080 0030 48 = 00000000\n\
ffff888a00000002 2000164 C Co:1:005:0 -32 0\n";
    let p = tmp("spray-vs-patch.txt", text.as_bytes());
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 0, "{}", r.out);
    r.assert_flat("SET_FEATURE(3) setup=02 03 0000 0080 0000 x1 first #1 elapsed 156 us");
    r.assert_flat("SET_FEATURE(3) setup=02 03 0000 0080 0030 x1 first #3 elapsed 164 us");
    r.assert_flat("1:005:0 SET_FEATURE(3) setup=02 03 0000 0080 0000 -> 0/0 B -32 EPIPE x1 elapsed 156 us");
    r.assert_flat("1:005:0 SET_FEATURE(3) setup=02 03 0000 0080 0030 -> 0/48 B -32 EPIPE x1 elapsed 164 us");
    let j = json_of(&run(&[&path_str(&p), "json"]));
    assert_eq!(j["transfers"].as_array().unwrap().len(), 2);
    // list shows both rows, with their distinct wLength
    let l = run(&[&path_str(&p), "list"]);
    l.assert_flat("wLen=0x0000");
    l.assert_flat("wLen=0x0030");
}

#[test]
fn underprinted_data_is_flagged_without_the_false_cap_explanation() {
    // mon_text.c prints exactly min(length, 32) bytes, so 2 bytes for a declared
    // length of 4 cannot be the 32-byte display cap.
    let text = "\
ffff888a0aa5dcc0 177565160 S Ci:1:005:0 s 80 06 0304 0409 0004 4 <\n\
ffff888a0aa5dcc0 177565700 C Ci:1:005:0 0 4 = 1201\n";
    let p = tmp("underprint.txt", text.as_bytes());
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 0, "{}", r.out);
    r.assert_contains("data-underprinted");
    r.assert_contains("the 32-byte display cap cannot explain this");
    let strict = run(&[&path_str(&p), "summary", "--strict"]);
    assert_eq!(strict.code, 6, "an unexplained short data section is a warning");
    // the real e0 fixture must NOT carry this warning (it is genuinely capped at 32)
    let e0 = run(&[&path_str(&fixture("e0-ident.txt")), "summary"]);
    assert_eq!(e0.code, 0);
    e0.assert_not_contains("data-underprinted");
}

#[test]
fn uppercase_hex_is_reported_as_rewritten_input() {
    let p = doctor_e0("doctored-upper.txt", |s| s.replace("ffff888a0e7f4480", "FFFF888A0E7F4480"));
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 0, "case does not change meaning, so this is a warning\n{}", r.out);
    r.assert_contains("uppercase-hex");
    assert_eq!(run(&[&path_str(&p), "summary", "--strict"]).code, 6);
    let clean = run(&[&path_str(&fixture("e0-ident.txt")), "summary"]);
    clean.assert_not_contains("uppercase-hex");
}

#[test]
fn force_with_structural_errors_still_exits_4_and_never_5() {
    let p = tmp("iso-force.txt", b"ffff888a02ddb0c0 178055064 C Zi:1:005:1 0:0:0 1:0:0 0\n");
    let r = run(&[&path_str(&p), "summary", "--force"]);
    assert_eq!(r.code, 4, "--force changes what is printed, never the verdict\n{}", r.out);
    r.assert_not_contains("URB count: 0");
    assert_eq!(run(&[&path_str(&p), "summary"]).code, 4);
}

#[test]
fn json_sha_mismatch_is_still_json() {
    let p = path_str(&fixture("e0-ident.txt"));
    let r = run(&[&p, "json", "--expect-sha256", "deadbeef"]);
    assert_eq!(r.code, 7);
    let v = json_of(&r);
    assert_eq!(v["error"].as_str().unwrap(), "expect-sha256-mismatch");
    assert_eq!(v["exit_code"].as_i64().unwrap(), 7);
}

#[test]
fn endpoint_is_decimal_unless_prefixed() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    // ep 10 does not exist; before this fix `--endpoint 10` meant 0x10 = 16.
    assert_eq!(run(&[&p, "summary", "--endpoint", "10"]).code, 5);
    // 0x01 selects the root hub's interrupt endpoint (2 transfers).
    let r = run(&[&p, "json", "--endpoint", "0x01"]);
    assert_eq!(r.code, 0);
    let j = json_of(&r);
    assert_eq!(j["transfers"].as_array().unwrap().len(), 2);
}

#[test]
fn extreme_gaps_ms_does_not_wrap_into_passing_everything() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    let r = run(&[&p, "list", "--gaps-ms", "18446744073709551615"]);
    assert_eq!(r.code, 0);
    r.assert_contains("0 transfer(s) at least 18446744073709551615 ms");
    // and a real threshold still finds the real gaps
    let real = run(&[&p, "list", "--gaps-ms", "100"]);
    real.assert_contains("7 transfer(s) at least 100 ms");
}

#[test]
fn garbage_request_argument_is_a_usage_error_not_a_silent_rewrite() {
    let p = path_str(&fixture("e4-gaster-1.txt"));
    assert_eq!(run(&[&p, "summary", "--request", "-1"]).code, 2);
    assert_eq!(run(&[&p, "summary", "--request", "6 "]).code, 2);
    assert_eq!(run(&[&p, "summary", "--request", ""]).code, 2);
    // an explicit hex code is still accepted and means the same as decimal 4
    assert_eq!(run(&[&p, "json", "--request", "0x04"]).code, 0);
    assert_eq!(run(&[&p, "json", "--request", "4"]).code, 0);
}

#[test]
fn many_problems_are_counted_even_when_the_list_is_capped() {
    let mut text = String::new();
    for _ in 0..2500 {
        text.push_str("not a usbmon line\n");
    }
    let p = tmp("many-problems.txt", text.as_bytes());
    let r = run(&[&path_str(&p), "summary"]);
    assert_eq!(r.code, 4);
    r.assert_contains("2500 structural error(s)");
    r.assert_contains("problem(s) were counted but not listed");
    let j = json_of(&run(&[&path_str(&p), "json"]));
    assert_eq!(j["parse"]["errors"].as_u64().unwrap(), 2500);
    assert_eq!(j["problems_not_listed"].as_u64().unwrap(), 1500);
}

#[test]
fn an_unterminated_line_stops_reading_instead_of_hanging() {
    // 70 MiB with no newline: bounded work, exit 4, no hang.
    let mut bytes = vec![b'a'; 70 << 20];
    bytes[0] = b'f';
    let p = tmp("unterminated.txt", &bytes);
    let start = std::time::Instant::now();
    let r = run(&[&path_str(&p), "summary"]);
    assert!(start.elapsed().as_secs() < 30, "must not drain an unbounded stream");
    assert_eq!(r.code, 4);
    r.assert_contains("line-unterminated");
}

// ---------------------------------------------------------------------------
// our-run1: the project's own winning run (the Lead's acceptance table)
// ---------------------------------------------------------------------------

const OUR_RUN: &str = "our-run1.txt";

#[test]
fn our_run_wire_facts_match_the_winning_run() {
    let p = path_str(&fixture(OUR_RUN));
    let r = run(&[&p, "attempts", "--device", "1:008"]);
    assert_eq!(r.code, 0, "{}", r.out);
    r.assert_contains("[MEASURED] 3 attempt(s)");
    // attempt 3: aborted DNLOAD then the pad STALL, on the wire.
    r.assert_flat("abort #57 487141154 1:008:0 OUT DFU_DNLOAD(1) wLen=0x0800 -> #58 -2 ENOENT 0/2048 B 70 us");
    r.assert_flat("pad #59 487141247 1:008:0 OUT GET_STATUS(0) wLen=0x0500 -> #60 -32 EPIPE 0/1280 B 736 us");
    r.assert_contains("[INFERRED] pad  : PAD STALL (EPIPE)");
    // the two windows that completed the whole download, and their drains
    r.assert_flat("#49 487138994 1:008:0 OUT DFU_DNLOAD(1) wLen=0x0800 -> #50 0 OK 2048/2048 B 935 us");
    r.assert_flat("#53 487140071 1:008:0 OUT DFU_DNLOAD(1) wLen=0x0800 -> #54 0 OK 2048/2048 B 974 us");
    // the device re-enumerates twice in this run
    let s = run(&[&p, "summary"]);
    for addr in ["1:008:0", "1:009:0", "1:010:0"] {
        s.assert_contains(addr);
    }
    // the PWND marker: a 228-byte string read while the stock length is 198
    s.assert_contains("idx 4 lang 0x0409 198 B x9 0 OK");
    s.assert_contains("idx 6 lang 0x0409 228 B x6 0 OK");
    s.assert_contains("iSerialNumber 6");
}

#[test]
fn our_run_host_log_join_reproduces_the_abort_windows() {
    let p = path_str(&fixture(OUR_RUN));
    let r = run(&[&p, "attempts", "--device", "1:008"]);
    assert_eq!(r.code, 0);
    // auto-discovered sibling trace
    r.assert_contains("host log   : ");
    r.assert_contains("our-run1.jsonl");
    r.assert_contains("[MEASURED host log] abort windows in order: 4 ms, 5 ms, 0 ms");
    r.assert_flat("[MEASURED host log] abort: stage=SETUP label=setup_abort_dnload status=OK transferred=2048/2048 xfer_micros=946 abort_after_ms=4");
    r.assert_flat("[MEASURED host log] abort: stage=SETUP label=setup_abort_dnload status=CANCELLED transferred=0/2048 xfer_micros=87 abort_after_ms=0");
    r.assert_contains("xfer_micros=745");
    r.assert_contains("[MEASURED wire]      abort elapsed in order: 935 us, 974 us, 70 us");
    // --no-host-log must produce wire-only output and say so
    let nohost = run(&[&p, "attempts", "--device", "1:008", "--no-host-log"]);
    assert_eq!(nohost.code, 0);
    nohost.assert_contains("host log   : disabled by --no-host-log");
    nohost.assert_not_contains("abort windows in order");
}

#[test]
fn our_run_attributes_spray_stall_and_patch_overflow_from_the_host_log() {
    let p = path_str(&fixture(OUR_RUN));
    let r = run(&[&p, "summary"]);
    assert_eq!(r.code, 0);
    r.assert_flat("1:008:0 SET_FEATURE(3) setup=02 03 0000 0080 0000 -> 0/0 B -32 EPIPE [host SPRAY/spray_request_stall] x1 elapsed 156 us");
    r.assert_flat("1:009:0 SET_FEATURE(3) setup=02 03 0000 0080 0030 -> 0/48 B -32 EPIPE [host PATCH/patch_overflow_callback] x1 elapsed 164 us");
    // the two requests must never share a row
    r.assert_not_flat("SET_FEATURE(3) setup=02 03 0000 0080 0000 -> 0/0 B -32 EPIPE [host SPRAY/spray_request_stall] x2");
}

#[test]
fn the_two_runs_have_the_same_shape_but_different_latencies() {
    // If the tool ever reported the same latency for both captures, it would be
    // reading the wrong file or hardcoding. This is that control.
    let ours = run(&[&path_str(&fixture(OUR_RUN)), "attempts", "--device", "1:008"]);
    let reference = run(&[&path_str(&fixture("e4-gaster-1.txt")), "attempts", "--device", "1:005"]);
    ours.assert_contains("736 us");
    reference.assert_contains("889 us");
    ours.assert_not_contains("889 us");
    reference.assert_not_contains("736 us");
    // and the abort latencies differ too: our wire 70 us, the reference's 117 us
    ours.assert_contains("0/2048 B  70 us");
    reference.assert_contains("0/2048 B  117 us");
}

/// The marker index MOVES across re-enumerations on this phone (the Lead measured
/// index 4 -> 228 B on one enumeration and index 6 -> 228 B on another). So the
/// tool must derive the index from the file, and must not call a 198-byte string
/// marker-length in either file.
#[test]
fn marker_index_is_derived_from_the_file_not_hardcoded() {
    let cases = [("synthetic-marker-idx4.txt", 4u8), ("synthetic-marker-idx6.txt", 6u8)];
    for (file, idx) in cases {
        let p = path_str(&manifest().join("tests/fixtures").join(file));
        let r = run(&[&p, "summary"]);
        assert_eq!(r.code, 0, "{file}: {}", r.out);
        // the marker-length read, at whatever index THIS file uses
        r.assert_contains(&format!("1:006:0: 228 B at idx {idx}"));
        r.assert_contains("= +30 B");
        // the negative control: the 198 B read is not marker-length
        r.assert_contains("1:005:0: 198 B at idx");
        r.assert_contains("no marker-length string here");
        // the declared index is read off the device descriptor, per device
        r.assert_contains(&format!("declared iSerialNumber={idx}"));
        r.assert_contains(&format!("(from device descriptor at #1)"));
        r.assert_contains(&format!("read at declared idx {idx}"));
        // the decoded device descriptor carries the declared index
        r.assert_contains(&format!("iSerialNumber {idx}"));
        // json carries the same, keyed on the declared index
        let j = json_of(&run(&[&p, "json"]));
        let serial = j["serial_descriptor"].as_array().unwrap();
        assert!(serial.iter().any(|d| d["declared_iSerialNumber"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_u64() == Some(idx as u64))));
    }
}

/// A host trace whose xfer order cannot line up with the wire must fail the
/// join, and NO host value may reach any attempt when it fails.
#[test]
fn a_failed_host_join_attaches_nothing() {
    let dir = tmp_dir();
    let mut trace = String::new();
    trace.push_str("{\"seq\":1,\"stage\":\"SETUP\",\"kind\":\"xfer\",\"label\":\"setup_abort_dnload\",\"status\":\"OK\",\"bm_request_type\":33,\"b_request\":1,\"w_value\":0,\"w_index\":0,\"w_length\":2048,\"transferred\":2048,\"xfer_micros\":946,\"abort_after_ms\":4}\n");
    trace.push_str("{\"seq\":2,\"stage\":\"SETUP\",\"kind\":\"xfer\",\"label\":\"never_on_the_wire\",\"status\":\"OK\",\"bm_request_type\":66,\"b_request\":66,\"w_value\":0,\"w_index\":183,\"w_length\":1911,\"transferred\":0,\"xfer_micros\":1}\n");
    let trace_path = dir.join("mismatched.jsonl");
    std::fs::write(&trace_path, trace).unwrap();
    let p = path_str(&fixture(OUR_RUN));
    let r = run(&[
        &p,
        "attempts",
        "--device",
        "1:008",
        "--host-log",
        &path_str(&trace_path),
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    r.assert_contains("host log join FAILED");
    r.assert_contains("no host value is attached");
    // no window, no per-transfer host row, no 946 anywhere
    r.assert_not_contains("abort windows in order");
    r.assert_not_contains("[MEASURED host log] abort:");
    r.assert_not_contains("xfer_micros=946");
    let j = json_of(&run(&[
        &p,
        "json",
        "--device",
        "1:008",
        "--host-log",
        &path_str(&trace_path),
    ]));
    assert_eq!(j["attempts"]["host_log"]["join_ok"].as_bool().unwrap(), false);
    for t in j["transfers"].as_array().unwrap() {
        assert!(t["host_log"].is_null(), "a failed join must attach nothing");
    }
}

/// A permuted host trace (identical setup packets swapped) must be caught by the
/// host/wire consistency check: a CANCELLED host record cannot sit next to a
/// wire transfer that completed 2048/2048.
#[test]
fn a_permuted_host_trace_is_reported_as_a_disagreement() {
    let good = std::fs::read_to_string(fixture(OUR_RUN)).unwrap();
    assert!(!good.is_empty());
    let trace = std::fs::read_to_string(repo_root().join("a9pwn-traces/linux/our-run1.jsonl")).unwrap();
    let lines: Vec<&str> = trace.lines().collect();
    // swap the first and third setup_abort_dnload records
    let idxs: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("setup_abort_dnload"))
        .map(|(i, _)| i)
        .collect();
    assert!(idxs.len() >= 3, "expected three abort DNLOAD records");
    let mut permuted: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    permuted.swap(idxs[0], idxs[2]);
    let p = tmp_dir().join("permuted.jsonl");
    std::fs::write(&p, permuted.join("\n")).unwrap();
    let r = run(&[
        &path_str(&fixture(OUR_RUN)),
        "report",
        "--host-log",
        &path_str(&p),
    ]);
    assert_eq!(r.code, 0, "{}", r.out);
    r.assert_contains("host/wire CONTRADICTION");
    r.assert_contains("[SUSPECT host log] abort windows in order");
    // and --strict refuses to call that clean
    let strict = run(&[
        &path_str(&fixture(OUR_RUN)),
        "summary",
        "--host-log",
        &path_str(&p),
        "--strict",
    ]);
    assert_eq!(strict.code, 6);
}

#[test]
fn no_host_log_says_disabled_not_missing() {
    let p = path_str(&fixture(OUR_RUN));
    let r = run(&[&p, "summary", "--no-host-log"]);
    r.assert_contains("host log   : disabled by --no-host-log");
}
