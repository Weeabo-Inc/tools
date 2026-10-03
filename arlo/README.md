# tools/arlo — the two tools that make this project's two recurring mistakes mechanical

**Written:** 2026-10-03, by `tooling-engineer`, task `task-11`.
**Scope:** this directory. Nothing here touches the phone, and nothing here edits `a9pwn/`.

The project's documented, repeated injury is two failures:

1. **A plausible-looking wrong value** (HANDOFF §9.5 — "never present an inference as a
   measurement"; seven occurrences and counting).
2. **A report measured before a final edit** (HANDOFF §9.7 — this already cost the project a
   round trip on `verdict.rs`).

These tools exist so that both are caught by a machine instead of by discipline.

| Tool | What it is | What it kills |
|---|---|---|
| `a9pwn-gate.ps1` | build + test gate that pins the run to exact bytes | a stale report, and "the tests passed" when the bytes moved mid-run |
| `traceview/` | Rust crate that reads a trace file and reports what is in it | the plausible-looking wrong value: it counts the file, and says which fields were absent instead of inventing them |

---

## 1. `a9pwn-gate.ps1` — build, test, and prove *which bytes* were tested

### Run it

```powershell
# from anywhere; the wrapper exists because this host's execution policy is
# Restricted, so a bare .ps1 cannot be run
E:\Reverseing\Arlo\tools\arlo\a9pwn-gate.cmd

# prove the gate itself (three bundled micro-crates; does not touch a9pwn)
E:\Reverseing\Arlo\tools\arlo\a9pwn-gate.cmd -Selftest

# also dump the machine-readable result to stdout
E:\Reverseing\Arlo\tools\arlo\a9pwn-gate.cmd -EmitJson

# gate a different crate
E:\Reverseing\Arlo\tools\arlo\a9pwn-gate.cmd -Repo E:\Reverseing\Arlo\a9pwn

# exclude a known-transient path from the change check (recorded in the result)
E:\Reverseing\Arlo\tools\arlo\a9pwn-gate.cmd -Ignore "src\.*.tmpdir\*"
```

Without the wrapper (or from a session where scripts are allowed):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools\arlo\a9pwn-gate.ps1
```

**Exit codes:** `0` PASS · `1` FAIL · `2` could not run (bad repo, no cargo, unwritable output).

### What it does, exactly

1. Hashes **every file under `a9pwn/src`** (recursively), plus the context files that decide what
   the tests *mean*: `Cargo.toml`, `Cargo.lock`, `payloads/**`, `build.rs`. Emits a per-file
   SHA-256 manifest and one `tree_sha256` over the sorted manifest.
2. Runs **`cargo build --release --offline`**, then **`cargo test --release --offline`**. Nothing
   else. It never executes `a9pwn.exe`.
3. Sums the test totals across **every** `test result:` line — a9pwn emits one per target
   (`unittests src\lib.rs`, `unittests src\main.rs`, `Doc-tests a9pwn`: three in the tree as of
   2026-10-03, 169 tests). Reading only the last one is how a failing integration test gets
   reported as a pass.
4. Re-hashes the same set and **fails if anything changed**. This is the property the gate exists
   for: `source_stable: false` means the verdict describes no particular bytes.
5. Writes `out\a9pwn-gate.json` (schema below) and keeps the raw cargo logs in `out\logs\<run>\`.

### What PASS *proves*

> These exact bytes — named by `source_manifest.tree_sha256_before` and by every per-file hash —
> built successfully, and their test binaries reported `N passed, 0 failed`, with the source
> unchanged from before the build to after the test.

### What PASS does **not** prove

- Nothing about the device, the driver, or whether checkm8 works. It is an offline gate.
- Nothing about whether the tests are *good*. It reports totals, not coverage.
- Nothing about `a9drv`, `a9ctl` or any other crate. It gates one crate, chosen by `-Repo`.
- If `source_stable: true`, the bytes were equal at both ends of the window. A file rewritten and
  reverted to **identical** bytes inside the window is not detectable by hashing; it is reported
  separately as `rewritten-identical` (a note, not a failure — identical bytes are identical
  bytes). An mtime-only change surfaces there too, so it is visible rather than silent.

### The JSON result (`out\a9pwn-gate.json`)

```jsonc
{
  "tool": "a9pwn-gate", "tool_version": "1.0.0", "schema": 1,
  "ok": false, "result": "FAIL",
  "failure_reasons": ["source_changed_during_run: src\\verdict.rs [modified] ..."],
  "repo":    { "path": "...", "manifest_root": "...\\a9pwn\\src" },
  "git":     { "available": true, "head": "64eb4e1", "branch": "main", "dirty_paths": [...] },
  "timing":  { "manifest_before": "...", "manifest_after": "...", "build_seconds": 12.3, ... },
  "commands":[ { "name": "build", "exit_code": 0, "errors": [], "log": "..." },
               { "name": "test",  "exit_code": 0, "errors": [], "log": "..." } ],
  "tests":   { "passed": 169, "failed": 0, "ignored": 0, "result_lines": 3,
               "targets": [...], "failed_names": [] },
  "source_manifest":  { "file_count": 9, "tree_sha256_before": "...", "tree_sha256_after": "...",
                        "files": [ { "path": "src\\verdict.rs", "sha256": "...", ... } ] },
  "context_manifest": { "files": [ { "path": "Cargo.lock", ... }, ... ] },
  "source_stable": true,
  "changed_during_run": [],
  "ignored_globs": [],
  "artefacts": { "a9pwn_exe": {...}, "newest_test_exe": {...} },
  "meaning": "PASS means these exact bytes built, ... It says nothing about the device."
}
```

Use `source_manifest.tree_sha256_before` as the thing you quote in a report. One hash, and anyone
can re-derive the whole tree from the manifest in the same file.

### Failure reasons it can emit

| reason | meaning |
|---|---|
| `build_failed` | `cargo build` exited non-zero |
| `test_command_failed` | `cargo test` exited non-zero |
| `tests_failed` | a `test result:` line reported failures (names listed) |
| `no_test_result_lines` | cargo produced no verdict at all — a compile failure looks exactly like this, hence a separate reason |
| `source_changed_during_run` | something under `src/` changed mid-run. **This is the point of the gate.** |
| `context_changed_during_run` | `Cargo.toml`/`Cargo.lock`/`payloads/**`/`build.rs` changed mid-run. Cargo may have rewritten `Cargo.lock` itself; either way the run is not pinned |
| `build_no_exit_code` / `test_no_exit_code` | the exit code could not be captured — treated as failure, never as success |
| `manifest_unreadable` | a guarded file could not be hashed |

### Safety, and what it never does

- **Read-only with respect to the working tree.** No `git checkout`, `git reset`, `git clean`, no
  deletion, no formatting. `git` is used for `rev-parse` and `status --porcelain` only, and
  `a9pwn` is the only part of this workspace that is even a repository.
- It does not run `a9pwn` at all. No `run`, `reset`, `ident`, `--stage`, `selftest`, `plan`. The
  phone belongs to the Lead (HANDOFF §9.1).
- It writes only under `tools\arlo\` (result JSON + logs), plus whatever cargo writes under
  `a9pwn\target\`. It refuses to write anywhere on `D:` (HANDOFF §0.2).
- **Concurrent edits make it FAIL, by design.** If another engineer saves a file under `src/`
  while the gate runs, `source_changed_during_run` fires and the run is void. Re-run when the tree
  is quiet. `-Ignore <glob>` is the audited escape hatch; every glob used is recorded in the
  result.

### Known limits

- **No timeout.** `cargo` is run synchronously so its exit code is trustworthy (see the 5.1 note
  below). A hung cargo hangs the gate; press Ctrl-C.
- **A cold `--release` build of a9pwn takes minutes.** The log is written live to
  `out\logs\<run>\build.log`, so `Get-Content -Wait` on it shows progress.
- Concurrent cargo invocations block on cargo's build-directory lock rather than failing. Expect a
  slower run, not a wrong one.
- The gate does not verify that the *test binary* it ran corresponds to the manifest; it records
  the newest `target\release\deps\a9pwn-*.exe` with its hash and whether its mtime falls inside the
  run window. Cargo's own freshness tracking is what actually links them.
- `-Selftest` covers the pass path, the mid-run-change path and the compile-failure path. It does
  not simulate a *test* failure; that path is the plain `tests_failed` sum over `test result:`
  lines.

---

## 2. `traceview` — read a trace and say what is in it

Rust, not a Python script (project rule). Two dependencies, both cached locally so `--offline`
works: `serde_json` (the same parser `a9pwn` writes the JSONL with, so "malformed" means
malformed) and `sha2` (a **third-party** SHA-256, deliberately *not* a9pwn's hand-rolled one — this
tool exists to be an independent check, and PowerShell's `Get-FileHash` is a third implementation).

### Build and run

```powershell
cd E:\Reverseing\Arlo\tools\arlo\traceview
cargo build --release --offline
cargo test  --offline                 # 21 tests

# the binary
.\target\release\traceview.exe E:\Reverseing\a9pwn-traces\run1.jsonl

# or straight from cargo
cargo run --release --offline -- E:\Reverseing\a9pwn-traces\run1.jsonl
```

```
traceview [OPTIONS] <TRACE>

  --json                 print the same measurements as one JSON object
  --expect-sha256 <HEX>  refuse to summarise unless the file hashes to HEX
  --strict               exit 6 on malformed lines / field-order violations / bad seq
  -h, --help   -V, --version
```

**Exit codes:** `0` read (a *failed run* reads fine — read the signals) · `2` usage ·
`3` unreadable · `4` no records parsed · `5` `--expect-sha256` mismatch · `6` `--strict` and
structural problems.

### What it prints

- the file's byte count and **SHA-256** — the summary is pinned to those exact bytes
- dialect (`jsonl`, `legacy-a9ctl`, or both), line/record/malformed counts
- **the PWND token**, first thing after the header, stated as a fact about the *file*
- per-stage transfer counts by status (OK / STALL / TIMEOUT / CANCELLED / NO_DEVICE / ERROR)
- the **SETUP abort-window sweep in order**, compressed exactly (`[4, 5, 0, 1, 2, 3] x 64`), with
  distinct windows, back-to-back repeats, and whether the sweep is **pinned**
- **SETUP pad-request outcomes**: STALL vs TIMEOUT vs ERROR vs OK vs CANCELLED, and the distinct
  pad sizes
- **early cancels**: `CANCELLED` in under 100 µs on a window of 1 ms or more — the `a9ctl` defect
  this project replaced — with the honest denominator (`xfer_micros present on N/M attempts`)
- SPRAY signatures, resets (real vs pipe-cycle), rounds, discovery/open-failure records
- **predicate failures** by code, with the first failure's detail
- a **signals** block: `[ALARM]` items contradict a documented pass condition, `[WARN]` items are
  missing or unusual, `[INFO]` items are positive observations
- every malformed / unrecognised / out-of-contract line, with its line number and an excerpt

Two dialects are read:

- **jsonl** — `a9pwn/INTERFACE.md` §5, one JSON object per line, `seq`/`stage`/`kind`/`t_micros`
  always, byte-stable key order.
- **legacy-a9ctl** — the pre-rewrite C++ text log. The project's regression signature,
  `a9ctl/stage-setup.log` (the 384-timeout failure), is read by a test, so the baseline every new
  trace is compared against is checked against the real artefact and not a stand-in.

### What it proves

- That a given trace file contains a given set of measurements, and **which fields were absent**
  (an absent `xfer_micros` is reported as absent, never as zero).
- That the file's field order matches the frozen contract, or which lines break it.
- That `--expect-sha256` matched, i.e. the summary describes exactly those bytes.

### What it cannot prove

- **Anything the file does not say.** No PWND token in a trace means *the file has no PWND token*,
  never "the device is not pwned". The verdict line from a9pwn is the authority on the device.
- It is not a pcap reader: it reads a9pwn's own trace, and a trace is only as complete as the
  tracer that wrote it. A missing line is indistinguishable from a line that was never written.
- A `legacy-a9ctl` log carries no request fields (`bm`, `b_request`, `w_length` on the abort line)
  and no timestamps. Those are reported absent. It never fills them in from the reference
  implementation — an inferred `w_length` is exactly the plausible-looking wrong value this project
  keeps paying for.
- Exit `0` is not "the run succeeded". Read the signals block.

---

## 3. PowerShell 5.1 notes (read before editing the gate)

This host runs **Windows PowerShell 5.1** (`PSEdition: Desktop`) and `pwsh` is **not installed**,
despite what a "pwsh" label suggests. The execution policy is **Restricted**, which is why the
`.cmd` wrapper exists. Three 5.1 landmines are worth knowing, because each one cost time here and
each one is invisible until it bites:

1. **`@($genericList)` throws `Argument types do not match`.** Wrapping a
   `List[object]` in the array subexpression operator fails on 5.1 (measured). Use `.ToArray()`, or
   plain arrays built with `+=`. Fixing this revealed the next one.
2. **A function returning an EMPTY array delivers `$null`.** PowerShell unrolls the empty array in
   the pipeline, so `$x = f; $x.ToArray()` throws *only in the case where nothing happened* — for
   this gate, that was the PASS path, which is the worst possible place for it. Always
   `$x = @(f)`.
3. **`Start-Process -PassThru` gives a Process whose `ExitCode` is EMPTY** once
   `-RedirectStandardOutput` is used (measured: a child doing `exit 3` reported nothing, before and
   after `WaitForExit`). The gate therefore runs cargo synchronously and reads `$LASTEXITCODE`.
   Treating an unknown exit code as 0 would have turned every cargo failure into a pass.
4. **Non-ASCII in a BOM-less `.ps1` breaks parsing.** 5.1 reads BOM-less UTF-8 as ANSI; the UTF-8
   bytes of an em-dash decode to `U+201D`, which PowerShell treats as a string delimiter, and the
   script dies with a parse error pointing at an unrelated line. Every other `.ps1` in this
   workspace is UTF-8-with-BOM; so is this one. It is **also ASCII-only on purpose**, so that an
   editor which drops the BOM (the `edit` tool here does) cannot break it. Keep it that way.

## 4. One measured run, kept as an example of the discipline (2026-10-03)

| | |
|---|---|
| `a9pwn-gate.cmd` on `a9pwn` | **PASS** — build exit 0 (0.5 s), test exit 0 (13.6 s), **169 passed / 0 failed / 0 ignored across 3 targets** |
| pinned to | `src` tree SHA-256 `7EAB505D4BD84CC63B33FDFF410DD760A3795D7CD652B30CA42C7FA8E37264F6` |
| git at the time | `HEAD 64eb4e1` on `main`, 9 modified paths — a **dirty** tree; this gate pins bytes, not commits |
| bytes re-verified after the run | all 9 files re-hashed, identical — so the PASS describes the current tree, not a stale one |
| `a9pwn.exe` produced | SHA-256 `A799B991…`, mtime inside the run window |
| payload blobs | the gate's hashes match the values published in `a9pwn/INTERFACE.md` §3 exactly |
| `traceview` | `cargo test --offline` exit 0, 21 tests (10 unit + 11 integration) |

This is a **dated measurement of those bytes**, not a standing claim about the project. That
distinction is the whole point: at the time of writing, `HANDOFF.md` §11 still says `a9pwn` "does
not currently compile" — which was true of *other* bytes. Re-run the gate before quoting it.

## 5. Layout

```
tools/arlo/
  README.md                 this file
  a9pwn-gate.ps1            the gate (UTF-8 with BOM, ASCII-only)
  a9pwn-gate.cmd            wrapper: -ExecutionPolicy Bypass for this process only
  out/                      result JSON + raw cargo logs (git-ignored by nature: regenerated)
    a9pwn-gate.json
    logs/gate-<stamp>-<id>/{build,test}.log
  .selftest/                the three gate selftest micro-crates (regenerated)
  traceview/                the Rust trace viewer
    src/lib.rs              parsing + summary + rendering (unit tests inline)
    src/main.rs             CLI
    tests/render.rs         integration tests, incl. the real a9ctl 384-timeout log
    tests/fixtures/*.jsonl  small synthetic fixtures, named `synthetic-*` on purpose
```

The `synthetic-*` fixtures are hand-written to the shapes documented in `INTERFACE.md` §5 and
`gaster.c`. They are **not** captures. The 384-timeout JSONL replay used by the tests is generated
in-test rather than committed, so it cannot drift from the real log it mirrors.
