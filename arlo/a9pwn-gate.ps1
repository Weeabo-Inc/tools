<#
.SYNOPSIS
    a9pwn test gate - build, test, and prove which bytes were tested.

.DESCRIPTION
    Runs `cargo build --release --offline` then `cargo test --release --offline`
    in a9pwn, and emits a machine-readable result that pins the run to exact
    bytes: a SHA-256 manifest of every file in a9pwn/src, plus the context files
    that change what those tests mean (Cargo.toml, Cargo.lock, payloads/**, build.rs).

    The property this gate exists for: the manifest is taken at BOTH ends of the
    run, and a difference is a FAILURE. "The tests passed" is worthless if the
    bytes changed while they ran - other engineers are editing this tree
    concurrently, and that has already cost this project a round trip.

    Read-only with respect to the working tree: no `git checkout`, no `git reset`,
    no `git clean`, no deletion, no formatting. The only things it writes are its
    own result/log files under tools/arlo/, and whatever cargo writes under
    a9pwn/target/. Git, if a9pwn has a repository, is used for `rev-parse` and
    `status --porcelain` only - recorded so a reader knows what the tree looked
    like, never modified.

    It never executes a9pwn.exe. Building and testing is the whole mandate;
    the phone belongs to the Lead.

.PARAMETER Repo
    The crate to gate. Default: <this script>\..\..\a9pwn.

.PARAMETER Out
    Where the machine-readable result is written. Default:
    <this script>\out\a9pwn-gate.json

.PARAMETER Ignore
    Globs, relative to the repo, excluded from the CHANGE CHECK (they are still
    hashed and reported, and every glob used is recorded in the result, so an
    exemption can never be silent). Off by default: the gate is fail-closed.

.PARAMETER EmitJson
    Also print the result JSON to stdout.

.PARAMETER Selftest
    Prove the gate itself: run three bundled micro-crates through the real gate
    and check that (1) a clean crate passes with exact totals, (2) a crate whose
    test rewrites its own source FAILS with source_changed_during_run, (3) a crate
    that does not compile FAILS with build_failed. Run this after changing the
    gate; it does not touch a9pwn.

.EXIT CODES
    0  PASS
    1  FAIL  (build failed, tests failed, no test result, or bytes moved mid-run)
    2  the gate could not run at all (bad repo, cargo missing, unwritable output)
#>
[CmdletBinding()]
param(
    [string]$Repo,
    [string]$Out,
    [string[]]$Ignore = @(),
    [switch]$EmitJson,
    [switch]$Selftest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:CARGO_TERM_COLOR = 'never'

# $PSScriptRoot is NOT reliably populated inside a param() default value on
# Windows PowerShell 5.1: it comes back empty and the Join-Path in the default
# fails before a single line of output. Resolve the script directory in the body
# instead, and use $ScriptDir everywhere below.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ScriptDir) { $ScriptDir = (Get-Location).Path }
if (-not $Repo) { $Repo = Join-Path $ScriptDir '..\..\a9pwn' }
if (-not $Out) { $Out = Join-Path $ScriptDir 'out\a9pwn-gate.json' }

$GateVersion = '1.0.0'
$script:Failures = New-Object System.Collections.Generic.List[string]

# --------------------------------------------------------------------- helpers

function Write-Head([string]$Text) { Write-Host $Text }
function Write-Note([string]$Text) { Write-Host "  $Text" }

<#
    Never write to D:. D: is a failing disk (HANDOFF 0.2, 2) and the whole tree
    moved to E: because of it.
#>
function Assert-WritablePath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($root -and $root.ToUpperInvariant().StartsWith('D:')) {
        throw "refusing to write to D: ($full) - HANDOFF 0.2: D: holds a failing disk. Use C: or E:."
    }
    return $full
}

function Get-RelPath {
    param([string]$Root, [string]$Full)
    try { return [System.IO.Path]::GetRelativePath($Root, $Full) } catch { }
    $r = $Root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($Full.StartsWith($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $Full.Substring($r.Length) }
    return $Full
}

function Get-Sha256 {
    param([string]$Path)
    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

<#
    SHA-256 over the canonical manifest text, so a whole tree can be named by one
    value. Uses a temp file rather than a .NET hash object: works in every
    language mode, and the temp file is checked against the D: rule first.
#>
function Get-TextSha256 {
    param([string]$Text, [string]$ScratchDir)
    $tmp = $null
    try {
        $tmp = Join-Path $ScratchDir ("manifest-" + [guid]::NewGuid().ToString('N') + ".txt")
        [System.IO.File]::WriteAllText($tmp, $Text, (New-Object System.Text.UTF8Encoding($false)))
        return (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash
    } catch {
        return $null
    } finally {
        if ($tmp -and (Test-Path -LiteralPath $tmp)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

<#
    The guarded set. `src` is the promise the gate makes; the rest is context that
    changes what the tests exercise (a swapped payload blob is a different
    exploit, tested by `verify_blob_hashes`).
#>
function Get-GuardedFiles {
    param([string]$RepoPath)
    $files = New-Object System.Collections.Generic.List[object]
    $src = Join-Path $RepoPath 'src'
    if (Test-Path -LiteralPath $src) {
        foreach ($f in Get-ChildItem -LiteralPath $src -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $files.Add([pscustomobject]@{ File = $f; Scope = 'source' })
        }
    }
    foreach ($name in 'Cargo.toml', 'Cargo.lock', 'build.rs') {
        $p = Join-Path $RepoPath $name
        if (Test-Path -LiteralPath $p) {
            $files.Add([pscustomobject]@{ File = (Get-Item -LiteralPath $p); Scope = 'context' })
        }
    }
    $payloads = Join-Path $RepoPath 'payloads'
    if (Test-Path -LiteralPath $payloads) {
        foreach ($f in Get-ChildItem -LiteralPath $payloads -Recurse -File -Force -ErrorAction SilentlyContinue) {
            $files.Add([pscustomobject]@{ File = $f; Scope = 'context' })
        }
    }
    return $files
}

function Get-Manifest {
    param([string]$RepoPath, [string[]]$IgnoreGlobs)
    $entries = New-Object System.Collections.Generic.List[object]
    $unreadable = New-Object System.Collections.Generic.List[string]
    foreach ($item in Get-GuardedFiles -RepoPath $RepoPath) {
        $f = $item.File
        $rel = Get-RelPath -Root $RepoPath -Full $f.FullName
        $sha = Get-Sha256 -Path $f.FullName
        if (-not $sha) { $unreadable.Add($rel) }
        $ignored = $false
        foreach ($g in $IgnoreGlobs) { if ($rel -like $g) { $ignored = $true } }
        $entries.Add([pscustomobject]@{
                rel       = $rel
                scope     = $item.Scope
                bytes     = $f.Length
                sha256    = $sha
                mtime_utc = $f.LastWriteTimeUtc.ToString('o')
                ignored   = $ignored
            })
    }
    $sorted = @($entries | Sort-Object -Property rel -CaseSensitive)
    $canonical = ($sorted | ForEach-Object { "$($_.rel)`t$($_.sha256)`n" }) -join ''
    return [pscustomobject]@{
        entries    = $sorted
        canonical  = $canonical
        count      = $sorted.Count
        unreadable = $unreadable.ToArray()
    }
}

function Compare-Manifest {
    param($Before, $After, [string[]]$IgnoreGlobs)
    $changed = New-Object System.Collections.Generic.List[object]
    $mapB = @{}
    foreach ($e in $Before.entries) { $mapB[$e.rel] = $e }
    $mapA = @{}
    foreach ($e in $After.entries) { $mapA[$e.rel] = $e }

    $allRels = @($mapB.Keys + $mapA.Keys | Sort-Object -Unique)
    foreach ($rel in $allRels) {
        $b = $mapB[$rel]
        $a = $mapA[$rel]
        $skip = $false
        foreach ($g in $IgnoreGlobs) { if ($rel -like $g) { $skip = $true } }
        if ($skip) { continue }
        if ($b -and -not $a) {
            $changed.Add([pscustomobject]@{ path = $rel; change = 'removed'; scope = $b.scope; sha_before = $b.sha256; sha_after = $null })
        } elseif ($a -and -not $b) {
            $changed.Add([pscustomobject]@{ path = $rel; change = 'added'; scope = $a.scope; sha_before = $null; sha_after = $a.sha256 })
        } elseif ($a.sha256 -ne $b.sha256) {
            $changed.Add([pscustomobject]@{ path = $rel; change = 'modified'; scope = $a.scope; sha_before = $b.sha256; sha_after = $a.sha256 })
        } elseif ($a.mtime_utc -ne $b.mtime_utc) {
            $changed.Add([pscustomobject]@{ path = $rel; change = 'rewritten-identical'; scope = $a.scope; sha_before = $b.sha256; sha_after = $a.sha256 })
        }
    }
    return $changed.ToArray()
}

function Get-GitInfo {
    param([string]$RepoPath)
    $info = [ordered]@{ available = $false; head = $null; branch = $null; dirty_paths = @(); note = $null }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { $info.note = 'git is not on PATH'; return $info }
    try {
        $head = & git -C $RepoPath rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -ne 0) { $info.note = 'not a git repository (read-only check; nothing was modified)'; return $info }
        $info.available = $true
        $info.head = "$head".Trim()
        $branch = & git -C $RepoPath branch --show-current 2>$null
        $info.branch = "$branch".Trim()
        $dirty = & git -C $RepoPath status --porcelain 2>$null
        $info.dirty_paths = @($dirty | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        $info.note = 'read-only: rev-parse + status only; the gate never checks out, resets or cleans'
    } catch {
        $info.note = "git inspection failed: $($_.Exception.Message)"
    }
    return $info
}

<#
    One cargo step. Synchronous, with every stream merged into one log file.
#>
function Invoke-CargoStep {
    param(
        [string]$Name,
        [string[]]$CargoArgs,
        [string]$RepoPath,
        [string]$WorkDir
    )
    $log = Join-Path $WorkDir "$Name.log"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $argvText = "cargo " + ($CargoArgs -join ' ')
    Write-Note "running: $argvText"
    Write-Note "  (a cold build can take minutes; every stream is going to $log)"

    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $code = $null
    Push-Location -LiteralPath $RepoPath
    try {
        # `*>` merges stdout, stderr and every PowerShell stream into the log.
        # `$LASTEXITCODE` is read on the very next statement. That is the only
        # exit-code source that is reliable here: on Windows PowerShell 5.1,
        # `Start-Process -PassThru` returns a Process whose ExitCode is EMPTY as
        # soon as -RedirectStandardOutput is used (measured on this host: a child
        # doing `exit 3` reported nothing, before and after WaitForExit), and an
        # empty exit code read as 0 would turn every cargo failure into a pass -
        # the exact class of bug this gate exists to catch.
        & cargo @CargoArgs *> $log
        $code = $LASTEXITCODE
    } finally {
        Pop-Location
        $ErrorActionPreference = $prevEap
    }
    $sw.Stop()
    $logText = if (Test-Path -LiteralPath $log) { [System.IO.File]::ReadAllText($log) } else { '' }
    return [pscustomobject]@{
        name      = $Name
        argv      = @('cargo') + $CargoArgs
        argv_text = $argvText
        exit_code = $code
        seconds   = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        combined  = $logText
        log       = $log
    }
}

<#
    Test totals across EVERY `test result:` line. a9pwn produces four (lib, bin,
    integration, doc); reading only the last one is how a failing integration
    test gets reported as a pass.
#>
function Get-TestTotals {
    param([string]$Text)
    $rx = [regex]'test result: (?<verdict>ok|FAILED)\. (?<passed>\d+) passed; (?<failed>\d+) failed; (?<ignored>\d+) ignored; (?<measured>\d+) measured; (?<filtered>\d+) filtered out'
    $targets = New-Object System.Collections.Generic.List[object]
    $passed = 0; $failed = 0; $ignored = 0; $measured = 0; $filtered = 0
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -notmatch 'test result:') { continue }
        foreach ($m in $rx.Matches($line)) {
            $passed += [int]$m.Groups['passed'].Value
            $failed += [int]$m.Groups['failed'].Value
            $ignored += [int]$m.Groups['ignored'].Value
            $measured += [int]$m.Groups['measured'].Value
            $filtered += [int]$m.Groups['filtered'].Value
            $targets.Add([pscustomobject]@{
                    verdict = $m.Groups['verdict'].Value
                    passed  = [int]$m.Groups['passed'].Value
                    failed  = [int]$m.Groups['failed'].Value
                    ignored = [int]$m.Groups['ignored'].Value
                    raw     = $line.Trim()
                })
        }
    }
    $failedNames = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Text -split "`r?`n")) {
        $m = [regex]::Match($line, '^test (?<name>.+?) \.\.\. FAILED')
        if ($m.Success) { $failedNames.Add($m.Groups['name'].Value) }
    }
    return [pscustomobject]@{
        parsed       = ($targets.Count -gt 0)
        result_lines = $targets.Count
        passed       = $passed
        failed       = $failed
        ignored      = $ignored
        measured     = $measured
        filtered_out = $filtered
        targets      = $targets.ToArray()
        failed_names = $failedNames.ToArray()
    }
}

function Get-ErrorLines {
    param([string]$Text, [int]$Limit = 12)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^error(\[|:)') {
            $out.Add($line.Trim())
            if ($out.Count -ge $Limit) { break }
        }
    }
    return $out.ToArray()
}

function Get-WarningCount {
    param([string]$Text)
    $n = 0
    foreach ($line in ($Text -split "`r?`n")) { if ($line -match '^warning:') { $n++ } }
    return $n
}

# ------------------------------------------------------------------- the gate

function Invoke-Gate {
    param(
        [string]$RepoPath,
        [string]$OutPath,
        [string[]]$IgnoreGlobs = @(),
        [switch]$Quiet
    )
    $failures = New-Object System.Collections.Generic.List[string]
    $started = (Get-Date).ToUniversalTime()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $repoFull = [System.IO.Path]::GetFullPath($RepoPath)
    if (-not (Test-Path -LiteralPath $repoFull)) {
        throw "repo not found: $repoFull"
    }
    $manifestRoot = Join-Path $repoFull 'src'
    if (-not (Test-Path -LiteralPath $manifestRoot)) {
        throw "no src directory under $repoFull - refusing to gate something that is not the layout this gate promises to hash"
    }
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) { throw 'cargo is not on PATH' }

    $workRoot = Join-Path $ScriptDir (Join-Path 'out' 'logs')
    $workRoot = Assert-WritablePath $workRoot
    New-Item -ItemType Directory -Force -Path $workRoot | Out-Null
    $stamp = $started.ToString('yyyyMMdd-HHmmss')
    $workDir = Join-Path $workRoot ("gate-" + $stamp + "-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Force -Path $workDir | Out-Null

    $cargoVersion = "$(& cargo --version 2>$null)".Trim()
    $rustcVersion = "$(& rustc --version 2>$null)".Trim()
    $gitInfo = Get-GitInfo -RepoPath $repoFull

    if (-not $Quiet) {
        Write-Note "repo          : $repoFull"
        Write-Note "cargo         : $cargoVersion"
        if ($gitInfo.available) {
            Write-Note "git           : HEAD $($gitInfo.head) on $($gitInfo.branch), $($gitInfo.dirty_paths.Count) modified path(s) (read-only)"
        } else {
            Write-Note "git           : $($gitInfo.note)"
        }
    }

    # ---- manifest BEFORE. This is the window's left edge; the right edge is
    #      taken after the test command returns, and equality is the proof that
    #      the tested bytes never moved.
    $beforeTime = (Get-Date).ToUniversalTime()
    $before = Get-Manifest -RepoPath $repoFull -IgnoreGlobs $IgnoreGlobs
    $beforeTree = Get-TextSha256 -Text $before.canonical -ScratchDir $workDir
    if ($before.unreadable.Count -gt 0) {
        $failures.Add("manifest_unreadable: $(($before.unreadable) -join ', ')")
    }
    if (-not $Quiet) {
        Write-Note "guarded       : $($before.count) file(s) [$((@($before.entries | Where-Object { $_.scope -eq 'source' })).Count) under src, $((@($before.entries | Where-Object { $_.scope -eq 'context' })).Count) context], tree sha256 $beforeTree"
    }

    # ---- build, then test. Exactly these two commands; nothing else is run.
    $build = Invoke-CargoStep -Name 'build' -CargoArgs @('build', '--release', '--offline') -RepoPath $repoFull -WorkDir $workDir
    if ($null -eq $build.exit_code) { $failures.Add('build_no_exit_code: cargo build ran but no exit code was captured - refusing to read an unknown exit code as success') }
    elseif ($build.exit_code -ne 0) { $failures.Add("build_failed: cargo build exited $($build.exit_code)") }

    $test = Invoke-CargoStep -Name 'test' -CargoArgs @('test', '--release', '--offline') -RepoPath $repoFull -WorkDir $workDir
    $totals = Get-TestTotals -Text $test.combined
    if ($null -eq $test.exit_code) { $failures.Add('test_no_exit_code: cargo test ran but no exit code was captured - refusing to read an unknown exit code as success') }
    elseif ($test.exit_code -ne 0) { $failures.Add("test_command_failed: cargo test exited $($test.exit_code)") }
    if (-not $totals.parsed) {
        $failures.Add('no_test_result_lines: cargo test produced no "test result:" line, so no test ran to a verdict (a build that fails to compile looks exactly like this)')
    } elseif ($totals.failed -gt 0) {
        $failures.Add("tests_failed: $($totals.failed) test(s) failed: $(($totals.failed_names | Select-Object -First 8) -join ', ')")
    }

    # ---- manifest AFTER, and the comparison that is the whole point.
    $after = Get-Manifest -RepoPath $repoFull -IgnoreGlobs $IgnoreGlobs
    $afterTime = (Get-Date).ToUniversalTime()
    $afterTree = Get-TextSha256 -Text $after.canonical -ScratchDir $workDir
    # `@(...)` around the call is load-bearing on Windows PowerShell 5.1: a
    # function that returns an EMPTY array delivers $null to the caller, because
    # the pipeline unrolls it. Without the @(), the "nothing changed" case - the
    # PASS case, exactly - became a null-valued expression and the gate died
    # instead of reporting success. Measured: f -> $null, @(f) -> 0-length array.
    $changed = @(Compare-Manifest -Before $before -After $after -IgnoreGlobs $IgnoreGlobs)
    $realChanges = @($changed | Where-Object { $_.change -ne 'rewritten-identical' })
    $touchedIdentical = @($changed | Where-Object { $_.change -eq 'rewritten-identical' })
    if ($realChanges.Count -gt 0) {
        $source = @($realChanges | Where-Object { $_.scope -eq 'source' })
        $context = @($realChanges | Where-Object { $_.scope -eq 'context' })
        if ($source.Count -gt 0) {
            $failures.Add("source_changed_during_run: $(($source | ForEach-Object { "$($_.path) [$($_.change)]" }) -join ', ') - the tests did not run against a fixed tree, so their verdict describes no particular bytes")
        }
        if ($context.Count -gt 0) {
            $failures.Add("context_changed_during_run: $(($context | ForEach-Object { "$($_.path) [$($_.change)]" }) -join ', ') - Cargo.toml/Cargo.lock/payloads decide what the tests exercise. cargo itself may have rewritten Cargo.lock; either way the run is not pinned, so re-run.")
        }
    }
    if ($after.unreadable.Count -gt 0) {
        $failures.Add("manifest_unreadable_after: $(($after.unreadable) -join ', ')")
    }

    # ---- artefacts, recorded but never trusted as proof of the source.
    $bin = Join-Path $repoFull 'target\release\a9pwn.exe'
    $binInfo = $null
    if (Test-Path -LiteralPath $bin) {
        $bi = Get-Item -LiteralPath $bin
        $binInfo = [pscustomobject]@{
            path      = $bin
            sha256    = Get-Sha256 -Path $bin
            mtime_utc = $bi.LastWriteTimeUtc.ToString('o')
            in_window = ($bi.LastWriteTimeUtc -ge $beforeTime.ToUniversalTime() -and $bi.LastWriteTimeUtc -le $afterTime)
        }
    }
    $testBins = @()
    $deps = Join-Path $repoFull 'target\release\deps'
    if (Test-Path -LiteralPath $deps) {
        $cands = Get-ChildItem -LiteralPath $deps -Filter 'a9pwn-*.exe' -File -ErrorAction SilentlyContinue
        if ($cands) {
            $newest = $cands | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
            $testBins = @([pscustomobject]@{
                    path      = $newest.FullName
                    sha256    = Get-Sha256 -Path $newest.FullName
                    mtime_utc = $newest.LastWriteTimeUtc.ToString('o')
                    in_window = ($newest.LastWriteTimeUtc -ge $beforeTime.ToUniversalTime() -and $newest.LastWriteTimeUtc -le $afterTime)
                })
        }
    }

    # ---- a source file vanishing between the two ends is a real change and is
    #      already in $realChanges; this only keeps the shape of the JSON stable.
    #
    # Built with explicit loops rather than `@($x | Where-Object { ... } |
    # ForEach-Object { [ordered]@{...} })` inside the hashtable literal below.
    # Windows PowerShell 5.1 fails on the nested form with "You cannot call a
    # method on a null-valued expression"; the trap that located it is described
    # in the README. A failure here would silently truncate the evidence.
    $srcFiles = @($before.entries | Where-Object { $_.scope -eq 'source' })
    $ctxFiles = @($before.entries | Where-Object { $_.scope -eq 'context' })
    $srcJson = New-Object System.Collections.Generic.List[object]
    foreach ($e in $srcFiles) {
        $srcJson.Add([ordered]@{ path = $e.rel; bytes = $e.bytes; sha256 = $e.sha256; mtime_utc = $e.mtime_utc; ignored = $e.ignored })
    }
    $ctxJson = New-Object System.Collections.Generic.List[object]
    foreach ($e in $ctxFiles) {
        $ctxJson.Add([ordered]@{ path = $e.rel; bytes = $e.bytes; sha256 = $e.sha256; mtime_utc = $e.mtime_utc; ignored = $e.ignored })
    }

    $summary = [ordered]@{
        tool                = 'a9pwn-gate'
        tool_version        = $GateVersion
        schema              = 1
        ok                  = ($failures.Count -eq 0)
        result              = if ($failures.Count -eq 0) { 'PASS' } else { 'FAIL' }
        failure_reasons     = $failures.ToArray()
        repo                = [ordered]@{
            path            = $repoFull
            exists          = $true
            manifest_root   = $manifestRoot
        }
        environment         = [ordered]@{
            cargo   = $cargoVersion
            rustc   = $rustcVersion
            pwsh    = "$($PSVersionTable.PSVersion)"
            machine = $env:COMPUTERNAME
            os      = "$([System.Environment]::OSVersion.VersionString)"
        }
        git                 = [ordered]@{
            available   = $gitInfo.available
            head        = $gitInfo.head
            branch      = $gitInfo.branch
            dirty_paths = @($gitInfo.dirty_paths)
            note        = $gitInfo.note
        }
        timing              = [ordered]@{
            started_utc      = $started.ToString('o')
            manifest_before  = $beforeTime.ToString('o')
            manifest_after   = $afterTime.ToString('o')
            finished_utc     = (Get-Date).ToUniversalTime().ToString('o')
            duration_seconds = [math]::Round($sw.Elapsed.TotalSeconds, 2)
            build_seconds    = $build.seconds
            test_seconds     = $test.seconds
        }
        commands            = @(
            [ordered]@{
                name      = 'build'
                argv      = $build.argv
                exit_code = $build.exit_code
                seconds   = $build.seconds
                warnings  = (Get-WarningCount -Text $build.combined)
                errors    = @(Get-ErrorLines -Text $build.combined)
                log       = $build.log
            },
            [ordered]@{
                name      = 'test'
                argv      = $test.argv
                exit_code = $test.exit_code
                seconds   = $test.seconds
                warnings  = (Get-WarningCount -Text $test.combined)
                errors    = @(Get-ErrorLines -Text $test.combined)
                log       = $test.log
            }
        )
        tests               = [ordered]@{
            parsed       = $totals.parsed
            result_lines = $totals.result_lines
            passed       = $totals.passed
            failed       = $totals.failed
            ignored      = $totals.ignored
            measured     = $totals.measured
            filtered_out = $totals.filtered_out
            targets      = @($totals.targets)
            failed_names = @($totals.failed_names)
        }
        source_manifest     = [ordered]@{
            root             = $manifestRoot
            promise          = 'these are the bytes the test command ran against, provided source_stable is true'
            file_count       = $srcFiles.Count
            tree_sha256_before = $beforeTree
            tree_sha256_after  = $afterTree
            files            = $srcJson.ToArray()
        }
        context_manifest    = [ordered]@{
            note               = 'hashed because these decide what the tests exercise: a swapped payload blob is a different exploit'
            tree_sha256_before = $beforeTree
            tree_sha256_after  = $afterTree
            files              = $ctxJson.ToArray()
        }
        source_stable       = ($realChanges.Count -eq 0)
        changed_during_run  = $changed
        rewritten_identical = @($touchedIdentical)
        ignored_globs       = @($IgnoreGlobs)
        artefacts           = [ordered]@{
            a9pwn_exe      = $binInfo
            newest_test_exe = if ($testBins.Count -gt 0) { $testBins[0] } else { $null }
        }
        logs                = $workDir
        meaning             = 'PASS means these exact bytes built, and their tests reported no failure. It says nothing about the device, the driver, or whether checkm8 will work.'
    }

    # Written here rather than by the caller, so a caller cannot forget: the
    # result exists as soon as the gate has an opinion.
    if ($OutPath) {
        $outFull = Assert-WritablePath $OutPath
        $parent = Split-Path -Parent $outFull
        if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
        $jsonText = $summary | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($outFull, $jsonText, (New-Object System.Text.UTF8Encoding($false)))
    }

    return [pscustomobject]@{ ok = ($failures.Count -eq 0); json = $summary; failures = $failures.ToArray(); before = $before; after = $after; changed = $changed; totals = $totals; build = $build; test = $test; git = $gitInfo; work_dir = $workDir }
}

function Write-GateReport {
    param($Run, [string]$OutPath)
    Write-Head ''
    Write-Head '  -- result ------------------------------------------------'
    Write-Note "build      : exit $($Run.build.exit_code) in $($Run.build.seconds)s, $((Get-WarningCount -Text $Run.build.combined)) warning(s)"
    Write-Note "test       : exit $($Run.test.exit_code) in $($Run.test.seconds)s, $((Get-WarningCount -Text $Run.test.combined)) warning(s)"
    if ($Run.totals.parsed) {
        Write-Note "tests      : $($Run.totals.passed) passed, $($Run.totals.failed) failed, $($Run.totals.ignored) ignored across $($Run.totals.result_lines) test target(s)"
    } else {
        Write-Note 'tests      : NO "test result:" LINE - nothing ran to a verdict'
    }
    $beforeTree = $Run.json.source_manifest.tree_sha256_before
    $afterTree = $Run.json.source_manifest.tree_sha256_after
    Write-Note "src tree   : $beforeTree (before) / $afterTree (after)"
    if ($Run.json.source_stable) {
        Write-Note "bytes      : STABLE - the source did not move during the run"
    } else {
        Write-Note "bytes      : MOVED DURING THE RUN - this is a failure, not a warning"
        foreach ($c in $Run.changed) {
            Write-Note "             $($c.change): $($c.path) [$($c.scope)] $($c.sha_before) -> $($c.sha_after)"
        }
    }
    if ($Run.failures.Count -gt 0) {
        Write-Note ''
        foreach ($f in $Run.failures) { Write-Note "FAILURE: $f" }
    }
    Write-Note ''
    Write-Note "RESULT: $(if ($Run.ok) { 'PASS' } else { 'FAIL' })"
    Write-Note "result json : $OutPath"
    Write-Note "logs        : $($Run.work_dir)"
    Write-Note 'PASS means these exact bytes built and their tests reported no failure. It says nothing about the device.'
}

# ----------------------------------------------------------------- selftest

function New-TinyCrate {
    param([string]$Dir, [string]$Name, [string]$LibRs)
    if (Test-Path -LiteralPath $Dir) { Remove-Item -LiteralPath $Dir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path (Join-Path $Dir 'src') | Out-Null
    $toml = @"
[package]
name = "$Name"
version = "0.0.0"
edition = "2021"

[lib]
path = "src/lib.rs"
"@
    [System.IO.File]::WriteAllText((Join-Path $Dir 'Cargo.toml'), $toml)
    [System.IO.File]::WriteAllText((Join-Path $Dir 'src\lib.rs'), $LibRs)
    # Generate the lockfile BEFORE the gate runs, exactly as a real checkout has
    # one. Otherwise cargo's own lockfile write lands inside the measured window
    # and the gate fails for a reason that has nothing to do with the tree.
    & cargo generate-lockfile --offline --manifest-path (Join-Path $Dir 'Cargo.toml') 2>&1 | Out-Null
    if (-not (Test-Path -LiteralPath (Join-Path $Dir 'Cargo.lock'))) {
        throw "selftest fixture $Dir has no Cargo.lock: `cargo generate-lockfile --offline` failed. Fix that before reading anything into the selftest result."
    }
    return $Dir
}

function Invoke-Selftest {
    $root = Join-Path $ScriptDir '.selftest'
    $root = Assert-WritablePath $root
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $results = New-Object System.Collections.Generic.List[object]

    # 1. a clean crate: the gate must PASS and count exactly
    $passDir = New-TinyCrate -Dir (Join-Path $root 'pass-crate') -Name 'gate-selftest-pass' -LibRs @'
pub fn add(a: i32, b: i32) -> i32 { a + b }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds() { assert_eq!(add(2, 2), 4); }

    #[test]
    fn adds_negatives() { assert_eq!(add(-1, 1), 0); }

    #[test]
    #[ignore]
    fn deliberately_ignored() { panic!("must never run by default"); }
}
'@
    Write-Head ''
    Write-Head '  selftest 1/3 - a clean crate must PASS with exact totals'
    $r1 = Invoke-Gate -RepoPath $passDir -OutPath (Join-Path $root 'pass.json')
    $ok1 = $r1.ok -and $r1.totals.passed -eq 2 -and $r1.totals.failed -eq 0 -and $r1.totals.ignored -eq 1 `
        -and $r1.json.source_stable -and $r1.json.source_manifest.file_count -eq 1 `
        -and "$($r1.json.source_manifest.tree_sha256_before)" -eq "$($r1.json.source_manifest.tree_sha256_after)"
    $results.Add([pscustomobject]@{
            scenario = 'clean crate passes with exact totals'
            expected = 'ok=True passed=2 failed=0 ignored=1 source_stable=True files=1'
            actual   = "ok=$($r1.ok) passed=$($r1.totals.passed) failed=$($r1.totals.failed) ignored=$($r1.totals.ignored) source_stable=$($r1.json.source_stable) files=$($r1.json.source_manifest.file_count)"
            pass     = $ok1
        })

    # 2. the property the gate exists for: a test that rewrites its own source
    $mutDir = New-TinyCrate -Dir (Join-Path $root 'mutate-crate') -Name 'gate-selftest-mutate' -LibRs @'
pub fn ok() -> bool { true }

#[cfg(test)]
mod tests {
    #[test]
    fn ok_test() { assert!(super::ok()); }

    /// Rewrites a file under src/ while the test command is running. The gate
    /// must refuse to report success.
    #[test]
    fn rewrites_its_own_source() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("mutated.txt");
        let mut s = std::fs::read_to_string(&p).unwrap_or_default();
        s.push('x');
        std::fs::write(&p, s).unwrap();
    }
}
'@
    Write-Head ''
    Write-Head '  selftest 2/3 - a mid-run source change must FAIL the gate'
    $r2 = Invoke-Gate -RepoPath $mutDir -OutPath (Join-Path $root 'mutate.json')
    $mutated = @($r2.changed | Where-Object { $_.path -like '*mutated.txt' })
    $ok2 = (-not $r2.ok) -and @($r2.failures | Where-Object { $_ -like 'source_changed_during_run*' }).Count -ge 1 -and $mutated.Count -ge 1
    $results.Add([pscustomobject]@{
            scenario = 'mid-run source change fails the gate'
            expected = 'ok=False + source_changed_during_run naming src/mutated.txt'
            actual   = "ok=$($r2.ok) failures=[$($r2.failures -join ' | ')]"
            pass     = $ok2
        })

    # 3. a crate that does not compile
    $badDir = New-TinyCrate -Dir (Join-Path $root 'broken-crate') -Name 'gate-selftest-broken' -LibRs @'
pub fn broken() -> i32 {
    let x: i32 = "this is not an integer";
    x
}
'@
    Write-Head ''
    Write-Head '  selftest 3/3 - a crate that does not compile must FAIL with build_failed'
    $r3 = Invoke-Gate -RepoPath $badDir -OutPath (Join-Path $root 'broken.json')
    $ok3 = (-not $r3.ok) `
        -and @($r3.failures | Where-Object { $_ -like 'build_failed*' }).Count -ge 1 `
        -and @($r3.failures | Where-Object { $_ -like 'no_test_result_lines*' }).Count -ge 1
    $results.Add([pscustomobject]@{
            scenario = 'uncompilable crate fails the gate'
            expected = 'ok=False + build_failed + no_test_result_lines'
            actual   = "ok=$($r3.ok) failures=[$($r3.failures -join ' | ')]"
            pass     = $ok3
        })

    Write-Head ''
    Write-Head '  -- gate selftest ------------------------------------------'
    foreach ($r in $results) {
        Write-Note ("[{0}] {1}" -f $(if ($r.pass) { 'ok  ' } else { 'FAIL' }), $r.scenario)
        if (-not $r.pass) {
            Write-Note "       expected: $($r.expected)"
            Write-Note "       actual  : $($r.actual)"
        }
    }
    $allPass = -not ($results | Where-Object { -not $_.pass })
    Write-Note ''
    Write-Note "SELFTEST: $(if ($allPass) { 'PASS' } else { 'FAIL' }) ($(@($results | Where-Object { $_.pass }).Count)/$($results.Count) scenarios)"
    if ($allPass) { exit 0 } else { exit 1 }
}

# ----------------------------------------------------------------------- main

if ($Selftest) {
    Invoke-Selftest
    exit 0
}

try {
    Write-Head ''
    Write-Head '  a9pwn gate - build, test, and prove which bytes were tested'
    # Fail fast on a forbidden output location, before spending minutes on cargo.
    $outFull = Assert-WritablePath $Out
    $run = Invoke-Gate -RepoPath $Repo -OutPath $outFull -IgnoreGlobs $Ignore
    Write-GateReport -Run $run -OutPath $outFull
    if ($EmitJson) { Write-Output (Get-Content -LiteralPath $outFull -Raw) }
    if ($run.ok) { exit 0 } else { exit 1 }
} catch {
    Write-Host ''
    Write-Host "  GATE COULD NOT RUN: $($_.Exception.Message)"
    Write-Host '  (exit 2 - this is a configuration problem, not a test failure)'
    exit 2
}
