@echo off
REM ---------------------------------------------------------------------------
REM a9pwn gate wrapper.  ASCII only, CRLF only: cmd.exe is not UTF-8 aware.
REM
REM This host's PowerShell execution policy is Restricted, so a9pwn-gate.ps1
REM cannot be run directly ("running scripts is disabled on this system"). This
REM wrapper passes -ExecutionPolicy Bypass for THIS PROCESS ONLY. No machine or
REM user execution policy is changed, and nothing is written outside tools\arlo\.
REM
REM Usage:
REM   tools\arlo\a9pwn-gate.cmd                 gate a9pwn and print the result
REM   tools\arlo\a9pwn-gate.cmd -Selftest       prove the gate itself
REM   tools\arlo\a9pwn-gate.cmd -EmitJson       also dump the result JSON
REM   tools\arlo\a9pwn-gate.cmd -Ignore "src\.*.tmpdir\*"
REM
REM Exit codes: 0 PASS, 1 FAIL, 2 could not run (see the script header).
REM ---------------------------------------------------------------------------
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0a9pwn-gate.ps1" %*
exit /b %ERRORLEVEL%
