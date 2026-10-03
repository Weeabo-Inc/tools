param(
  [Parameter(Mandatory=$true)][string]$Path,
  [switch]$Quiet
)
$adb = "<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
$dir = Split-Path -Parent $Path
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
if (Test-Path $Path) { Remove-Item $Path -Force -ErrorAction SilentlyContinue }

# Start adb as a process with a raw stdout stream so PNG bytes are never re-encoded.
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $adb
$psi.Arguments = 'exec-out screencap -p'
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$p = [System.Diagnostics.Process]::Start($psi)
$fs = [System.IO.File]::Create($Path)
$p.StandardOutput.BaseStream.CopyTo($fs)
$fs.Close()
$p.WaitForExit()

$len = (Get-Item $Path -ErrorAction SilentlyContinue).Length
if ($len -lt 100) {
  Write-Output "SCREENCAP FAILED (only $len bytes)"
  exit 1
}
$bytes = [System.IO.File]::ReadAllBytes($Path)
$sig = ($bytes[0..7] | ForEach-Object { $_.ToString('X2') }) -join ' '
if ($sig -ne '89 50 4E 47 0D 0A 1A 0A') { Write-Output "WARNING: not a valid PNG ($sig)" }
if (-not $Quiet) { Write-Output "OK $Path ($len bytes)" }
