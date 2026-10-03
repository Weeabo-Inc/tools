# Drive the phone over SSH once sshd is up.
# Usage: powershell -File ssh-phone.ps1 -Cmd "uname -a"
param(
  [string]$Cmd = "echo hello",
  [string]$HostAddr = "<LAN_IP>",
  [int]$Port = 8022,
  [string]$User = "termux",
  [string]$Pass = "termux123"
)

$ErrorActionPreference = 'Continue'
$ssh = "C:\Windows\System32\OpenSSH\ssh.exe"
$scp = "C:\Windows\System32\OpenSSH\scp.exe"

Write-Output "=== testing reachability ==="
$t = Test-NetConnection -ComputerName $HostAddr -Port $Port -WarningAction SilentlyContinue
Write-Output ("  TCP {0}:{1} reachable = {2}" -f $HostAddr, $Port, $t.TcpTestSucceeded)
if (-not $t.TcpTestSucceeded) { Write-Output "SSHD NOT REACHABLE"; exit 1 }

Write-Output "=== running remote command ==="
# plink supports -pw; Windows OpenSSH does not accept passwords non-interactively.
$plink = (Get-Command plink.exe -ErrorAction SilentlyContinue).Source
if ($plink) {
    & $plink -ssh -P $Port -l $User -pw $Pass -batch $HostAddr $Cmd 2>&1 | Out-String
} else {
    Write-Output "  (no plink; attempting plain ssh - may prompt)"
    & $ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=NUL -p $Port "$User@$HostAddr" $Cmd 2>&1 | Out-String
}
