Write-Host "=== killing brokkr (elevated) ===" -ForegroundColor Cyan
$procs = Get-Process brokkr -ErrorAction SilentlyContinue
if (-not $procs) { Write-Host "  brokkr not running" -ForegroundColor Yellow }
foreach ($p in $procs) {
  try { Stop-Process -Id $p.Id -Force -ErrorAction Stop; Write-Host ("  killed PID {0}" -f $p.Id) -ForegroundColor Green }
  catch { Write-Host ("  failed PID {0}: {1}" -f $p.Id, $_.Exception.Message) -ForegroundColor Red }
}
Start-Sleep -Seconds 2
if (Get-Process brokkr -ErrorAction SilentlyContinue) { Write-Host "  STILL RUNNING" -ForegroundColor Red }
else { Write-Host "  brokkr is gone" -ForegroundColor Green }

Write-Host ""
Write-Host "=== remaining handle-holders ===" -ForegroundColor Cyan
Get-Process -ErrorAction SilentlyContinue |
  Where-Object { $_.ProcessName -match 'zadig|brokkr|adb|scrcpy|heimdall|odin|probe' } |
  Select-Object Id,ProcessName | Format-Table -AutoSize

Write-Host "=== phone on USB? ===" -ForegroundColor Cyan
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
  Where-Object { $_.InstanceId -match 'VID_04E8|VID_0000|VID_18D1' } |
  Select-Object Status,Service,FriendlyName,InstanceId | Format-Table -AutoSize
Write-Host "Done. You can close this window." -ForegroundColor DarkGray
