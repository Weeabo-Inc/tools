$id = 'USB\VID_04E8&PID_685D\6&3AF0F9CE&0&14'
Write-Host "=== restarting device (port power-cycle) ===" -ForegroundColor Cyan
pnputil /restart-device $id
Start-Sleep 3
Write-Host "=== scanning for hardware changes ===" -ForegroundColor Cyan
pnputil /scan-devices
Write-Host "=== current state ===" -ForegroundColor Cyan
pnputil /enum-devices /instanceid $id
