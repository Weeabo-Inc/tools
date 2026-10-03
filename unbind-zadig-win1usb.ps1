$ErrorActionPreference = "Continue"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Whale-chan: unbind Zadig WinUSB -> let inbox CDC (usbser.sys) bind" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1] Current oem45.inf (Zadig / libwdi WinUSB):" -ForegroundColor Yellow
pnputil /enum-drivers | Select-String -Pattern "oem45" -Context 0,6
Write-Host ""

Write-Host "[2] Deleting oem45.inf and uninstalling the driver package..." -ForegroundColor Yellow
pnputil /delete-driver oem45.inf /uninstall /force
Write-Host ("    exit code = {0}" -f $LASTEXITCODE) -ForegroundColor Gray
Write-Host ""

Write-Host "[3] Rescanning hardware..." -ForegroundColor Yellow
pnputil /scan-devices
Write-Host ""

Write-Host "[4] Any Samsung device now?" -ForegroundColor Yellow
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
  Where-Object { $_.InstanceId -match "VID_04E8" } |
  Select-Object Status,Class,Service,FriendlyName,InstanceId | Format-Table -AutoSize
Write-Host ""

Write-Host "[5] Any device still failing descriptors?" -ForegroundColor Yellow
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
  Where-Object { $_.InstanceId -match "VID_0000" } |
  Select-Object Status,Class,Service,FriendlyName,InstanceId | Format-Table -AutoSize
Write-Host ""

Write-Host "[6] COM ports now:" -ForegroundColor Yellow
Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
  Select-Object Status,FriendlyName,InstanceId | Format-Table -AutoSize
Write-Host ""

Write-Host "[7] Is oem45.inf gone from the driver store?" -ForegroundColor Yellow
$still = pnputil /enum-drivers | Select-String -Pattern "oem45"
if ($still) { Write-Host "    STILL PRESENT" -ForegroundColor Red } else { Write-Host "    REMOVED" -ForegroundColor Green }
Write-Host ""

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " NEXT: unplug the phone, wait 5s, plug it back in." -ForegroundColor Green
Write-Host " Windows should then bind usbser.sys and a COM port should appear." -ForegroundColor Green
Write-Host " Tell the whale what step [6] shows." -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "(This window stays open - close it whenever.)" -ForegroundColor DarkGray
