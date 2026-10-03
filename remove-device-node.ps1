$ErrorActionPreference = "Continue"
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Remove the DEVICE NODE (not just the package) so usbser can bind" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$targets = @(
  "USB\VID_04E8&PID_685D\6&3AF0F9CE&0&14",
  "USB\VID_04E8&PID_685D&Modem\7&1D64F404&0&0000"
)

Write-Host "[1] Present 04E8/685D nodes before removal:" -ForegroundColor Yellow
Get-PnpDevice -ErrorAction SilentlyContinue |
  Where-Object { $_.InstanceId -match "VID_04E8&PID_685D" } |
  Select-Object Status,Class,Service,InstanceId | Format-Table -AutoSize
Write-Host ""

Write-Host "[2] Removing device node (this clears the WinUSB driver-key override)..." -ForegroundColor Yellow
foreach ($t in $targets) {
  Write-Host ("  -> " + $t) -ForegroundColor Gray
  pnputil /remove-device "$t"
  Write-Host ("     exit = {0}" -f $LASTEXITCODE) -ForegroundColor Gray
}
Write-Host ""

Write-Host "[3] Also try deleting the driver package again (belt and braces)..." -ForegroundColor Yellow
pnputil /delete-driver oem45.inf /uninstall /force
Write-Host ("    exit = {0}" -f $LASTEXITCODE) -ForegroundColor Gray
Write-Host ""

Write-Host "[4] Rescanning..." -ForegroundColor Yellow
pnputil /scan-devices
Start-Sleep -Seconds 3
Write-Host ""

Write-Host "[5] Device nodes AFTER:" -ForegroundColor Yellow
Get-PnpDevice -ErrorAction SilentlyContinue |
  Where-Object { $_.InstanceId -match "VID_04E8&PID_685D|VID_04E8&PID_6860&MI_01" } |
  Select-Object Status,Class,Service,InstanceId | Format-Table -AutoSize
Write-Host ""

Write-Host "[6] Did usbser bind? Check the Service column above." -ForegroundColor Yellow
Write-Host "    Desired: Service = usbser    (was: WinUSB)" -ForegroundColor Green
Write-Host ""

Write-Host "[7] COM ports:" -ForegroundColor Yellow
Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
  Select-Object Status,FriendlyName,InstanceId | Format-Table -AutoSize
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " If Service still says WinUSB: UNPLUG and REPLUG the phone." -ForegroundColor Green
Write-Host " A replug re-runs driver selection against the (now removed) override." -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "(Window stays open - close it whenever.)" -ForegroundColor DarkGray
