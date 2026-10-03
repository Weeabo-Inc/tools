$ErrorActionPreference='Continue'
$env:ADB_TOOLS='<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools'
$adb = Join-Path '<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools' 'adb.exe'
$fastboot = Join-Path '<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools' 'fastboot.exe'
function global:adb { & $adb @args }
function global:fastboot { & $fastboot @args }
$env:PATH = '<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools;' + $env:PATH
Write-Host "adb + fastboot ready on PATH (session)" -ForegroundColor Green
