$ErrorActionPreference = 'Continue'
$adb = "<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
$dest = "<REPO_ROOT>\phone-backup-2026"
New-Item -ItemType Directory -Force -Path $dest | Out-Null

function Say($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }
function Pull($remote, $localName) {
  Say "PULL START $remote -> $dest\$localName"
  & $adb pull -a $remote (Join-Path $dest $localName) 2>&1 | Out-Null
  if (Test-Path (Join-Path $dest $localName)) {
    $sz = (Get-ChildItem (Join-Path $dest $localName) -Recurse -File -ErrorAction SilentlyContinue |
           Measure-Object -Property Length -Sum).Sum
    Say ("PULL DONE  {0}  ({1:N1} MB)" -f $remote, ($sz / 1MB))
  } else {
    Say "PULL FAIL  $remote (nothing landed)"
  }
}

Say "=== BACKUP BEGIN ==="
& $adb start-server 2>&1 | Out-Null

# 1) Camera photos + videos (the big one)
Pull "/sdcard/DCIM" "DCIM"

# 2) Downloads
Pull "/sdcard/Download" "Download"

# 3) WhatsApp: databases (chat history) + Media (media), skip throwaway cache
Pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases" "WhatsApp-Databases"
Pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Media"     "WhatsApp-Media"
Pull "/sdcard/Android/media/com.whatsapp/WhatsApp/Backups"   "WhatsApp-Backups"

# 4) Odds and ends sitting loose in /sdcard root
foreach ($loose in @("A long overdue meeting with death_240417_160642_1.jpg",
                     "A long overdue meeting with death_240417_160642_2.jpg",
                     "Imp backlog_230731_020545.pdf",
                     "Life 3_240222_011743.pdf",
                     "Pretty girls_1.jpg",
                     "Pretty girls_2.jpg")) {
  Pull "/sdcard/$loose" "loose"
}
foreach ($sub in @("Pictures","Documents","Movies","Music","Recordings","opsu","AnkiDroid","Alarms","Notifications","Ringtones","Podcasts")) {
  Pull "/sdcard/$sub" $sub
}

# 5) App list so we can see what to reinstall after a wipe
Say "saving installed package list"
& $adb shell pm list packages -3 2>&1 | Out-File -FilePath (Join-Path $dest "installed-packages-thirdparty.txt") -Encoding utf8
& $adb shell pm list packages 2>&1    | Out-File -FilePath (Join-Path $dest "installed-packages-all.txt") -Encoding utf8
& $adb shell dumpsys package 2>&1     | Out-File -FilePath (Join-Path $dest "dumpsys-package.txt") -Encoding utf8

Say "=== BACKUP COMPLETE ==="
$total = (Get-ChildItem $dest -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
Say ("TOTAL BACKED UP: {0:N2} GB across {1} files" -f ($total / 1GB), (Get-ChildItem $dest -Recurse -File -ErrorAction SilentlyContinue).Count)
Get-ChildItem $dest | Select-Object Name, @{n='MB';e={[math]::Round(((Get-ChildItem $_.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum)/1MB,1)}} | Format-Table -AutoSize | Out-String | Write-Output
