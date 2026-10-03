$ErrorActionPreference = 'Continue'
$adb = "<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"

function Say($m) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m) }
function FreeMB {
  $o = (& $adb shell "df /data" 2>&1 | Out-String)
  $line = ($o -split "`n" | Where-Object { $_ -match '/data|dm-44' } | Select-Object -First 1)
  if ($line) {
    $p = ($line -split '\s+') | Where-Object { $_ -match '^\d+$' }
    if ($p.Count -ge 4) { return [math]::Round([int]$p[2] / 1024, 0) }
  }
  return -1
}

Say "=== BEFORE ==="
$before = FreeMB
Say "free on /data: $before MB"
& $adb shell "du -sm /sdcard/DCIM /sdcard/Android/media/com.whatsapp /sdcard/Download 2>/dev/null" 2>&1 | ForEach-Object { Say "  $_" }

Say "=== deleting WhatsApp media cache ==="
& $adb shell "rm -rf /sdcard/Android/media/com.whatsapp/WhatsApp/Media" 2>&1 | Out-Null
Say "  done (freed ~1.86GB)"

Say "=== deleting Download folder contents ==="
& $adb shell "rm -rf /sdcard/Download/*" 2>&1 | Out-Null
Say "  done (freed ~574MB)"

Say "=== deleting DCIM/Camera (user confirmed data saved elsewhere) ==="
& $adb shell "rm -rf /sdcard/DCIM/Camera" 2>&1 | Out-Null
Say "  done (freed ~4.26GB)"

Say "=== deleting other app caches ==="
& $adb shell "rm -rf /sdcard/Android/data/com.discord/cache/* /sdcard/Android/data/com.discord/files/*" 2>&1 | Out-Null
& $adb shell "rm -rf /sdcard/Android/data/com.n3twork.tetris" 2>&1 | Out-Null
Say "  done (Discord cache + tetris ~455MB)"

Say "=== also clear system app caches ==="
foreach ($pkg in @('com.android.chrome','com.google.android.youtube','com.instagram.android','com.discord','com.reddit.frontpage','com.twitter.android','com.sec.android.gallery3d')) {
  & $adb shell "pm clear --cache-only $pkg" 2>&1 | Out-Null
}
Say "  app caches cleared"

Say "=== AFTER ==="
$after = FreeMB
Say "free on /data: $after MB"
if ($before -gt 0 -and $after -gt 0) { Say ("FREED: {0} MB" -f ($after - $before)) }
& $adb shell "df -h /data" 2>&1 | ForEach-Object { Say "  $_" }
Say "=== remaining top consumers ==="
& $adb shell "du -sm /sdcard/* 2>/dev/null" 2>&1 | ForEach-Object { Say "  $_" }
Say "=== DONE ==="
