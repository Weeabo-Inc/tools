# Phone control helpers for the cracked-screen SM-A135F.
# Dot-source or call: powershell -ExecutionPolicy Bypass -File phone.ps1 -Action <name> [-Args ...]

param(
  [Parameter(Mandatory=$true)][string]$Action,
  [string]$Text,
  [int]$X = -1,
  [int]$Y = -1,
  [int]$X2 = -1,
  [int]$Y2 = -1,
  [int]$Ms = 300,
  [string]$Key
)

$ErrorActionPreference = 'Continue'
$adb  = "<HOME>\AppData\Local\Microsoft\WinGet\Packages\Google.PlatformTools_Microsoft.Winget.Source_8wekyb3d8bbwe\platform-tools\adb.exe"
$shots = "<REPO_ROOT>\phone-shots"

function Shot([string]$name) {
  $p = Join-Path $shots $name
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "<REPO_ROOT>\tools\take-shot.ps1" -Path $p -Quiet | Out-Null
  Write-Output $p
}
function Adb([string[]]$a) { & $adb @a 2>&1 | Out-String }

switch ($Action) {
  'wake'      { Adb @('shell','input','keyevent','KEYCODE_WAKEUP') | Out-Null; Start-Sleep -Milliseconds 500; Write-Output 'awake' }
  'sleep'     { Adb @('shell','input','keyevent','KEYCODE_SLEEP') | Out-Null; Write-Output 'asleep' }
  'home'      { Adb @('shell','input','keyevent','KEYCODE_HOME') | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output 'home' }
  'back'      { Adb @('shell','input','keyevent','KEYCODE_BACK') | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output 'back' }
  'enter'     { Adb @('shell','input','keyevent','KEYCODE_ENTER') | Out-Null; Write-Output 'enter' }
  'key'       { Adb @('shell','input','keyevent',$Key) | Out-Null; Write-Output "key $Key" }
  'swipeup'   { Adb @('shell','input','swipe','540','2000','540','800','250') | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output 'swiped up' }
  'swipedown' { Adb @('shell','input','swipe','540','800','540','2000','250') | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output 'swiped down' }
  'tap'       { Adb @('shell','input','tap',"$X","$Y") | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output "tapped $X,$Y" }
  'longpress' { Adb @('shell','input','swipe',"$X","$Y","$X","$Y",'1000') | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output "longpressed $X,$Y" }
  'swipe'     { Adb @('shell','input','swipe',"$X","$Y","$X2","$Y2",'300') | Out-Null; Start-Sleep -Milliseconds $Ms; Write-Output "swiped $X,$Y -> $X2,$Y2" }
  'text'      {
    $esc = $Text -replace ' ', '%s' -replace '([&<>|;()$`"''\\!#])', '\$1'
    Adb @('shell','input','text',$esc) | Out-Null
    Write-Output "typed: $Text"
  }
  'shot'      { Shot 'shot.png' }
  'focus'     { Adb @('shell','dumpsys window 2>/dev/null | grep -E "mCurrentFocus|mFocusedApp"') }
  'screen'    { Adb @('shell','wm size; wm density') }
  'stayon'    { Adb @('shell','svc power stayon usb') | Out-Null; Write-Output 'stayon usb enabled' }
  'killapp'   { Adb @('shell','am','force-stop',$Text) | Out-Null; Write-Output "killed $Text" }
  'start'     { Adb @('shell','am','start','-a',$Text) | Out-Null; Write-Output "started $Text" }
  'tapui'     {
    # Tap the first UI element whose text/content-desc matches $Text.
    $dump = Adb @('shell','uiautomator','dump','/sdcard/ui.xml')
    Adb @('pull','/sdcard/ui.xml',"$env:TEMP\ui.xml") | Out-Null
    if (Test-Path "$env:TEMP\ui.xml") {
      [xml]$xml = Get-Content "$env:TEMP\ui.xml" -Raw
      $node = $xml.SelectNodes('//node') | Where-Object {
        ($_.text -and $_.text -match [regex]::Escape($Text)) -or ($_.'content-desc' -and $_.'content-desc' -match [regex]::Escape($Text))
      } | Select-Object -First 1
      if ($node) {
        $b = $node.bounds -replace '[\[\]]',' ' -replace ',',' '
        $parts = $b -split '\s+' | Where-Object { $_ -ne '' }
        $cx = [int](([int]$parts[0] + [int]$parts[2]) / 2)
        $cy = [int](([int]$parts[1] + [int]$parts[3]) / 2)
        Adb @('shell','input','tap',"$cx","$cy") | Out-Null
        Write-Output "tapped '$Text' at $cx,$cy"
      } else { Write-Output "NO MATCH for '$Text'" }
    } else { Write-Output 'uiautomator dump failed' }
  }
  'dumptext'  {
    $dump = Adb @('shell','uiautomator','dump','/sdcard/ui.xml')
    Adb @('pull','/sdcard/ui.xml',"$env:TEMP\ui.xml") | Out-Null
    if (Test-Path "$env:TEMP\ui.xml") {
      [xml]$xml = Get-Content "$env:TEMP\ui.xml" -Raw
      $xml.SelectNodes('//node') | Where-Object { $_.text -or $_.'content-desc' } | ForEach-Object {
        $t = if ($_.text) { $_.text } else { $_.'content-desc' }
        Write-Output ("{0,-55} {1}" -f $t, $_.bounds)
      }
    } else { Write-Output 'uiautomator dump failed' }
  }
  default { Write-Output "unknown action: $Action" }
}
