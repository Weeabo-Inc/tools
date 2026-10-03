# Inspect the Termux APK: which ABIs does it ship native libs for?
Add-Type -AssemblyName System.IO.Compression.FileSystem
$apk = "<REPO_ROOT>\termux\termux-fdroid.apk"
if (-not (Test-Path $apk)) { Write-Output "APK MISSING"; exit 1 }

$zip = [System.IO.Compression.ZipFile]::OpenRead($apk)
try {
    $entries = $zip.Entries | ForEach-Object { $_.FullName }
    Write-Output ("total entries: {0}" -f $entries.Count)
    Write-Output ""
    Write-Output "=== native libs (lib/<abi>/*) ==="
    $libs = $entries | Where-Object { $_ -like 'lib/*' }
    $libs | ForEach-Object { Write-Output "  $_" }
    Write-Output ""
    Write-Output "=== ABI directories shipped ==="
    $abis = $libs | ForEach-Object { ($_ -split '/')[1] } | Sort-Object -Unique
    foreach ($a in $abis) { Write-Output "  ABI: $a" }
    Write-Output ""
    Write-Output "=== dex / manifest ==="
    $entries | Where-Object { $_ -like '*.dex' -or $_ -eq 'AndroidManifest.xml' } | ForEach-Object { Write-Output "  $_" }
} finally { $zip.Dispose() }
