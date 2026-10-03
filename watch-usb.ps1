$start = Get-Date
$deadline = $start.AddSeconds(45)
$prev = ''
$events = @()
"WATCH START $(Get-Date -Format HH:mm:ss)"
while ((Get-Date) -lt $deadline) {
    $now = @{}
    foreach ($d in (Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'VID_0C45|VID_05AC' })) {
        if ($d.InstanceId -match '(VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4})') { $now[$Matches[1].ToUpper()] = $true }
    }
    $key = ($now.Keys | Sort-Object) -join ','
    $t = [int]((Get-Date) - $start).TotalSeconds
    if ($key -ne $prev) {
        if ($prev -eq '') { "  [$t" + "s] baseline: $key" }
        else {
            $old = @($prev -split ',' | Where-Object { $_ })
            $new = @($key  -split ',' | Where-Object { $_ })
            foreach ($a in ($new | Where-Object { $_ -notin $old })) { "  [$t" + "s] *** APPEARED: $a ***"; $events += "APPEARED $a" }
            foreach ($v in ($old | Where-Object { $_ -notin $new })) { "  [$t" + "s] --- VANISHED: $v ---"; $events += "VANISHED $v" }
            if ($new.Count -eq 0) { "  [$t" + "s] (no devices present)" }
        }
        $prev = $key
    }
    Start-Sleep -Milliseconds 150
}
""
"WATCH END"
if ($events.Count -gt 0) { $events | Group-Object | ForEach-Object { "  EVENT: $($_.Name) x$($_.Count)" } }
else { "  NO USB CHANGES OBSERVED" }
"FINAL: " + ((Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match 'VID_0C45|VID_05AC' } | ForEach-Object { if ($_.InstanceId -match '(VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4})') { $Matches[1].ToUpper() } } | Sort-Object -Unique) -join ', ')
