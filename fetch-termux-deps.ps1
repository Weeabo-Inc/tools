# Download a full dependency closure from the Termux ARM repo for offline install.
$ErrorActionPreference = 'Continue'
$base    = "https://packages-cf.termux.dev/apt/termux-main"
$stage   = "<REPO_ROOT>\stage\debs"
$idxPath = "<REPO_ROOT>\stage\Packages-arm.txt"
New-Item -ItemType Directory -Force -Path $stage | Out-Null

# ---- parse the Packages index into a lookup table -------------------------
Write-Output "=== parsing Packages index ==="
$pkgs = @{}
$cur = $null
foreach ($l in (Get-Content $idxPath)) {
    if ($l -match '^Package: (.+)$') {
        if ($cur) { $pkgs[$cur.Package] = $cur }
        $cur = [ordered]@{ Package = $Matches[1]; Depends = ''; Provides = '' }
    }
    elseif ($cur -and $l -match '^([A-Za-z0-9-]+):\s*(.*)$') {
        $k = $Matches[1]; $v = $Matches[2]
        if ($k -in @('Version','Filename','Size','Architecture','Depends','Provides','Installed-Size')) { $cur[$k] = $v }
    }
}
if ($cur) { $pkgs[$cur.Package] = $cur }
Write-Output ("  indexed {0} packages" -f $pkgs.Count)

# ---- resolve dependency closure starting from roots ----------------------
$roots = @('proot','proot-distro','python','libandroid-shmem','libtalloc')
$want  = New-Object System.Collections.Generic.HashSet[string]
$queue = New-Object System.Collections.Generic.Queue[string]
foreach ($r in $roots) { if ($pkgs.ContainsKey($r)) { [void]$queue.Enqueue($r) } else { Write-Output "  WARN root not found: $r" } }

while ($queue.Count -gt 0) {
    $name = $queue.Dequeue()
    if ($want.Contains($name)) { continue }
    if (-not $pkgs.ContainsKey($name)) { continue }
    [void]$want.Add($name)
    $dep = $pkgs[$name].Depends
    if ($dep) {
        foreach ($d in ($dep -split ',')) {
            $dn = ($d.Trim() -split '\s+')[0]
            $dn = ($dn -split '\(')[0].Trim()
            if ($dn -and $pkgs.ContainsKey($dn)) { [void]$queue.Enqueue($dn) }
        }
    }
}
Write-Output ("=== dependency closure: {0} packages ===" -f $want.Count)
$want | Sort-Object | ForEach-Object { Write-Output "  $_" }

# ---- download them --------------------------------------------------------
Write-Output ""
Write-Output "=== downloading ==="
$total = 0
foreach ($n in ($want | Sort-Object)) {
    $p  = $pkgs[$n]
    $fn = $p.Filename
    if (-not $fn) { Write-Output "  skip $n (no Filename)"; continue }
    $leaf = Split-Path $fn -Leaf
    $dest = Join-Path $stage $leaf
    if (Test-Path $dest) { Write-Output ("  have  {0}" -f $leaf); continue }
    $url = "$base/$fn"
    try {
        Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing -TimeoutSec 300
        $sz = (Get-Item $dest).Length
        $total += $sz
        Write-Output ("  got   {0}  ({1:N0} KB)" -f $leaf, ($sz/1KB))
    } catch { Write-Output ("  FAIL  {0} : {1}" -f $leaf, $_.Exception.Message) }
}
Write-Output ""
Write-Output ("=== staged {0} debs, {1:N1} MB ===" -f (Get-ChildItem $stage -Filter *.deb).Count, ($total/1MB))
Get-ChildItem $stage -Filter *.deb | Select-Object Name, @{n='KB';e={[math]::Round($_.Length/1KB,0)}} | Format-Table -AutoSize | Out-String
