# Verify the host clone is a complete, usable kernel tree.
$dst = "<REPO_ROOT>\kernel\src"
if (-not (Test-Path $dst)) { Write-Output "MISSING CLONE"; exit 1 }

Write-Output "=== top-level dirs ==="
Get-ChildItem $dst -Directory -Force | Where-Object { $_.Name -notmatch '^\.' } | Select-Object -ExpandProperty Name | Sort-Object | ForEach-Object { Write-Output "  $_" }

Write-Output ""
Write-Output "=== critical kernel paths ==="
$crit = @(
  'Makefile','Kconfig','arch\arm64\Makefile','arch\arm64\Kconfig',
  'arch\arm64\configs\physwizz_defconfig','arch\arm64\boot\Makefile',
  'drivers\Kconfig','drivers\Makefile','drivers\gpu\arm\Kconfig',
  'kernel\sched\core.c','kernel\Kconfig','mm\Kconfig','fs\Kconfig',
  'net\Kconfig','init\main.c','security\Kconfig','crypto\Kconfig',
  'block\Kconfig','ipc\Kconfig','build_kernel.sh'
)
foreach ($f in $crit) {
  $p = Join-Path $dst $f
  if (Test-Path $p) { Write-Output ("  OK   {0}" -f $f) } else { Write-Output ("  MISS {0}" -f $f) }
}

Write-Output ""
Write-Output "=== counts per major subsystem ==="
foreach ($d in @('arch','drivers','kernel','mm','fs','net','security','crypto','block','ipc','sound','include','scripts')) {
  $p = Join-Path $dst $d
  if (Test-Path $p) {
    $n = (Get-ChildItem $p -Recurse -File -Force -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Output ("  {0,-12} {1,7} files" -f $d, $n)
  } else { Write-Output ("  {0,-12} MISSING" -f $d) }
}

Write-Output ""
Write-Output "=== .config present (generated config)? ==="
Write-Output ("  host .config: " + (Test-Path (Join-Path $dst '.config')))

Write-Output ""
Write-Output "=== sanity: does the Mali Kconfig still have the BUG (upstream) or our FIX? ==="
$mk = Join-Path $dst 'drivers\gpu\arm\Kconfig'
if (Test-Path $mk) {
  Get-Content $mk | Select-Object -Skip 23 -First 8 | ForEach-Object { Write-Output "  | $_" }
}

Write-Output ""
Write-Output "=== sanity: is drivers/kernelsu referenced but absent (upstream state)? ==="
$dk = Join-Path $dst 'drivers\Kconfig'
if (Test-Path $dk) { Get-Content $dk | Select-String -Pattern 'kernelsu' | ForEach-Object { Write-Output "  | $_" } }
$ksu = Join-Path $dst 'drivers\kernelsu'
Write-Output ("  drivers/kernelsu dir exists: " + (Test-Path $ksu))
