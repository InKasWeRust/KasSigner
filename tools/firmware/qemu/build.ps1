$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
. (Join-Path $root 'scripts/windows/lib/common.ps1')
$firmware = Join-Path $root 'apps/signer-firmware'
$targetTriple = 'xtensa-esp32s3-none-elf'
$firmwareTarget = Join-Path $firmware 'target'
$qemuElf = Join-Path $firmwareTarget "$targetTriple/release/kassigner-firmware"
$qemuOut = Join-Path $root 'target/qemu'
$image = Join-Path $qemuOut 'kassigner-qemu-flash.bin'
$requiredBytes = 8 * 1024 * 1024
foreach ($cmd in @('cargo','espflash')) { Require-KasSignerCommand $cmd | Out-Null }
$python = Get-KasSignerPython
New-Item -ItemType Directory -Force -Path $qemuOut | Out-Null
Invoke-KasSignerCommand -Command 'cargo' -Arguments @('build','--locked','--release','--no-default-features','--features','qemu-tests') -WorkingDirectory $firmware -Environment @{ 'CARGO_TARGET_DIR'=$firmwareTarget } | Out-Null
Invoke-KasSignerCommand -Command 'espflash' -Arguments @('save-image','--chip','esp32s3','--flash-size','8mb','--merge',$qemuElf,$image) -WorkingDirectory $root | Out-Null
$actual = (Get-Item -LiteralPath $image).Length
if ($actual -gt $requiredBytes) { throw "QEMU flash image is $actual bytes; expected at most $requiredBytes" }
if ($actual -lt $requiredBytes) {
    $stream = [IO.File]::Open($image,[IO.FileMode]::Append,[IO.FileAccess]::Write)
    try {
        [byte[]]$buffer = New-Object byte[] 65536
        for ($i = 0; $i -lt $buffer.Length; $i++) { $buffer[$i] = 0xff }
        $remaining = $requiredBytes - $actual
        while ($remaining -gt 0) { $count = [Math]::Min($buffer.Length,$remaining); $stream.Write($buffer,0,$count); $remaining -= $count }
    } finally { $stream.Dispose() }
}
Write-Host "QEMU ELF:   $qemuElf"
Write-Host "QEMU flash: $image"
Write-Host ((Get-FileHash -Algorithm SHA256 -LiteralPath $image).Hash.ToLowerInvariant() + '  ' + $image)
