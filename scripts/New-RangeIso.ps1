# New-RangeIso.ps1 — build the range answer-file ISO via IMAPI2FS (no external tools).
param(
  [string]$SourceDir = 'C:\Users\Jack\Downloads\enclave\deploy\range-iso',
  [string]$OutIso = 'C:\Users\Jack\Documents\Virtual Machines\enclave-target\autounattend.iso',
  [string]$VolName = 'RANGESETUP'
)
$ErrorActionPreference = 'Stop'
if (Test-Path $OutIso) { Remove-Item $OutIso -Force }
$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.VolumeName = $VolName
$fsi.FileSystemsToCreate = 3   # ISO9660 + Joliet
$fsi.Root.AddTree($SourceDir, $false)
$result = $fsi.CreateResultImage()
# The RCW hides IStream.Read — cast to the COM interface to expose it.
$istream = [System.Runtime.InteropServices.ComTypes.IStream]$result.ImageStream
$fs = [System.IO.File]::OpenWrite($OutIso)
$buffer = New-Object byte[] 65536
$ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
try {
  do {
    $istream.Read($buffer, $buffer.Length, $ptr)
    $read = [System.Runtime.InteropServices.Marshal]::ReadInt32($ptr)
    if ($read -gt 0) { $fs.Write($buffer, 0, $read) }
  } while ($read -gt 0)
} finally {
  [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
  $fs.Close()
}
Write-Output ("ISO written: {0} ({1} bytes)" -f $OutIso, (Get-Item $OutIso).Length)
