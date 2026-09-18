# guest-icmp-matrix5.ps1 - RCVALL test: raw socket bound to the SPECIFIC guest IP with
# SIO_RCVALL (ReceiveAll) enabled, then 18s passive listen with a type-permissive VC
# parser. The live icmp agents generate channel replies every ~8s - if FRAME lines
# appear, RCVALL+specific-bind is the receive fix for 24H2. PURE ASCII ONLY.
$ErrorActionPreference = 'Stop'
$out = @()
try {
  $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]::Icmp)
  $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('192.168.50.130'), 0)))
  $s.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll, [byte[]](1, 0, 0, 0), $null)
  $s.ReceiveTimeout = 1000
} catch { Write-Host ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt 18000) {
  $buf = New-Object byte[] 65535
  $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
  $n = 0
  try { $n = $s.ReceiveFrom($buf, [ref]$remote) } catch { continue }
  if ($n -lt 29) { continue }
  $data = New-Object byte[] $n
  [Array]::Copy($buf, 0, $data, 0, $n)
  if (($data[0] -shr 4) -eq 4) {
    $ihl = ($data[0] -band 0x0F) * 4
    if ($ihl -ge 20 -and $ihl -le $n) { $s2 = New-Object byte[] ($n - $ihl); [Array]::Copy($data, $ihl, $s2, 0, ($n - $ihl)); $data = $s2 }
  }
  if ($data.Length -lt 21) { continue }
  if ($data[8] -ne 0x56 -or $data[9] -ne 0x43) { continue }
  $seen++
  $out += ('F t' + [int]$data[0] + ' s' + (([int]$data[6] * 256) + [int]$data[7]) + ' l' + ($data.Length - 21))
}
Write-Host ('DONE seen=' + $seen + ' ' + ($out -join ' '))
