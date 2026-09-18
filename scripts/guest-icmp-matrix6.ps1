# guest-icmp-matrix6.ps1 - passive RCVALL listener with DIRECTION: logs every VC frame
# with src (.130 = outbound guest frames, .1 = INBOUND channel frames). 20s window.
# Run while a live icmp agent pulls with a task queued: if no src=.1 frames appear,
# the channel's reply never reaches the guest NIC (host-side send path is the bug).
# PURE ASCII ONLY.
$ErrorActionPreference = 'Stop'
try {
  $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]::Icmp)
  $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('192.168.50.130'), 0)))
  $s.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll, [byte[]](1, 0, 0, 0), $null)
  $s.ReceiveTimeout = 1000
} catch { Write-Host ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0; $lines = @()
while ($sw.ElapsedMilliseconds -lt 20000) {
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
  $kind = [int]$data[10]
  $seq32 = ([int64]$data[11] * 16777216) + ([int64]$data[12] * 65536) + ([int64]$data[13] * 256) + [int64]$data[14]
  $lines += ('t' + [int]$data[0] + ' k' + $kind + ' s' + $seq32 + ' l' + ($data.Length - 21) + ' ' + $remote.Address.ToString())
}
Write-Host ('DONE seen=' + $seen + ' | ' + ($lines -join ' | '))
