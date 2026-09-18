# icmp-host-listen.ps1 - host-side RCVALL listener: logs every VC frame arriving at
# 192.168.50.1 (kind/seq/dlen/src) for ListenMs, to a file. Used to count how many
# frames of a multi-frame ICMP push actually cross the wire. PURE ASCII ONLY.
param([int]$ListenMs = 60000, [string]$LogPath = 'C:\Users\Jack\AppData\Local\Temp\icmp-host-listen.log')
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -Path $LogPath -Value $m -Encoding Ascii }
try {
  $s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]::Icmp)
  $s.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse('192.168.50.1'), 0)))
  $s.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll, [byte[]](1, 0, 0, 0), $null)
  $s.ReceiveTimeout = 1000
} catch { Log ('SOCK-FAIL: ' + $_.Exception.Message); exit 1 }
Log 'LISTEN-START'
$sw = [Diagnostics.Stopwatch]::StartNew()
$seen = 0
while ($sw.ElapsedMilliseconds -lt $ListenMs) {
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
  Log ('F t' + [int]$data[0] + ' k' + $kind + ' s' + $seq32 + ' l' + ($data.Length - 21) + ' ' + $remote.Address.ToString())
}
Log ('LISTEN-DONE seen=' + $seen)
