# VARVEL tunnel-keeper — keeps the Spark brain-lane tunnel (127.0.0.1:8080) alive.
# Loop: probe the lane; if it doesn't answer AND no tunnel ssh is running, open one hidden.
# Survives wifi blips: when the network returns, the next probe cycle re-opens the tunnel.
$ErrorActionPreference = "SilentlyContinue"
while ($true) {
  $code = & curl.exe -s -o NUL -m 5 -w "%{http_code}" http://127.0.0.1:8080/v1/models
  if ($code -eq "000") {
    $existing = Get-CimInstance Win32_Process | Where-Object {
      $_.Name -match '^ssh' -and $_.CommandLine -match '-L\s+8080|8080:127\.0\.0\.1:8080' }
    if (-not $existing) {
      Start-Process -WindowStyle Hidden -FilePath "ssh.exe" -ArgumentList @(
        "-o","BatchMode=yes","-o","ConnectTimeout=10",
        "-o","ServerAliveInterval=15","-o","ServerAliveCountMax=3",
        "-o","ExitOnForwardFailure=yes",
        "-N","-L","8080:127.0.0.1:8080","varvel@gx10-d094.local")
    }
  }
  Start-Sleep -Seconds 20
}
