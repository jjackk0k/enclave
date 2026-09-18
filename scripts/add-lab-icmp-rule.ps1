# add-lab-icmp-rule.ps1 — ONE-TIME elevated host change, run via UAC (Start-Process -Verb RunAs).
# The range's ICMP transport needs UNSOLICITED inbound ICMP (agent frames) to reach the
# channel host's raw sockets; Windows Firewall's default public profile drops all of it
# (proven: guest type-8 ping times out, guest type-0 frames never arrive). This rule is
# deliberately NARROW: ICMPv4 in, from the sealed lab subnet ONLY (192.168.50.0/24).
# Reversible: netsh advfirewall firewall delete rule name="VARVEL lab ICMP in"
$ruleName = 'VARVEL lab ICMP in'
$proof = Join-Path $env:TEMP 'varvel-fw-rule.txt'
try {
  netsh advfirewall firewall delete rule name="$ruleName" 2>$null | Out-Null   # idempotent re-run
  $r = netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=icmpv4:any,any remoteip=192.168.50.0/24
  $show = netsh advfirewall firewall show rule name="$ruleName"
  "ADDED: $r`n$show" | Out-File -Encoding utf8 $proof
} catch {
  "FAILED: $($_.Exception.Message)" | Out-File -Encoding utf8 $proof
}
