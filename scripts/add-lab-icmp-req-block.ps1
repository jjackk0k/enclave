# add-lab-icmp-req-block.ps1 - BLOCK inbound ICMPv4 echo REQUESTS (type 8) from the lab
# net. Purpose: stop the host KERNEL from auto-answering the VARVEL agent's solicitation
# probes, so the guest-side echo state survives until the channel's type-0 reply arrives
# (the only reply shape Windows delivers to a raw socket - range matrix proven).
# Block rules take precedence over the existing 'VARVEL lab ICMP in' allow; type-0
# agent pulls are unaffected. Reversible:
#   netsh advfirewall firewall delete rule name="VARVEL lab ICMP req block"
netsh advfirewall firewall add rule name="VARVEL lab ICMP req block" dir=in action=block protocol=icmpv4:8,any remoteip=192.168.50.0/24
