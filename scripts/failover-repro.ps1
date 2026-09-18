# failover-repro.ps1 — one-shot: dot-source the agent with the crashing args and print the
# full error position + stack (bash mangles $_ inline, so this lives in a file - lesson 18).
try {
  . 'C:\Users\Jack\Downloads\enclave\varvel\agents\varvel-agent.ps1' -Url 'http://192.168.50.1:49999' -DnsPort 5335 -Transports 'http,dns' -FailAfter 3 -AgentId deadbeef0000 -Token 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef -MaxLoops 8 -Interval 300 -Jitter 50 -Sandbox 'C:\Windows\Temp\failover-repro'
} catch {
  Write-Output ('POSITION: ' + $_.InvocationInfo.PositionMessage)
  Write-Output ('STACK: ' + $_.ScriptStackTrace)
}
