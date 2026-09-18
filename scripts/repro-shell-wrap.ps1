# repro-shell-wrap.ps1 — reproduces the EXACT wrapper varvel-agent.ps1's Invoke-Task
# uses for 'shell' tasks, to pin where backslashes in a task's command get mangled.
$Task = @{ data = 'powershell -NoProfile -ExecutionPolicy Bypass -File C:\Windows\System32\agentbox\varvel-agent.ps1 -Url icmp://192.168.50.1 -AgentId x -Token y -Transport icmp -MaxLoops 1' }
Write-Host ('TASKDATA: ' + $Task.data)
$out = cmd /c "$($Task.data) 2>&1" | Out-String
Write-Host ('OUTPUT: ' + $out.Trim())
