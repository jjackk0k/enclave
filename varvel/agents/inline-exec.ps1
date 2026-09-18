# VARVEL - inline-dotnet PowerShell helper (the in-memory execution tier, gap #4 remainder).
#
# Spawned by the Node agent (agents/inlineexec.mjs) as:
#   powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File inline-exec.ps1
# with ONE JSON job on STDIN:  {"assemblyB64":"<base64>","args":["..."],"entryPoint":""}
#
# What this does: decodes the assembly IN MEMORY, loads it into THIS process with
# [Reflection.Assembly]::Load(byte[]), invokes the entry point with console capture, and
# writes ONE JSON result line to stdout: {"exitCode","timedOut","stdout","stderr"}.
#
# HARD DOCTRINE (absolute, the operator's standing rule): NO EVASION.
#   - The bytes NEVER touch disk: they arrive on stdin, live as a byte[], and are loaded
#     from that byte[]. Nothing here writes a file.
#   - Nothing here patches or dodges AMSI/ETW. On Win10+ AMSI scans the byte[] load -
#     that scan is the DETECTION SURFACE the platform's detoracle measures. So be it.
#   - Own-process only: the assembly runs in THIS helper process; there is no injection
#     into any other process, ever.
#
# Timeout lives on the NODE side (it kills this process tree after HELPER_TIMEOUT_MS);
# this script itself runs the invoke synchronously - a helper cannot kill itself cleanly
# mid-invoke, and a wedge must never be silent (the node side reports timedOut loudly).
#
# NOTE: this file is PURE ASCII by necessity - PS 5.1 decodes a BOM-less .ps1 as ANSI,
# and a UTF-8 em-dash's 0x94 byte becomes a smart-quote that TERMINATES strings early
# (that exact parse break shipped here once and was range-proven fixed).

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

$CAP = 1048576  # 1 MiB - mirrors engine/inlineexec.mjs MAX_INLINE_ASSEMBLY_BYTES (defense in depth)

function Send-Result($Obj) {
  # Exactly ONE JSON line on the real stdout - the node runner parses the last JSON line.
  [Console]::Out.WriteLine(($Obj | ConvertTo-Json -Compress))
}

$jobRaw = [Console]::In.ReadToEnd()
try { $job = $jobRaw | ConvertFrom-Json } catch { Send-Result ([ordered]@{ exitCode = -1; timedOut = $false; stdout = ''; stderr = 'job JSON unparseable: ' + $_.Exception.Message }); exit 0 }

$bytes = $null
try { $bytes = [Convert]::FromBase64String([string]$job.assemblyB64) } catch { Send-Result ([ordered]@{ exitCode = -1; timedOut = $false; stdout = ''; stderr = 'assemblyB64 is not valid base64 - nothing executed' }); exit 0 }
if ($bytes.Length -eq 0) { Send-Result ([ordered]@{ exitCode = -1; timedOut = $false; stdout = ''; stderr = 'assembly decoded to zero bytes - nothing executed' }); exit 0 }
if ($bytes.Length -gt $CAP) { Send-Result ([ordered]@{ exitCode = -1; timedOut = $false; stdout = ''; stderr = "assembly is $($bytes.Length) bytes - over the $CAP-byte cap (nothing executed)" }); exit 0 }

$asmArgs = @()
if ($job.args) { $asmArgs = @($job.args | ForEach-Object { [string]$_ }) }
$epName = ''
if ($job.entryPoint) { $epName = [string]$job.entryPoint }

# Console capture around the invoke ONLY - our own result line goes to the real stdout.
$outW = New-Object System.IO.StringWriter
$errW = New-Object System.IO.StringWriter
$oldOut = [Console]::Out
$oldErr = [Console]::Error
$code = 0
[Console]::SetOut($outW)
[Console]::SetError($errW)
try {
  $asm = [Reflection.Assembly]::Load($bytes)   # in-memory load; AMSI may scan - by design
  $entry = $asm.EntryPoint
  if ($epName.Length -gt 0) {
    # Override shape: 'Namespace.Type.Method' - a STATIC method taking string[] or nothing.
    $i = $epName.LastIndexOf('.')
    if ($i -lt 1) { throw "entryPoint override must be 'Namespace.Type.Method' (got '$epName')" }
    $t = $asm.GetType($epName.Substring(0, $i))
    if ($null -eq $t) { throw "type not found in assembly: $($epName.Substring(0, $i))" }
    $entry = $t.GetMethod($epName.Substring($i + 1), [Reflection.BindingFlags]('Public,NonPublic,Static'))
  }
  if ($null -eq $entry) { throw 'no entry point: the assembly has no EntryPoint and no valid override was given' }
  $r = $null
  if ($entry.GetParameters().Count -gt 0) { $r = $entry.Invoke($null, @(, [string[]]$asmArgs)) } else { $r = $entry.Invoke($null, $null) }
  if ($r -is [int]) { $code = [int]$r }
} catch {
  [Console]::Error.WriteLine($_.Exception.ToString())
  $code = -1
} finally {
  [Console]::SetOut($oldOut)
  [Console]::SetError($oldErr)
}

$stdout = $outW.ToString()
$stderr = $errW.ToString()
if ($stdout.Length -gt 200000) { $stdout = $stdout.Substring(0, 200000) + "`n[truncated at 200000 chars]" }
if ($stderr.Length -gt 60000) { $stderr = $stderr.Substring(0, 60000) + "`n[truncated at 60000 chars]" }
Send-Result ([ordered]@{ exitCode = $code; timedOut = $false; stdout = $stdout; stderr = $stderr })
exit 0
