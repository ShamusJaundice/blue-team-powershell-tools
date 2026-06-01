#Requires -Version 2.0

<#
.SYNOPSIS
    OS-aware SMB security auditor and remediator for Windows.

.DESCRIPTION
    Detects the Windows version and PowerShell capabilities of the host, then runs
    the correct set of SMB security checks for that specific OS. SMB capabilities and
    the cmdlets used to inspect/configure them differ significantly across Windows
    versions, so the script branches on the detected OS instead of assuming modern
    cmdlets exist.

    Flow: scan first, report, ask for confirmation, then remediate. Nothing is ever
    fixed silently — every remediation re-runs its check to verify it actually worked.

.PARAMETER AuditOnly
    Scan and report only. Skip Region 4 (remediation) entirely.

.PARAMETER AutoConfirm
    Apply remediations without the interactive confirmation prompt. Intended for
    automation/scheduled runs. Use with care — this changes system configuration.

.PARAMETER ReportPath
    Directory to write the timestamped text report into. Defaults to the script folder.

.EXAMPLE
    .\Invoke-SMBHardener.ps1

.EXAMPLE
    .\Invoke-SMBHardener.ps1 -AuditOnly

.NOTES
    Must be run from an elevated (Administrator) session.
    Designed to degrade gracefully from Windows 11 / PowerShell 7 down to
    Windows 7 / PowerShell 2, where modern Smb*/Net* cmdlets do not exist.
#>
param(
    [switch]$AuditOnly,
    [switch]$AutoConfirm,
    [string]$ReportPath
)

# ── GUARD: must be elevated ────────────────────────────────────────────────────
# Note: we do NOT use `#Requires -RunAsAdministrator` because that directive only
# exists on PowerShell 4+. This WindowsPrincipal check works all the way back to PS2.
$CurrentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal($CurrentIdentity)
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run from an elevated (Administrator) session. Exiting."
    exit 1
}

# $PSScriptRoot is only auto-populated inside scripts on PS3+. Derive the folder from
# $MyInvocation so Region 5's report path works on PS2 as well.
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

#region Region 1 — OS Detection
Write-Host "=== Invoke-SMBHardener ===" -ForegroundColor Cyan
Write-Host "Detecting host OS and PowerShell capabilities..." -ForegroundColor Cyan
Write-Host ""

# ── Raw version inputs ─────────────────────────────────────────────────────────
# [Environment]::OSVersion.Version is available on every PowerShell version. On modern
# .NET (PowerShell 7) it reports the true build; on older .NET Framework it can be
# capped at 6.2 for unmanifested apps, so we treat the WMI/CIM build as authoritative
# and only fall back to this if neither is available.
$OSVersion = [System.Environment]::OSVersion.Version
$PSMajor   = $PSVersionTable.PSVersion.Major

# ── Capability flags ───────────────────────────────────────────────────────────
# These booleans are the whole point of Region 1: later regions branch on them
# instead of re-checking the OS each time. A cmdlet is "available" only if Get-Command
# can find it on this host.
#
# NOTE ON Get-WmiObject vs Get-CimInstance:
#   The original design called for Get-WmiObject to read the build number. But
#   Get-WmiObject was REMOVED in PowerShell 7 (your likely Win11 shell), while the
#   newer Get-CimInstance does not exist on PowerShell 2 (Win7). Since OS/cmdlet
#   awareness is the entire premise of this tool, we detect which is present and pick
#   accordingly, falling back to the registry/Environment if neither exists.
$HasCimInstance         = [bool](Get-Command Get-CimInstance            -ErrorAction SilentlyContinue)
$HasGetWmiObject        = [bool](Get-Command Get-WmiObject              -ErrorAction SilentlyContinue)
$HasSmbCmdlets          = [bool](Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue)
$HasNetFirewallCmdlets  = [bool](Get-Command Get-NetFirewallRule        -ErrorAction SilentlyContinue)

# ── Authoritative OS query (build + friendly caption) ──────────────────────────
$OSInfo = $null
if ($HasCimInstance) {
    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
}
elseif ($HasGetWmiObject) {
    $OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue
}

if ($OSInfo) {
    $Build       = [int]$OSInfo.BuildNumber
    $Caption     = $OSInfo.Caption
    $ProductType = [int]$OSInfo.ProductType   # 1 = workstation, 2 = domain controller, 3 = server
}
else {
    # Last-resort fallback: registry build number is reliable on every Windows version.
    $RegCV = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    try   { $Build = [int](Get-ItemProperty -Path $RegCV -Name CurrentBuildNumber -ErrorAction Stop).CurrentBuildNumber }
    catch { $Build = [int]$OSVersion.Build }
    $Caption     = "Unknown (no WMI/CIM available)"
    $ProductType = 1
}

$IsServer = ($ProductType -ne 1)

# ── Classify the OS family from the build number ───────────────────────────────
# Build numbers are the most reliable discriminator. Version numbers lie (Win10 and
# Win11 both report major version 10); builds do not.
if     ($Build -ge 22000) { $OSName = 'Windows 11';        $OSFamily = 'Win11' }
elseif ($Build -ge 10240) { $OSName = 'Windows 10';        $OSFamily = 'Win10' }
elseif ($Build -eq 9600)  { $OSName = 'Windows 8.1';       $OSFamily = 'Win81' }
elseif ($Build -eq 9200)  { $OSName = 'Windows 8';         $OSFamily = 'Win8'  }
elseif ($Build -ge 7600)  { $OSName = 'Windows 7';         $OSFamily = 'Win7'  }
else                      { $OSName = 'Legacy/Unknown';    $OSFamily = 'Legacy' }

# ── SMBGhost (CVE-2020-0796) applies ONLY to Win10 builds 18362 and 18363 ──────
# The vulnerable SMBv3.1.1 compression code shipped only in those two feature updates
# (1903 / 1909). Flagging it here keeps Region 2's scanner declarative.
$IsSmbGhostCandidate = ($Build -eq 18362 -or $Build -eq 18363)

# ── Report what we detected ────────────────────────────────────────────────────
Write-Host "  Detected OS    : $OSName  (build $Build)" -ForegroundColor White
Write-Host "  Caption        : $Caption"
Write-Host "  OS version     : $($OSVersion.ToString())"
Write-Host "  Role           : $(if ($IsServer) { 'Server / Domain Controller' } else { 'Workstation' })"
Write-Host "  PowerShell     : $($PSVersionTable.PSVersion.ToString())  (major $PSMajor)"
Write-Host ""
Write-Host "  Capability flags:" -ForegroundColor White
Write-Host "    Get-CimInstance available           : $HasCimInstance"
Write-Host "    Get-WmiObject available             : $HasGetWmiObject"
Write-Host "    SMB cmdlets (Get-SmbServerConfig)   : $HasSmbCmdlets"
Write-Host "    Firewall cmdlets (Get-NetFirewall)  : $HasNetFirewallCmdlets"
Write-Host ""
Write-Host "  Vulnerability applicability:" -ForegroundColor White
Write-Host "    SMBGhost (CVE-2020-0796) candidate  : $IsSmbGhostCandidate"
Write-Host ""

if ($OSFamily -eq 'Legacy') {
    Write-Warning "Unrecognised/legacy build ($Build). Checks will run best-effort via registry."
}
if (-not $HasSmbCmdlets) {
    Write-Host "  -> SMB cmdlets absent: SMB checks will use the registry/WMI fallback path." -ForegroundColor DarkYellow
}
Write-Host ""
#endregion

#region Region 2 — Scanner
# Each vulnerability is a small Test-* function that returns ONE finding object when the
# system is non-compliant, or $null when it's OK or not applicable to this OS/build.
# This shape matters for Region 4: to verify a remediation, we just call the same
# Test-* function again and check whether it still returns a finding.
#
# The functions read the Region 1 capability flags ($HasSmbCmdlets, $HasCimInstance,
# $Build, $IsSmbGhostCandidate, …) directly. PowerShell's scoping lets a function read
# variables from the script scope that called it, so we don't thread them through params.

# ── Registry locations these checks touch ─────────────────────────────────────
$LanmanParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$LsaPath      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

# ── Helpers ────────────────────────────────────────────────────────────────────
# Read a single registry value, returning $null if the value (or key) does not exist.
# This lets a check distinguish "set to 0" from "never configured", which matters:
# for several settings a missing value means the insecure OS default is in effect.
function Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch { return $null }
}

# Build a finding. Plain New-Object PSObject (not the [PSCustomObject] accelerator) so
# the script still parses on PowerShell 2; Region 3 selects explicit columns, so the
# hashtable's lack of ordering on PS2 is irrelevant.
function New-Finding {
    param(
        [string]$VulnName,
        [string]$Severity,
        [string]$CurrentState,
        [string]$RecommendedFix,
        [bool]  $CanAutoRemediate
    )
    New-Object PSObject -Property @{
        VulnName         = $VulnName
        Severity         = $Severity
        CurrentState     = $CurrentState
        RecommendedFix   = $RecommendedFix
        CanAutoRemediate = $CanAutoRemediate
    }
}

# ── Check 1: SMB1 protocol (Critical, all versions) ────────────────────────────
function Test-Smb1 {
    Write-Host -NoNewline "  [1] SMB1 protocol            ... "
    $enabled = $null
    if ($HasSmbCmdlets) {
        try { $enabled = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $enabled = $null }
    }
    if ($null -eq $enabled) {
        # Registry fallback (Win7 / no cmdlets). A MISSING SMB1 value means enabled,
        # because legacy Windows ships SMB1 on by default.
        $reg = Get-RegValue $LanmanParams 'SMB1'
        if ($null -eq $reg) { $enabled = $true } else { $enabled = ($reg -ne 0) }
    }
    if ($enabled) {
        Write-Host "VULNERABLE" -ForegroundColor Red
        return New-Finding 'SMB1 protocol enabled' 'Critical' `
            'SMB1/SMBv1 is enabled. SMB1 is obsolete and is the vector exploited by EternalBlue/WannaCry.' `
            'Disable SMB1: Set-SmbServerConfiguration -EnableSMB1Protocol $false (or registry SMB1=0).' `
            $true
    }
    Write-Host "OK" -ForegroundColor Green
    return $null
}

# ── Check 2: SMBGhost / CVE-2020-0796 (Critical, ONLY Win10 builds 18362/18363) ─
function Test-SmbGhost {
    Write-Host -NoNewline "  [2] SMBGhost (CVE-2020-0796) ... "
    if (-not $IsSmbGhostCandidate) {
        Write-Host "N/A (build not affected)" -ForegroundColor DarkGray
        return $null
    }
    # Vulnerable unless SMBv3.1.1 compression is explicitly disabled (DisableCompression=1).
    $disableComp = Get-RegValue $LanmanParams 'DisableCompression'
    if ($disableComp -eq 1) {
        Write-Host "OK (compression disabled)" -ForegroundColor Green
        return $null
    }
    Write-Host "VULNERABLE" -ForegroundColor Red
    return New-Finding 'SMBGhost (CVE-2020-0796)' 'Critical' `
        "SMBv3.1.1 compression is enabled on vulnerable build $Build — wormable pre-auth RCE." `
        'Set DisableCompression=1 under LanmanServer\Parameters (mitigation, no reboot required).' `
        $true
}

# ── Check 3: Null session access (High, all versions) ──────────────────────────
function Test-NullSessions {
    Write-Host -NoNewline "  [3] Null sessions            ... "
    $restrict = Get-RegValue $LanmanParams 'RestrictNullSessAccess'
    $pipes    = Get-RegValue $LanmanParams 'NullSessionPipes'
    $shares   = Get-RegValue $LanmanParams 'NullSessionShares'

    $bad = $false
    if ($restrict -ne 1) { $bad = $true }   # missing or 0 => anonymous (null) sessions permitted
    if ($pipes  -and (@($pipes  | Where-Object { $_ -ne '' }).Count -gt 0)) { $bad = $true }
    if ($shares -and (@($shares | Where-Object { $_ -ne '' }).Count -gt 0)) { $bad = $true }

    if ($bad) {
        Write-Host "VULNERABLE" -ForegroundColor Red
        $r = if ($null -eq $restrict) { 'not set' } else { $restrict }
        return New-Finding 'Null session access permitted' 'High' `
            "RestrictNullSessAccess=$r; NullSessionPipes/Shares may permit anonymous SMB connections." `
            'Set RestrictNullSessAccess=1 and clear NullSessionPipes / NullSessionShares.' `
            $true
    }
    Write-Host "OK" -ForegroundColor Green
    return $null
}

# ── Check 4: SMB signing required (High, all versions) ─────────────────────────
function Test-SmbSigning {
    Write-Host -NoNewline "  [4] SMB signing required     ... "
    $required = $null
    if ($HasSmbCmdlets) {
        try { $required = [bool](Get-SmbServerConfiguration -ErrorAction Stop).RequireSecuritySignature } catch { $required = $null }
    }
    if ($null -eq $required) {
        $reg = Get-RegValue $LanmanParams 'RequireSecuritySignature'
        if ($null -ne $reg) { $required = ($reg -eq 1) } else { $required = $false }
    }
    if (-not $required) {
        Write-Host "VULNERABLE" -ForegroundColor Red
        return New-Finding 'SMB signing not required' 'High' `
            'The SMB server does not require packet signing; exposes sessions to relay/MITM tampering.' `
            'Require signing: Set-SmbServerConfiguration -RequireSecuritySignature $true (or registry=1).' `
            $true
    }
    Write-Host "OK" -ForegroundColor Green
    return $null
}

# ── Check 5: Guest account enabled (Medium, all versions) ──────────────────────
function Test-GuestAccount {
    Write-Host -NoNewline "  [5] Guest account            ... "
    $active = $null
    $guest  = $null
    # Prefer the well-known Guest SID (...-501): locale-independent, unlike parsing net.exe.
    if ($HasCimInstance) {
        try { $guest = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction Stop } catch {}
    }
    elseif ($HasGetWmiObject) {
        try { $guest = Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-501'" -ErrorAction Stop } catch {}
    }
    if ($guest) {
        $active = (-not $guest.Disabled)
    }
    else {
        # Last resort: parse `net user guest` (English-locale dependent).
        $out  = net user guest 2>$null
        $line = $out | Where-Object { $_ -match 'Account active' }
        if ($line) { $active = ($line -match 'Yes') }
    }
    if ($active -eq $true) {
        Write-Host "VULNERABLE" -ForegroundColor Red
        return New-Finding 'Guest account enabled' 'Medium' `
            'The built-in Guest account is active, enabling unauthenticated local/SMB access.' `
            'Disable Guest: net user guest /active:no (or Disable-LocalUser -Name Guest).' `
            $true
    }
    Write-Host "OK" -ForegroundColor Green
    return $null
}

# ── Check 6: NTLMv1 / LM weak authentication (High, all versions) ──────────────
function Test-Ntlmv1 {
    Write-Host -NoNewline "  [6] NTLMv1 / LM auth         ... "
    # Want LmCompatibilityLevel=5 (send NTLMv2 only; refuse LM & NTLM). A missing value
    # falls back to the OS default (3 on modern Windows) which still permits NTLMv1.
    $level = Get-RegValue $LsaPath 'LmCompatibilityLevel'
    if ($level -eq 5) {
        Write-Host "OK" -ForegroundColor Green
        return $null
    }
    $state = if ($null -eq $level) { 'not set (effective OS default 3)' } else { "set to $level" }
    Write-Host "VULNERABLE" -ForegroundColor Red
    return New-Finding 'Weak NTLM / LM authentication' 'High' `
        "LmCompatibilityLevel is $state; levels below 5 allow NTLMv1/LM responses to be sent." `
        'Set LmCompatibilityLevel=5 (NTLMv2 only). Note: can break very old/legacy clients.' `
        $true
}

# ── Check 7: Port 445 firewall exposure (Medium) ───────────────────────────────
# Not auto-remediated: blocking 445 is environment-specific and can break legitimate
# file sharing, so this surfaces for manual review with the exact command to run.
function Test-Port445Firewall {
    Write-Host -NoNewline "  [7] Port 445 firewall        ... "
    if ($HasNetFirewallCmdlets) {
        try {
            $exposed = @()
            $portFilters = Get-NetFirewallPortFilter -ErrorAction Stop |
                Where-Object { $_.Protocol -eq 'TCP' -and ($_.LocalPort -eq '445' -or $_.LocalPort -contains '445') }
            foreach ($pf in $portFilters) {
                foreach ($r in ($pf | Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
                    if ("$($r.Enabled)" -eq 'True' -and "$($r.Direction)" -eq 'Inbound' -and
                        "$($r.Action)" -eq 'Allow' -and ("$($r.Profile)" -match 'Public|Any')) {
                        $exposed += $r.DisplayName
                    }
                }
            }
            if ($exposed.Count -gt 0) {
                Write-Host "REVIEW" -ForegroundColor Yellow
                return New-Finding 'SMB (TCP 445) exposed on Public/Any profile' 'Medium' `
                    ('Enabled inbound Allow rule(s) for TCP/445 on Public/Any: ' + (($exposed | Select-Object -Unique) -join ', ')) `
                    'Restrict inbound 445 to Domain/Private; block on Public. Verify before changing — may break file sharing.' `
                    $false
            }
            Write-Host "OK" -ForegroundColor Green
            return $null
        }
        catch {
            Write-Host "REVIEW (query failed)" -ForegroundColor Yellow
            return New-Finding 'Port 445 firewall state unknown' 'Medium' `
                "Could not query firewall rules: $($_.Exception.Message)" `
                'Manually confirm inbound TCP/445 is blocked on untrusted (Public) networks.' `
                $false
        }
    }
    # Legacy fallback (no NetSecurity cmdlets): cannot reliably parse — flag for manual review.
    Write-Host "REVIEW (manual)" -ForegroundColor Yellow
    return New-Finding 'Port 445 firewall (manual review)' 'Medium' `
        'Firewall cmdlets are unavailable on this OS; TCP/445 exposure could not be auto-assessed.' `
        'Use netsh advfirewall to confirm inbound TCP/445 is blocked on public networks.' `
        $false
}

# ── Check 8: Anonymous enumeration (Medium, all versions) ──────────────────────
function Test-AnonymousEnum {
    Write-Host -NoNewline "  [8] Anonymous enumeration    ... "
    $ra    = Get-RegValue $LsaPath 'RestrictAnonymous'
    $raSam = Get-RegValue $LsaPath 'RestrictAnonymousSAM'
    if ($ra -eq 1) {
        Write-Host "OK" -ForegroundColor Green
        return $null
    }
    $state    = if ($null -eq $ra)    { 'not set' } else { "set to $ra" }
    $samState = if ($null -eq $raSam) { 'not set' } else { $raSam }
    Write-Host "VULNERABLE" -ForegroundColor Red
    return New-Finding 'Anonymous share/account enumeration allowed' 'Medium' `
        "RestrictAnonymous is $state (RestrictAnonymousSAM=$samState); anonymous users may enumerate shares/accounts." `
        'Set RestrictAnonymous=1 and RestrictAnonymousSAM=1 under Control\Lsa.' `
        $true
}

# ── Run every applicable check, in order, collecting non-null findings ─────────
Write-Host "Scanning for SMB vulnerabilities on $OSName ..." -ForegroundColor Cyan
Write-Host ""

$Findings = @()
foreach ($result in @(
    (Test-Smb1),
    (Test-SmbGhost),
    (Test-NullSessions),
    (Test-SmbSigning),
    (Test-GuestAccount),
    (Test-Ntlmv1),
    (Test-Port445Firewall),
    (Test-AnonymousEnum)
)) {
    if ($result) { $Findings += $result }
}

Write-Host ""
Write-Host "Scan complete: $($Findings.Count) issue(s) found." -ForegroundColor Cyan
Write-Host ""
#endregion

#region Region 3 — Report
# Read-only: present what Region 2 found. Nothing is changed here. We sort by severity
# (Critical first) so the most urgent issues are at the top of both the console and the
# saved report, and we surface per-severity counts for an at-a-glance posture summary.

# Lower rank = more severe; used as the Sort-Object key. Kept in script scope so Region 5
# can reuse it when it re-renders the findings into the saved report.
$SeverityRank = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }

# Console colour for a severity label.
function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'Red' }
        'Medium'   { 'Yellow' }
        default    { 'Gray' }
    }
}

Write-Host "================= SMB Audit Report =================" -ForegroundColor Cyan
Write-Host "  Host : $Caption"
Write-Host "  OS   : $OSName (build $Build)"
Write-Host "  Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

if ($Findings.Count -eq 0) {
    Write-Host "  No SMB misconfigurations detected — host is compliant with all" -ForegroundColor Green
    Write-Host "  applicable checks for this OS." -ForegroundColor Green
    Write-Host ""
    # Leave $SortedFindings defined (empty) so later regions can rely on it existing.
    $SortedFindings = @()
}
else {
    # Per-severity counts. Scriptblock Where-Object (not the PS3+ simplified syntax) keeps
    # this parseable on PowerShell 2.
    $countCritical = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $countHigh     = @($Findings | Where-Object { $_.Severity -eq 'High'     }).Count
    $countMedium   = @($Findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
    $countLow      = @($Findings | Where-Object { $_.Severity -eq 'Low'      }).Count

    Write-Host "  Findings by severity:" -ForegroundColor White
    Write-Host "    Critical : $countCritical" -ForegroundColor Red
    Write-Host "    High     : $countHigh"     -ForegroundColor Red
    Write-Host "    Medium   : $countMedium"   -ForegroundColor Yellow
    Write-Host "    Low      : $countLow"      -ForegroundColor Gray
    Write-Host ""

    # Explicit hashtable sort keys: the @(scriptblock, string) shorthand is unreliable
    # on PowerShell 2, so spell out each key the way the rest of this script does.
    $SortedFindings = $Findings | Sort-Object @(
        @{ Expression = { $SeverityRank[$_.Severity] }; Ascending = $true },
        @{ Expression = 'VulnName';                     Ascending = $true }
    )

    # At-a-glance table.
    Write-Host ("  {0,-3} {1,-9} {2,-46} {3}" -f '#', 'Severity', 'Vulnerability', 'Auto-fix') -ForegroundColor White
    Write-Host ("  {0,-3} {1,-9} {2,-46} {3}" -f '---', '--------', '---------------------------------------------', '--------')
    $idx = 0
    foreach ($f in $SortedFindings) {
        $idx++
        $auto = if ($f.CanAutoRemediate) { 'yes' } else { 'no' }
        Write-Host ("  {0,-3} {1,-9} {2,-46} {3}" -f $idx, $f.Severity, $f.VulnName, $auto) -ForegroundColor (Get-SeverityColor $f.Severity)
    }
    Write-Host ""

    # Detail block per finding.
    $idx = 0
    foreach ($f in $SortedFindings) {
        $idx++
        $color = Get-SeverityColor $f.Severity
        Write-Host ("  [{0}] {1}  ({2})" -f $idx, $f.VulnName, $f.Severity) -ForegroundColor $color
        Write-Host ("      Current state   : {0}" -f $f.CurrentState)
        Write-Host ("      Recommended fix : {0}" -f $f.RecommendedFix)
        Write-Host ("      Auto-remediable : {0}" -f $(if ($f.CanAutoRemediate) { 'yes' } else { 'no — manual review required' }))
        Write-Host ""
    }
}

Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""
#endregion

#region Region 4 — Remediation
# Scan -> report -> CONFIRM -> remediate. Nothing here runs without either an explicit
# typed confirmation or the -AutoConfirm switch. Every fix is verified by re-running the
# same Region 2 Test-* function: if it no longer returns a finding, the fix took.

# Write a registry value, creating the key path if it does not yet exist. Counterpart to
# Get-RegValue. -Force on New-ItemProperty overwrites an existing value of any type.
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
}

# VulnName -> how to fix it, how to verify it, and whether a reboot is needed to fully
# apply. Verify scriptblocks reuse the Region 2 checks verbatim. Repair scriptblocks read
# the Region 1 capability flags / path variables from script scope, preferring cmdlets
# when present and falling back to the registry otherwise.
$RemediationRegistry = @{
    'SMB1 protocol enabled' = @{
        Reboot = $true   # recommended, to fully unload the SMB1 driver
        Repair = {
            if ($HasSmbCmdlets) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop }
            else                { Set-RegValue $LanmanParams 'SMB1' 0 'DWord' }
        }
        Verify = { Test-Smb1 }
    }
    'SMBGhost (CVE-2020-0796)' = @{
        Reboot = $false  # mitigation is effective immediately per MS advisory
        Repair = { Set-RegValue $LanmanParams 'DisableCompression' 1 'DWord' }
        Verify = { Test-SmbGhost }
    }
    'Null session access permitted' = @{
        Reboot = $true   # Server service restart / reboot to take effect
        Repair = {
            Set-RegValue $LanmanParams 'RestrictNullSessAccess' 1 'DWord'
            Set-RegValue $LanmanParams 'NullSessionPipes'  ([string[]]@('')) 'MultiString'
            Set-RegValue $LanmanParams 'NullSessionShares' ([string[]]@('')) 'MultiString'
        }
        Verify = { Test-NullSessions }
    }
    'SMB signing not required' = @{
        Reboot = $false  # applies to new connections immediately
        Repair = {
            if ($HasSmbCmdlets) { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force -ErrorAction Stop }
            else                { Set-RegValue $LanmanParams 'RequireSecuritySignature' 1 'DWord' }
        }
        Verify = { Test-SmbSigning }
    }
    'Guest account enabled' = @{
        Reboot = $false
        Repair = {
            if (Get-Command Disable-LocalUser -ErrorAction SilentlyContinue) {
                Disable-LocalUser -Name 'Guest' -ErrorAction Stop
            }
            else {
                # net.exe returns non-zero on failure; surface that as a terminating error.
                net user guest /active:no | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "net user guest /active:no failed (exit $LASTEXITCODE)" }
            }
        }
        Verify = { Test-GuestAccount }
    }
    'Weak NTLM / LM authentication' = @{
        Reboot = $true   # LmCompatibilityLevel changes apply fully after reboot
        Repair = { Set-RegValue $LsaPath 'LmCompatibilityLevel' 5 'DWord' }
        Verify = { Test-Ntlmv1 }
    }
    'Anonymous share/account enumeration allowed' = @{
        Reboot = $true   # Lsa changes apply fully after reboot
        Repair = {
            Set-RegValue $LsaPath 'RestrictAnonymous'    1 'DWord'
            Set-RegValue $LsaPath 'RestrictAnonymousSAM' 1 'DWord'
        }
        Verify = { Test-AnonymousEnum }
    }
}

# Remediation outcome tracking, consumed by Region 5's saved report. Initialised up
# front so the variables always exist regardless of which branch below runs.
$RemediationStatus = 'Not run.'
$FixedItems        = @()
$UnfixedItems      = @()

if ($AuditOnly) {
    Write-Host "-AuditOnly specified: skipping remediation (Region 4)." -ForegroundColor DarkYellow
    Write-Host ""
    $RemediationStatus = 'Skipped — script run with -AuditOnly.'
}
elseif ($Findings.Count -eq 0) {
    Write-Host "Nothing to remediate — no findings." -ForegroundColor Green
    Write-Host ""
    $RemediationStatus = 'Not required — no findings.'
}
else {
    $Remediable = @($Findings | Where-Object { $_.CanAutoRemediate })
    $Manual     = @($Findings | Where-Object { -not $_.CanAutoRemediate })

    Write-Host "── Remediation ────────────────────────────────────" -ForegroundColor Cyan
    if ($Remediable.Count -gt 0) {
        Write-Host "  The following $($Remediable.Count) finding(s) can be fixed automatically:" -ForegroundColor White
        foreach ($f in $Remediable) { Write-Host "    - $($f.VulnName)  ($($f.Severity))" }
    }
    if ($Manual.Count -gt 0) {
        Write-Host "  The following require MANUAL review and will NOT be changed:" -ForegroundColor Yellow
        foreach ($f in $Manual) { Write-Host "    - $($f.VulnName)  ($($f.Severity)) -> $($f.RecommendedFix)" }
    }
    Write-Host ""

    if ($Remediable.Count -eq 0) {
        Write-Host "  No auto-remediable findings to apply." -ForegroundColor Yellow
        Write-Host ""
        $RemediationStatus = "Not applicable — $($Manual.Count) finding(s) require manual review; none auto-remediable."
    }
    else {
        # Confirmation gate.
        $Proceed = $AutoConfirm
        if ($AutoConfirm) {
            Write-Host "  -AutoConfirm set: applying fixes without prompting." -ForegroundColor DarkYellow
        }
        else {
            $answer  = Read-Host "  Apply these $($Remediable.Count) fix(es) now? Type YES to proceed"
            $Proceed = ($answer -eq 'YES')
        }
        Write-Host ""

        if (-not $Proceed) {
            Write-Host "  Remediation cancelled — no changes made." -ForegroundColor Yellow
            Write-Host ""
            $RemediationStatus = 'Declined at confirmation prompt — no changes made.'
        }
        else {
            $RemediationStatus = 'Applied (see fixed / still-vulnerable lists).'
            $RebootNeeded = $false
            foreach ($f in $Remediable) {
                $plan = $RemediationRegistry[$f.VulnName]
                Write-Host "  Remediating: $($f.VulnName)" -ForegroundColor White

                if (-not $plan) {
                    # CanAutoRemediate said yes but no handler exists — a wiring bug, not a
                    # system state. Surface it loudly rather than silently skipping.
                    Write-Warning "    No remediation handler registered for '$($f.VulnName)'. Skipping."
                    $UnfixedItems += "$($f.VulnName) (no remediation handler)"
                    continue
                }

                # Apply.
                try { & $plan.Repair }
                catch {
                    Write-Host "    APPLY FAILED: $($_.Exception.Message)" -ForegroundColor Red
                    $UnfixedItems += "$($f.VulnName) (apply failed)"
                    continue
                }

                # Verify by re-running the original check. $null = no longer a finding = fixed.
                Write-Host "    Re-checking ... " -NoNewline
                $recheck = & $plan.Verify
                if ($null -eq $recheck) {
                    Write-Host "    -> VERIFIED FIXED." -ForegroundColor Green
                    $FixedItems += $f.VulnName
                    if ($plan.Reboot) {
                        $RebootNeeded = $true
                        Write-Host "    -> NOTE: a reboot is required to fully apply this change." -ForegroundColor Yellow
                    }
                }
                else {
                    Write-Host "    -> NOT FIXED: still reports as vulnerable. Manual investigation needed." -ForegroundColor Red
                    $UnfixedItems += "$($f.VulnName) (still vulnerable after fix)"
                }
            }

            Write-Host ""
            if ($RebootNeeded) {
                Write-Host "  *** One or more applied changes require a REBOOT to take full effect. ***" -ForegroundColor Yellow
                Write-Host ""
            }
        }
    }
    Write-Host "────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host ""
}
#endregion

#region Region 5 — Output
# Persist a structured plain-text audit record mirroring the console output: detection
# header, findings summary + detail, and the remediation outcome. Built as an array of
# strings joined with newlines (no [PSCustomObject], no $null-stream suppression) so the
# whole region parses and runs on PowerShell 2.

# Resolve the output directory: explicit -ReportPath, else the script's own folder.
$ReportDir = $ReportPath
if ([string]::IsNullOrEmpty($ReportDir)) { $ReportDir = $ScriptRoot }
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir -Force | Out-Null
}
$ReportFile = Join-Path $ReportDir ("SMBHardener_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + ".txt")

# Recompute the per-severity counts here rather than depend on Region 3's variables,
# which only exist on its populated branch.
$cCrit = @($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$cHigh = @($Findings | Where-Object { $_.Severity -eq 'High'     }).Count
$cMed  = @($Findings | Where-Object { $_.Severity -eq 'Medium'   }).Count
$cLow  = @($Findings | Where-Object { $_.Severity -eq 'Low'      }).Count

$Lines = @()
$Lines += '==================================================='
$Lines += ' Invoke-SMBHardener — SMB Security Audit Report'
$Lines += '==================================================='
$Lines += "Host           : $env:COMPUTERNAME"
$Lines += "OS             : $OSName (build $Build)"
$Lines += "Caption        : $Caption"
$Lines += "PowerShell     : $($PSVersionTable.PSVersion.ToString())"
$Lines += "Report time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$Lines += ''
$Lines += '--- Findings summary ---'
$Lines += "Total findings : $(@($Findings).Count)"
$Lines += "  Critical : $cCrit"
$Lines += "  High     : $cHigh"
$Lines += "  Medium   : $cMed"
$Lines += "  Low      : $cLow"
$Lines += ''
$Lines += '--- Findings detail ---'
if (@($SortedFindings).Count -eq 0) {
    $Lines += 'No findings — host compliant.'
}
else {
    $i = 0
    foreach ($f in $SortedFindings) {
        $i++
        $Lines += "[$i] $($f.VulnName)"
        $Lines += "    Severity        : $($f.Severity)"
        $Lines += "    Current state   : $($f.CurrentState)"
        $Lines += "    Recommended fix : $($f.RecommendedFix)"
        $Lines += "    Auto-remediable : $($f.CanAutoRemediate)"
        $Lines += ''
    }
}
$Lines += '--- Remediation summary ---'
$Lines += "Status : $RemediationStatus"
if (@($FixedItems).Count -gt 0) {
    $Lines += 'Fixed and verified:'
    foreach ($n in $FixedItems) { $Lines += "  - $n" }
}
if (@($UnfixedItems).Count -gt 0) {
    $Lines += 'Not fixed / needs attention:'
    foreach ($n in $UnfixedItems) { $Lines += "  - $n" }
}
# $RebootNeeded only exists if remediation actually proceeded — guard before referencing.
$RebootVar = Get-Variable -Name RebootNeeded -ErrorAction SilentlyContinue
if ($RebootVar -and $RebootVar.Value) {
    $Lines += ''
    $Lines += '*** A REBOOT is required to fully apply one or more changes. ***'
}
$Lines += ''
$Lines += '=== End of report ==='

($Lines -join "`n") | Out-File -FilePath $ReportFile -Encoding UTF8
Write-Host "Report saved to: $ReportFile" -ForegroundColor Green
#endregion
