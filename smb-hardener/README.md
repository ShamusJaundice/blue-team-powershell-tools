# Invoke-SMBHardener

OS-aware SMB security auditor and remediator for Windows. Detects the host's Windows version and PowerShell capabilities, then runs the **correct** checks and fixes for that specific OS — because SMB features and the cmdlets that configure them differ significantly across versions.

## Why OS awareness matters

The same SMB misconfiguration is inspected and fixed differently depending on the host:

- **Windows 8 and newer (PowerShell 3+)** ship the `Smb*` cmdlets (`Get-/Set-SmbServerConfiguration`) and `Net*` firewall cmdlets.
- **Windows 7 (PowerShell 2)** has none of those — every check must fall back to `reg query` and WMI.
- **`Get-WmiObject`** was removed in PowerShell 7; **`Get-CimInstance`** doesn't exist on PowerShell 2. The script detects which is present and uses it.

The script sets capability flags up front (`$HasSmbCmdlets`, `$HasCimInstance`, …) and branches on them rather than assuming any cmdlet exists.

## What it checks (OS-aware)

| # | Vulnerability | Severity | Modern path | Win7 fallback |
|---|---------------|----------|-------------|---------------|
| 1 | SMB1 enabled | Critical | `Set-SmbServerConfiguration` | `LanmanServer\Parameters\SMB1` registry |
| 2 | SMBGhost (CVE-2020-0796) | Critical | registry compression flag | *(only Win10 builds 18362/18363)* |
| 3 | Null sessions | High | registry | registry |
| 4 | SMB signing not required | High | `Get/Set-SmbServerConfiguration` | registry |
| 5 | Guest account enabled | Medium | `net user guest` | `net user guest` |
| 6 | NTLMv1 weak auth | High | `LmCompatibilityLevel` registry (want `5`) | same |
| 7 | Port 445 firewall exposure | Medium | Windows Firewall rules | netsh/registry |
| 8 | Anonymous share enumeration | Medium | `RestrictAnonymous` registry | same |

## How it works

1. **Detect** *(Region 1)* — Windows version, build, PowerShell version, and cmdlet availability → capability flags.
2. **Scan** *(Region 2)* — run every applicable check for the detected OS and build a findings list.
3. **Report** *(Region 3)* — print findings sorted by severity with per-severity counts. Read-only.
4. **Remediate** *(Region 4)* — **only after you confirm**, apply each fixable finding, then re-run its check to verify it worked. Reboot requirements are called out explicitly.
5. **Output** *(Region 5)* — save a timestamped `.txt` report.

> **Scan → report → confirm → remediate.** Nothing is fixed silently, and every fix verifies itself by re-checking.

## Requirements

- Windows 7 or newer (graceful degradation down to PowerShell 2)
- Administrator privileges (the script enforces this)

## Usage

```powershell
# Audit + report, then prompt before remediating
.\Invoke-SMBHardener.ps1

# Audit and report only — never change anything
.\Invoke-SMBHardener.ps1 -AuditOnly

# Apply fixes without the interactive prompt (automation; use with care)
.\Invoke-SMBHardener.ps1 -AutoConfirm

# Write the report somewhere specific
.\Invoke-SMBHardener.ps1 -ReportPath C:\Reports
```

## Parameters

| Parameter      | Default       | Description                                              |
|----------------|---------------|----------------------------------------------------------|
| `AuditOnly`    | off           | Scan and report only; skip remediation entirely          |
| `AutoConfirm`  | off           | Apply remediations without the interactive confirmation  |
| `ReportPath`   | script folder | Directory for the timestamped text report                |

> **Status:** complete. All five regions are implemented — OS detection, scanner, report, remediation (with confirmation + per-fix verification), and timestamped text output.
