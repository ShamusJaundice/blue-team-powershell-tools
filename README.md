# Blue Team PowerShell Tools

A collection of PowerShell security automation scripts for blue team operations, 
incident response, and Windows endpoint administration.

## Tools

### Event Security Logger *(in development)*
Monitors Windows Event Log for critical security events, flags them by Event ID, 
timestamp, and involved processes, and generates a plain-text incident summary.

### SMB Hardener
OS-aware SMB security auditor and remediator. Detects the host's Windows version and 
PowerShell capabilities, then runs the correct checks and fixes for that specific OS. 
Scans for SMB1, SMBGhost, null sessions, weak signing, NTLMv1, and more — reports first, 
then remediates only after confirmation, verifying each fix by re-checking. 
See [`smb-hardener/`](smb-hardener/).

### Portable Shield *(in development)*
Incident response containment script. Execute on a compromised endpoint to isolate 
it, limit damage, and assist in breach containment.

## Requirements
- PowerShell 7.6+ (the SMB Hardener degrades gracefully down to PowerShell 2 / Windows 7)
- Administrator privileges
- Windows 10/11 or Windows Server 2019+ (SMB Hardener supports Windows 7+)