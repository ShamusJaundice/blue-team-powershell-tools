# Blue Team PowerShell Tools

A collection of PowerShell security automation scripts for blue team operations, 
incident response, and Windows endpoint administration.

## Tools

### Event Security Logger *(in development)*
Monitors Windows Event Log for critical security events, flags them by Event ID, 
timestamp, and involved processes, and generates a plain-text incident summary.

### Portable Shield *(in development)*
Incident response containment script. Execute on a compromised endpoint to isolate 
it, limit damage, and assist in breach containment.

## Requirements
- PowerShell 7.6+
- Administrator privileges
- Windows 10/11 or Windows Server 2019+