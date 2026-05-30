#Requires -RunAsAdministrator
#Requires -Version 7.0

<#
.SYNOPSIS
    Surfaces rare Windows events and explains them using Gemini AI.

.DESCRIPTION
    Collects events from all Windows event logs over a configurable time window,
    identifies low-frequency event ID + provider combinations, and sends each
    to the Gemini API for a structured security explanation.

.PARAMETER DaysBack
    How many days back to collect events. Default: 7.

.PARAMETER RareThreshold
    Events with a count at or below this value are considered rare. Default: 5.

.PARAMETER MaxPerLog
    Maximum number of events to collect per individual event log. Default: 1000.

.EXAMPLE
    .\Invoke-EventLogIntel.ps1

.EXAMPLE
    .\Invoke-EventLogIntel.ps1 -DaysBack 3 -RareThreshold 2

.NOTES
    Requires the GEMINI_API_KEY environment variable.
    Must be run as Administrator.
#>
param(
    [int]$DaysBack      = 7,
    [int]$RareThreshold = 5,
    [int]$MaxPerLog     = 1000
)

# ── GUARD: API key must be present before doing any work ───────────────────────
if (-not $env:GEMINI_API_KEY) {
    Write-Error "GEMINI_API_KEY environment variable is not set. Exiting."
    exit 1
}

$StartTime = (Get-Date).AddDays(-$DaysBack)

Write-Host "=== Invoke-EventLogIntel ===" -ForegroundColor Cyan
Write-Host "Window : last $DaysBack day(s) (since $($StartTime.ToString('yyyy-MM-dd HH:mm')))"
Write-Host "Rarity : event IDs seen $RareThreshold time(s) or fewer"
Write-Host "Cap    : $MaxPerLog events per log"
Write-Host ""

# ── REGION 2: Event collection (coming next) ───────────────────────────────────

# ── REGION 3: Rarity analysis (coming next) ────────────────────────────────────

# ── REGION 4: Gemini enrichment (coming next) ──────────────────────────────────
