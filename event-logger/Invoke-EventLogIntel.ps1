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

.PARAMETER MaxEnrich
    Maximum number of rare events to send to Gemini. Rare events are sorted ascending
    by count (rarest first), so the most unusual events are always enriched first.
    Default: 25. Increase cautiously — the Gemini free tier rate-limits aggressively.

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
    [int]$MaxPerLog     = 1000,
    [int]$MaxEnrich     = 25
)

# ── GUARD: API key must be present before doing any work ───────────────────────
if (-not $env:GEMINI_API_KEY) {
    Write-Error "GEMINI_API_KEY environment variable is not set. Exiting."
    exit 1
}

$StartTime = (Get-Date).AddDays(-$DaysBack)

Write-Host "=== Invoke-EventLogIntel ===" -ForegroundColor Cyan
Write-Host "Window  : last $DaysBack day(s) (since $($StartTime.ToString('yyyy-MM-dd HH:mm')))"
Write-Host "Rarity  : event IDs seen $RareThreshold time(s) or fewer"
Write-Host "Cap     : $MaxPerLog events per log"
Write-Host "Enrich  : top $MaxEnrich rare events sent to Gemini"
Write-Host ""

#region Region 2 — Event Collection
Write-Host "Discovering event logs..." -ForegroundColor Cyan

# ListLog enumerates every registered log on this machine (200+ on a typical Windows install).
# We pre-filter to logs that have at least one record on disk — no point querying empty ones.
$AllLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
    Where-Object { $_.RecordCount -gt 0 }

Write-Host "Found $($AllLogs.Count) non-empty log(s). Collecting events since $($StartTime.ToString('yyyy-MM-dd HH:mm'))..."
Write-Host ""

# Generic List is more efficient than repeated += on a PS array, which copies the whole
# array each time. With potentially tens-of-thousands of events this matters.
$AllEvents   = [System.Collections.Generic.List[PSCustomObject]]::new()
$LogsQueried = 0
$LogsSkipped = 0
$LogTotal    = $AllLogs.Count
$LogIndex    = 0

foreach ($Log in $AllLogs) {
    $LogIndex++

    # Overwrite the same console line so the terminal doesn't scroll endlessly.
    Write-Host "`r  [$LogIndex/$LogTotal] $($Log.LogName.PadRight(60))" -NoNewline

    try {
        # FilterHashtable is significantly faster than piping to Where-Object because
        # the filtering happens inside the ETW/EVTX reader before objects are created.
        $Filter = @{
            LogName   = $Log.LogName
            StartTime = $StartTime
        }

        $Events = Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxPerLog -ErrorAction Stop

        foreach ($Evt in $Events) {
            # Select only the fields we need — the full event object carries XML payload
            # and message DLL data we don't want to hold in memory for every event.
            $AllEvents.Add([PSCustomObject]@{
                Id               = $Evt.Id
                ProviderName     = $Evt.ProviderName
                LogName          = $Evt.LogName
                TimeCreated      = $Evt.TimeCreated
                LevelDisplayName = $Evt.LevelDisplayName
                Message          = if ($Evt.Message) { $Evt.Message } else { '(no message)' }
            })
        }

        $LogsQueried++
    }
    catch {
        # Get-WinEvent throws when a log has no events in the time window, or when
        # the log requires permissions we don't have even as admin. Both are expected.
        $LogsSkipped++
    }
}

Write-Host ""  # end the overwriting line
Write-Host ""
Write-Host "Queried : $LogsQueried log(s)"
Write-Host "Skipped : $LogsSkipped log(s)  (empty in window or access-denied)"
Write-Host "Total   : $($AllEvents.Count) event(s) collected"
Write-Host ""
#endregion

#region Region 3 — Rarity Analysis
if ($AllEvents.Count -eq 0) {
    Write-Host "No events collected in the specified window. Exiting." -ForegroundColor Yellow
    exit 0
}

Write-Host "Analysing event frequency..." -ForegroundColor Cyan

# Group by Id + ProviderName together — this is the true fingerprint of an event type.
# Event ID 4 from the Kernel-Power provider is completely different from Event ID 4
# from a third-party driver, even though the number is the same.
$AllGroups  = $AllEvents | Group-Object -Property Id, ProviderName
$RareGroups = $AllGroups  | Where-Object { $_.Count -le $RareThreshold } | Sort-Object Count

Write-Host "Unique event types : $($AllGroups.Count)"
Write-Host "Rare (count <= $RareThreshold)  : $($RareGroups.Count)"
Write-Host ""

if ($RareGroups.Count -eq 0) {
    Write-Host "No rare events found with the current threshold. Try raising -RareThreshold." -ForegroundColor Yellow
    exit 0
}

# Build one summary row per rare event type.
# $_.Group is the array of raw events that landed in this bucket.
# We pick the most-recent occurrence as the representative so the Message is fresh.
$RareSummary = foreach ($Group in $RareGroups) {
    $Representative = $Group.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $UniqueLogNames = ($Group.Group | Select-Object -ExpandProperty LogName -Unique) -join ', '

    [PSCustomObject]@{
        EventId      = $Representative.Id
        ProviderName = $Representative.ProviderName
        Count        = $Group.Count
        LogNames     = $UniqueLogNames
        LastSeen     = $Representative.TimeCreated
        Message      = $Representative.Message
    }
}

# Preview the rare events in the terminal so the analyst can see what will be enriched.
Write-Host "── Rare Events ────────────────────────────────────────────────" -ForegroundColor DarkCyan
$RareSummary | Format-Table -AutoSize -Property Count, EventId, ProviderName, LastSeen, LogNames
#endregion

#region Region 4 — Gemini Enrichment
$GeminiEndpoint = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent'

# Build the headers hashtable once, outside the loop.
# The API key goes in a header — NOT in the URL — for a reason explained below.
$Headers = @{
    'x-goog-api-key' = $env:GEMINI_API_KEY
    'Content-Type'   = 'application/json'
}

Write-Host "── Gemini Enrichment ──────────────────────────────────────────" -ForegroundColor DarkCyan

$EnrichQueue = $RareSummary | Select-Object -First $MaxEnrich
if ($RareSummary.Count -gt $MaxEnrich) {
    Write-Host "Enriching top $MaxEnrich of $($RareSummary.Count) rare event(s) (rarest first). Raise -MaxEnrich to increase."
} else {
    Write-Host "Enriching all $($EnrichQueue.Count) rare event(s)."
}
Write-Host ""

$Results = foreach ($Event in $EnrichQueue) {
    Write-Host "  Querying: Event $($Event.EventId) / $($Event.ProviderName)..." -NoNewline

    # Truncate the message so we don't blow the model's context window.
    $MsgPreview = $Event.Message.Substring(0, [Math]::Min(500, $Event.Message.Length))

    $Prompt = @"
You are a Windows security analyst. A rare Windows event has been observed.

Event ID  : $($Event.EventId)
Provider  : $($Event.ProviderName)
Count     : $($Event.Count) occurrence(s) in the collection window
Log(s)    : $($Event.LogNames)
Last seen : $($Event.LastSeen)
Message   : $MsgPreview

Respond ONLY with a JSON object — no markdown fences, no text outside the JSON — with exactly these keys:
{
  "why_it_happened": "...",
  "what_caused_it": "...",
  "human_intervention": "...",
  "security_importance": "...",
  "prevention": "...",
  "big_picture": "..."
}
"@

    # Gemini's REST API expects a specific nested JSON shape.
    # ConvertTo-Json -Depth 5 is required because the hashtable is 4 levels deep
    # (outer → contents → parts → text). The default depth is 2, which would
    # silently truncate the inner levels to the string "@{text=...}".
    $Body = @{
        contents = @(
            @{
                parts = @(
                    @{ text = $Prompt }
                )
            }
        )
    } | ConvertTo-Json -Depth 5

    try {
        # ── Invoke-RestMethod ───────────────────────────────────────────────────
        #
        # -Uri     : the endpoint — note the API key is NOT in this URL.
        #            If the key were a query parameter (?key=abc123), it would appear
        #            in proxy logs, SIEM logs, browser history, and server access logs
        #            in plain text. Headers are still transmitted in plain text over
        #            the wire, but TLS encrypts them in transit, and they are NOT
        #            written to URL-based logs by default.
        #
        # -Method  : POST because we are sending a body. GET requests carry no body.
        #
        # -Headers : a hashtable passed as HTTP request headers. This is where the
        #            API key lives. PowerShell reads $env:GEMINI_API_KEY at this line
        #            and inserts the value — the literal string is never in the script.
        #            If someone reads your .ps1, they see the variable name, not the
        #            secret. If this key is ever rotated, you update the env var, not
        #            the code.
        #
        # -Body    : the serialized JSON string built above.
        #
        # Invoke-RestMethod (IRM) differs from Invoke-WebRequest (IWR) in one key
        # way: IRM automatically parses the response body as JSON and gives you a
        # live PowerShell object. IWR gives you the raw HTTP response (status code,
        # headers, raw content string) — useful for debugging, not for consuming APIs.
        #
        # ───────────────────────────────────────────────────────────────────────
        $Response = Invoke-RestMethod `
            -Uri         $GeminiEndpoint `
            -Method      Post `
            -Headers     $Headers `
            -Body        $Body `
            -ErrorAction Stop

        # Drill into the response shape: candidates[0] → content → parts[0] → text
        $RawText   = $Response.candidates[0].content.parts[0].text

        # Gemini sometimes wraps JSON in ```json ... ``` despite being told not to.
        $CleanText = $RawText -replace '(?s)```json\s*', '' -replace '(?s)```\s*', ''

        $Parsed = $CleanText | ConvertFrom-Json

        Write-Host " done." -ForegroundColor Green

        # Throttle to stay under the Gemini per-minute rate limit. Only sleep on
        # success — failed calls didn't consume a successful-request quota slot,
        # and we don't want to slow down the retry/error path.
        Start-Sleep -Seconds 3

        [PSCustomObject]@{
            EventId            = $Event.EventId
            ProviderName       = $Event.ProviderName
            Count              = $Event.Count
            LogNames           = $Event.LogNames
            LastSeen           = $Event.LastSeen
            WhyItHappened      = $Parsed.why_it_happened
            WhatCausedIt       = $Parsed.what_caused_it
            HumanIntervention  = $Parsed.human_intervention
            SecurityImportance = $Parsed.security_importance
            Prevention         = $Parsed.prevention
            BigPicture         = $Parsed.big_picture
        }
    }
    catch {
        Write-Host " FAILED." -ForegroundColor Red
        Write-Warning "  $($_.Exception.Message)"

        [PSCustomObject]@{
            EventId            = $Event.EventId
            ProviderName       = $Event.ProviderName
            Count              = $Event.Count
            LogNames           = $Event.LogNames
            LastSeen           = $Event.LastSeen
            WhyItHappened      = 'API error'
            WhatCausedIt       = 'API error'
            HumanIntervention  = 'API error'
            SecurityImportance = 'API error'
            Prevention         = 'API error'
            BigPicture         = $_.Exception.Message
        }
    }
}
#endregion

#region Region 5 — Output
Write-Host ""
Write-Host "── Results ────────────────────────────────────────────────────" -ForegroundColor DarkCyan

foreach ($R in $Results) {
    Write-Host ""
    Write-Host "Event $($R.EventId)  |  $($R.ProviderName)  |  seen $($R.Count)x  |  $($R.LastSeen)" -ForegroundColor White
    Write-Host "  Why it happened      : $($R.WhyItHappened)"
    Write-Host "  What caused it       : $($R.WhatCausedIt)"
    Write-Host "  Human intervention   : $($R.HumanIntervention)"
    Write-Host "  Security importance  : $($R.SecurityImportance)"
    Write-Host "  Prevention           : $($R.Prevention)"
    Write-Host "  Big picture          : $($R.BigPicture)"
}

$CsvPath = Join-Path $PSScriptRoot "EventLogIntel_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "Results saved to: $CsvPath" -ForegroundColor Green
#endregion
