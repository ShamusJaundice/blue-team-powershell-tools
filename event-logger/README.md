# Invoke-EventLogIntel

Collects events from all Windows event logs, surfaces rare event ID + provider combinations, and explains each one using the Gemini AI API.

## What it does

1. **Collect** — queries every available Windows event log for events within a configurable time window
2. **Analyse** — groups events by Event ID and provider name, then isolates low-frequency combinations (the "rare" ones worth investigating)
3. **Enrich** — sends each rare event ID to Gemini and gets back a structured security explanation covering cause, impact, and remediation

## Requirements

- PowerShell 7.0+
- Administrator privileges
- `GEMINI_API_KEY` environment variable set to a valid Gemini API key

## Usage

```powershell
# Run with defaults (7 days back, threshold of 5, max 1000 events per log)
.\Invoke-EventLogIntel.ps1

# Tighten the window and lower the rarity threshold
.\Invoke-EventLogIntel.ps1 -DaysBack 3 -RareThreshold 2

# Cast a wider net per log
.\Invoke-EventLogIntel.ps1 -DaysBack 14 -MaxPerLog 5000

# Enrich more events (free tier allows ~1500 requests/day total)
.\Invoke-EventLogIntel.ps1 -MaxEnrich 50
```

## Parameters

| Parameter        | Default | Description                                                       |
|-----------------|---------|-------------------------------------------------------------------|
| `DaysBack`      | `7`     | How far back in time to collect events                            |
| `RareThreshold` | `5`     | Events seen this many times or fewer are flagged as rare          |
| `MaxPerLog`     | `1000`  | Cap on events collected from each individual log (performance guard) |
| `MaxEnrich`     | `25`    | Maximum rare events sent to Gemini (rarest first). Raise cautiously — the free tier rate-limits aggressively. |

## Setting your API key

```powershell
$env:GEMINI_API_KEY = "your-key-here"
```

Or add it to your PowerShell profile so it persists across sessions.

## Output

For each rare event, the script prints a structured block containing:
- Event ID and provider
- Occurrence count in the time window
- Gemini explanation: cause, trigger, whether human intervention is needed, security importance, prevention steps, and big-picture context
