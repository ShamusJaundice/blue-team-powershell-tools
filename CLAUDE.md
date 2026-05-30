# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running a script

All scripts require PowerShell 7+ and an elevated session. Launch one from the repo root:

```powershell
# Set the API key for the current session, then run
$env:GEMINI_API_KEY = "your-key-here"
.\event-logger\Invoke-EventLogIntel.ps1

# Override defaults
.\event-logger\Invoke-EventLogIntel.ps1 -DaysBack 3 -RareThreshold 2 -MaxPerLog 500
```

There are no build steps, no package installs, and no test suite — scripts are run directly.

## Architecture of Invoke-EventLogIntel.ps1

The script is divided into five `#region` blocks that run sequentially. Data flows forward through variables — no functions, no modules.

| Region | Variable produced | Purpose |
|--------|------------------|---------|
| 1 — Config & guard | `$StartTime` | Validates `$env:GEMINI_API_KEY`, prints run banner |
| 2 — Event collection | `$AllEvents` (Generic List) | Queries every non-empty Windows event log via `Get-WinEvent -FilterHashtable` |
| 3 — Rarity analysis | `$RareSummary` | Groups `$AllEvents` by `Id + ProviderName`; keeps rows where `Count ≤ $RareThreshold` |
| 4 — Gemini enrichment | `$Results` | POSTs each row to the Gemini REST API; parses the JSON response into 6 explanation fields |
| 5 — Output | _(side-effects)_ | Prints a structured block per event to the terminal; exports `$Results` to a timestamped CSV beside the script |

**Key design decisions to preserve:**

- **Grouping fingerprint is `Id + ProviderName` together.** The same Event ID means different things from different providers. Never group on ID alone.
- **`FilterHashtable` over pipeline `Where-Object`.** The filter runs inside the EVTX reader before objects are created — much faster at scale.
- **`[System.Collections.Generic.List[PSCustomObject]]` for `$AllEvents`.** Avoids the O(n²) copy cost of `+=` on PS arrays when collecting tens of thousands of events.
- **API key in the `x-goog-api-key` header, never in the URL.** URLs land in proxy/SIEM logs; headers are encrypted by TLS and not logged by default.
- **`ConvertTo-Json -Depth 5` for the Gemini request body.** The default depth of 2 silently truncates the nested hashtable — no PS error, but the API returns a 400.
- **Gemini model:** `gemini-3.5-flash` via `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash:generateContent`. Auth via `Invoke-RestMethod -Headers @{ 'x-goog-api-key' = $env:GEMINI_API_KEY }`.
- **Message truncated to 500 chars** before sending to Gemini to avoid blowing the context window.
- **Gemini ignores the "no fences" instruction** intermittently — the regex `-replace '(?s)```json\s*'` strips them defensively.

## Planned tools

`Portable Shield` — incident response containment script (isolate a compromised endpoint). Not yet started. Will live in its own subfolder following the same pattern as `event-logger/`.

## Conventions

- One script per tool subfolder, accompanied by a `README.md`.
- Four tuning knobs at the top of each script as `param()` with defaults: time window, rarity threshold, per-log cap, and Gemini enrichment cap.
- Secrets always via `$env:` variables — never hardcoded, never passed as positional args.
- `Write-Host` for user-facing output; `Write-Warning` for non-fatal API failures; `Write-Error` + `exit 1` for fatal startup failures.
