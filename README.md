# TRACEX — Windows Event Log Analyzer

**Version:** 1.0.0  
**Tools:** Python, python-evtx, SQLite, vanilla JS  
**Platform:** Windows, Linux  

## Summary

Standalone Windows Event Log analyzer built for forensic triage and detection engineering. Point it at any `.evtx` file it parses every record, runs correlated detection rules, maps findings to MITRE ATT&CK, scores them by confidence, and opens an interactive dashboard in your browser automatically.

No Splunk. No SIEM. No license. No infrastructure.

Built to fill a real gap: most log analysis tools assume you already have agents deployed and a SIEM running. TRACEX is for the situations where you don't incident response on a host that was never monitored, forensic triage on an exported log from a disk image, or environments that can't justify enterprise tooling.

Tested against real Windows Security log telemetry throughout development, on both Windows 11 and Kali Linux.

## Detection Rules

| Rule | EventIDs | What it detects |
|------|----------|-----------------|
| `brute_force_logon` | 4625, 4624 | Failed logon cluster from same source IP within 5 minutes escalates to HIGH if followed by a successful logon from the same IP |
| `suspicious_process_execution` | 4688 | Known LOLBin execution (cmd.exe, powershell.exe, certutil.exe, rundll32.exe) |
| `privilege_escalation_sequence` | 4672, 4688 | Special privileges assigned followed by a suspicious process from the same user within 5 minutes |
| `explicit_credential_use` | 4648 | Alternate credential logon where subject authenticates as a different user common lateral movement indicator |
| `account_modification` | 4738 | User account modified by a different account self-modifications excluded as routine |

## MITRE ATT&CK Mapping

| Rule | Technique ID | Technique |
|------|-------------|-----------|
| `brute_force_logon` | T1110 | Brute Force |
| `suspicious_process_execution` | T1059 | Command and Scripting Interpreter |
| `privilege_escalation_sequence` | T1078 | Valid Accounts |
| `explicit_credential_use` | T1550.003 | Use Alternate Authentication Material |
| `account_modification` | T1098 | Account Manipulation |

## Installation

**Windows:**
```bash
git clone https://github.com/HariCipher/tracex
cd tracex
setup.bat
```

**Linux / Kali:**
```bash
git clone https://github.com/HariCipher/tracex
cd tracex
bash setup.sh
source .venv/bin/activate
```

## Usage

```
tracex <path-to-evtx>     Analyze an EVTX file
tracex --help             Show help menu
tracex --version          Show version
tracex --clear-db         Wipe findings database
```

**Example:**
```bash
tracex C:\Users\user\Documents\Security.evtx
tracex /home/kali/Documents/Security.evtx
```

## Output

Every run produces:

- `dashboard.html` — interactive HTML dashboard, opens automatically in your default browser
- `tracex.db` — SQLite database that persists findings across runs

**Dashboard features:** time range filters (24h / 7d / 14d / 30d), severity filter, rule filter, live search, sortable columns, expandable rows showing full finding detail MITRE technique, confidence score, raw event record IDs, full description.

## Confidence Scoring

Each finding gets a numeric confidence score (0–100) based on rule type, severity escalation, number of events involved, and whether the subject is a known service account. Findings are ranked highest score first.

| Rule | Base Score |
|------|------------|
| `privilege_escalation_sequence` | 80 |
| `brute_force_logon` | 60 |
| `explicit_credential_use` | 55 |
| `account_modification` | 50 |
| `suspicious_process_execution` | 30 |

Adjustments applied on top: +10 if severity escalated to high, +5 if 5 or more events involved in one finding, −15 if subject is a known service account.

## Notable Findings From Real Testing

| Type | Value | Notes |
|------|-------|-------|
| Brute force | `127.0.0.1` | 5 failed logons followed by successful logon score 75, HIGH |
| LOLBin execution | `certutil.exe` by `hari9` | Flagged correctly, low confidence no command-line visibility |
| Account modification | `TEST$` modified `hari9` | Medium severity, score 35 |
| False positive found | `SplunkForwarder` | Service account tripping escalation rule via routine cmd.exe health checks investigated, documented, excluded |

## Known Limitations

- `suspicious_process_execution` flags by process name only command-line argument visibility requires enabling "Include command line in process creation events" via Group Policy (disabled by default on most Windows machines)
- Detection rules currently cover Security and System log channels
- Time range filters in the dashboard show meaningful differences only after running against logs from different days

## Project Structure

```
tracex/
├── adapters/
│   ├── evtx_adapter.py       # EVTX parsing — raw binary to structured records
│   └── normalize.py          # Field normalization across EventIDs
├── detections/
│   └── rules.py              # All 5 detection rules + correlation engine
├── dashboard.py              # Interactive HTML dashboard generator
├── db.py                     # SQLite persistence with deduplication
├── main.py                   # CLI entry point
├── mitre_map.py              # ATT&CK technique mapping per rule
├── scoring.py                # Confidence scoring engine
├── setup.py                  # pip installable package
├── requirements.txt          # Dependencies
├── setup.bat                 # Windows setup script
└── setup.sh                  # Linux setup script
```

## Author

Harilal P — [github.com/HariCipher](https://github.com/HariCipher) — thisisharilal@gmail.com
