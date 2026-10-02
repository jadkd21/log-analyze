# Log Analyzer

A baby SIEM: reads `honeypot.log` and detects attack patterns.

## How to run

1. Generate a log first: run `honeypot.py`, then `fake_attacker.py`
2. `python log_analyzer.py` — analyzes `honeypot.log` in the same folder

## What it detects

- **Brute force** — 5+ login attempts from one IP within 60 seconds
- **Password spraying** — 4+ different usernames tried from one IP
- Plus statistics: total attempts, top attacker IPs, usernames, passwords

## What I learned

- Detection logic: turning raw logs into alerts with sliding time windows
- The difference between brute force (many passwords, one user)
  and spraying (one password, many users)
- The SIEM pipeline: honeypot collects -> analyzer detects -> analyst responds
- Threshold tuning: too sensitive = alert fatigue, too loose = missed attacks
- This is the same job Splunk/Wazuh correlation rules do at scale

## Note

Thresholds are at the top of the script — tune them and watch
the alerts change. That's detection engineering.
