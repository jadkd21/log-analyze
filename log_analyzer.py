#!/usr/bin/env python3
"""
Log Analyzer - baby SIEM
Reads honeypot.log and hunts for attack patterns:

  * BRUTE FORCE: many login attempts from one IP in a short time
  * PASSWORD SPRAYING: many different usernames tried from one IP
  * Plus the greatest-hits stats: top IPs, usernames, passwords

This is the detection half of the SIEM story. The honeypot collects,
this tool thinks. Real SIEMs (Splunk, Wazuh) do this at massive scale.

How to run:
    python log_analyzer.py              (reads honeypot.log)
    python log_analyzer.py mylog.log    (reads another file)
"""

import sys
from datetime import datetime
from collections import defaultdict, Counter

DEFAULT_LOG = "honeypot.log"

BRUTE_FORCE_THRESHOLD = 5   # attempts...
BRUTE_FORCE_WINDOW = 60     # ...inside this many seconds = brute force
SPRAY_USER_THRESHOLD = 4    # distinct usernames from one IP = spraying


def parse_line(line):
    """Turn '2026-10-02 05:27:45 | 127.0.0.1 | admin | admin'
    into (datetime, ip, username, password)."""
    parts = [p.strip() for p in line.split("|")]
    if len(parts) != 4:
        return None
    try:
        ts = datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return (ts, parts[1], parts[2], parts[3])


def detect_brute_force(events):
    """Sliding window: 5+ attempts from one IP within 60 seconds."""
    alerts = []
    by_ip = defaultdict(list)
    for ts, ip, _user, _pwd in events:
        by_ip[ip].append(ts)
    for ip, times in by_ip.items():
        times.sort()
        start = 0
        for end in range(len(times)):
            while (times[end] - times[start]).total_seconds() > BRUTE_FORCE_WINDOW:
                start += 1
            if end - start + 1 >= BRUTE_FORCE_THRESHOLD:
                alerts.append((ip, end - start + 1, times[start], times[end]))
                break  # one alert per IP is enough
    return alerts


def detect_spraying(events):
    """One IP trying many different usernames = password spraying."""
    alerts = []
    users_by_ip = defaultdict(set)
    for _ts, ip, user, _pwd in events:
        users_by_ip[ip].add(user)
    for ip, users in users_by_ip.items():
        if len(users) >= SPRAY_USER_THRESHOLD:
            alerts.append((ip, len(users), sorted(users)))
    return alerts


def main():
    logfile = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG

    print("=" * 70)
    print("  LOG ANALYZER - baby SIEM")
    print("=" * 70)

    try:
        with open(logfile, encoding="utf-8") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"\n  No {logfile} found.")
        print("  Run honeypot.py + fake_attacker.py first to generate one.")
        sys.exit(1)

    events = [e for line in lines if (e := parse_line(line))]
    print(f"\n  Parsed {len(events)} login attempts from {logfile}\n")

    if not events:
        print("  Log is empty - no attacks to analyze yet.")
        return

    # ---- alerts ----
    print("-" * 70)
    print("  ALERTS")
    print("-" * 70)
    found = False

    for ip, count, first, last in detect_brute_force(events):
        secs = int((last - first).total_seconds())
        print(f"  [ALERT] BRUTE FORCE from {ip}: {count} attempts in {secs}s")
        found = True

    for ip, nusers, users in detect_spraying(events):
        print(f"  [ALERT] PASSWORD SPRAYING from {ip}: "
              f"{nusers} usernames tried ({', '.join(users)})")
        found = True

    if not found:
        print("  No attack patterns detected. Either you're safe,")
        print("  or the attackers are being sneaky (tune the thresholds).")

    # ---- stats ----
    print("\n" + "-" * 70)
    print("  STATISTICS")
    print("-" * 70)
    ips = Counter(e[1] for e in events)
    users = Counter(e[2] for e in events)
    pwds = Counter(e[3] for e in events)
    print("  Total attempts : " + str(len(events)))
    print("  Attacker IPs   : " + str(len(ips)))
    print("  Top IPs        : " + ", ".join(ip + " (" + str(n) + ")" for ip, n in ips.most_common(3)))
    print("  Top usernames  : " + ", ".join(u + " (" + str(n) + ")" for u, n in users.most_common(3)))
    print("  Top passwords  : " + ", ".join(p + " (" + str(n) + ")" for p, n in pwds.most_common(3)))
    print("\n  Tip: in a real SOC, these alerts would feed a dashboard in")
    print("  Splunk or Wazuh instead of a terminal. Same logic, bigger scale.")


if __name__ == "__main__":
    main()
