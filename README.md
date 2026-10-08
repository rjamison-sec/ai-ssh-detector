# SSH Brute Force Detector

A beginner-friendly Python project that detects repeated failed SSH passwords.
The repository keeps its original `ai-ssh-detector` name, but the current
implementation is **rule-based**, with no AI or machine-learning model.

## What it does

- Alerts after **3 failed passwords from one IP within 60 seconds** by default.
- Supports validated IPv4 and IPv6 addresses.
- Emits one alert per burst, then rearms when the active count falls below the threshold.
- Shares detection logic between live monitoring and offline practice.
- Simulates a blocking decision. **It never changes firewall rules or blocks traffic.**

## Quick start: offline practice

Requires Python 3.9 or newer; no third-party packages needed.
From the project folder, run:

```bash
python3 replay_detector.py
```

The included sample produces **one alert for 192.168.1.50**. The other source
has only two failures, and the successful login does not count as a failure.
Replay does not require sudo and does not write alerts or change your system.

Try your own chronological classic syslog file:

```bash
python3 replay_detector.py sample_logs.txt --threshold 4 --window 120
```

Supported example format:

```text
Apr 20 15:01:01 server sshd[1001]: Failed password for invalid user test from 192.0.2.10 port 54422 ssh2
```

Replay uses timestamps in the file, not how quickly Python reads the lines.
Unsupported lines are counted as skipped. Invalid dates or out-of-order SSH
records produce a line-numbered error. Classic syslog lacks a year; use a
single-year fixture without a December-to-January rollover.

## Live monitoring on Linux

Requires systemd's `journalctl`, a running SSH server, and permission to read
its journal. Start with:

```bash
python3 live_monitor.py
```

If journal access is denied, use an account with journal permissions or run
with sudo. If your SSH unit is named `sshd`, select it explicitly:

```bash
sudo python3 live_monitor.py --unit sshd --threshold 3 --window 60
```

The monitor follows **new events only**, avoiding historical failures on startup.
It accepts journal messages from `sshd` and `sshd-session`. Live windows use
monotonic receipt time, so changing the wall clock does not break counting.
Delayed or queued events are therefore measured when received.
Press **Ctrl+C** to stop the monitor and its journal follower.

Alerts are printed and saved to `runtime/alerts.log` beside the scripts, with
rotation at roughly 1 MB and three backups. Override this with
`--log-file /path/to/alerts.log`. Default paths work even when launched from
another directory. Runtime files are ignored by Git.

If no events appear, check that the selected service exists and that your
account can read its logs. An empty stream alone does not prove access works.

## Tests

```bash
python3 -m unittest discover -v
```

Tests use synthetic logs and mocked journal processes. They do not attempt
SSH logins, change firewall rules, or require root.

## Limits and learning goals

This is a learning detector, not a replacement for a production protection
service. It detects `Failed password` events, not all authentication methods.
Shared source addresses can cause false positives. Slow or distributed
attempts may stay below the threshold. Successful logins do not reset recent
failures. Counts reset when the program restarts, and there is no persistent
blocklist. History is capped at the threshold per IP; the number of distinct
IPs within an active window can still grow.

Old generated `alerts.log` and `blocked_ips.txt` files were removed from the
current repository tree; previous versions remain in Git history.
