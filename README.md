# AI SSH Brute Force Detector

## Overview
This project monitors SSH logs in real time and detects brute force login attempts by analyzing repeated failed login attempts.

## Features
- Real-time SSH log monitoring
- Failed login detection
- IP extraction using regex
- Attempt tracking per IP
- Brute force alerting (threshold: 3 attempts)
- Automatic IP blocking using iptables

## Technologies
- Python
- Linux (journalctl, iptables)
- Regex (re)
- subprocess module

## How It Works
The script listens to live SSH logs:
journalctl -u ssh -f

It detects:
Failed password

Extracts attacker IP:
from (\d+\.\d+\.\d+\.\d+)

Tracks attempts and triggers:
- Alert after 3 failed attempts
- Firewall block using iptables

## Usage
```bash
sudo python3 live_monitor.py
