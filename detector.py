"""Shared, rule-based detection. No network or firewall operations."""

import argparse
from collections import deque
from ipaddress import ip_address
import math
import re


FAILURE = re.compile(r"\bFailed password for .+? from (\S+) port \d+\b")


def failed_ip(message):
    """Return a validated, normalized IPv4/IPv6 address, or None."""
    match = FAILURE.search(message)
    if match:
        try:
            return str(ip_address(match.group(1)))
        except ValueError:
            pass
    return None


def positive_int(value):
    try:
        number = int(value)
        if number > 0:
            return number
    except ValueError:
        pass
    raise argparse.ArgumentTypeError("must be a positive integer")


def add_detection_options(parser):
    parser.add_argument("--threshold", type=positive_int, default=3,
                        help="failed attempts required (default: 3)")
    parser.add_argument("--window", type=positive_int, default=60,
                        help="sliding window in seconds (default: 60)")


class Detector:
    """Alert once per IP burst; rearm when fewer than threshold remain.

    Events must arrive in timestamp order. The window is (now-window, now].
    Store at most threshold timestamps per active IP and expire inactive IPs.
    """

    def __init__(self, threshold=3, window=60):
        if not isinstance(threshold, int) or threshold < 1:
            raise ValueError("threshold must be a positive integer")
        if not math.isfinite(window) or window <= 0:
            raise ValueError("window must be positive and finite")
        self.threshold = threshold
        self.window = window
        self.attempts = {}
        self.alerted = set()
        self.last_time = None

    def feed(self, message, timestamp):
        if not math.isfinite(timestamp):
            raise ValueError("timestamp must be finite")
        if self.last_time is not None and timestamp < self.last_time:
            raise ValueError("events must be in chronological order")
        self.last_time = timestamp
        for ip in list(self.attempts):
            times = self.attempts[ip]
            while times and times[0] <= timestamp - self.window:
                times.popleft()
            if len(times) < self.threshold:
                self.alerted.discard(ip)
            if not times:
                del self.attempts[ip]
        ip = failed_ip(message)
        if ip is None:
            return None
        times = self.attempts.setdefault(ip, deque(maxlen=self.threshold))
        times.append(timestamp)
        if len(times) >= self.threshold and ip not in self.alerted:
            self.alerted.add(ip)
            return ip
        return None


def alert_message(ip, detector):
    return (f"[ALERT] Possible SSH brute force from {ip}: at least "
            f"{detector.threshold} failed passwords within {detector.window:g}s. "
            "[SIMULATED] Would block this IP; no firewall change made.")
