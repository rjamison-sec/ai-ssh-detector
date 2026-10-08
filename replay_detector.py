"""Replay a chronological classic syslog SSH fixture using its event times."""

import argparse
from datetime import datetime
from pathlib import Path
import re
import sys

from detector import Detector, add_detection_options, alert_message


SYSLOG = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
                    r"\S+ sshd(?:-session)?\[\d+\]: (.*)$")
MONTHS = {month: index for index, month in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}


def parse_line(line):
    match = SYSLOG.match(line)
    if not match:
        return None
    month, day, clock = match.group(1).split()
    hour, minute, second = map(int, clock.split(":"))
    try:
        date = datetime(2000, MONTHS[month], int(day), hour, minute, second)
    except (KeyError, ValueError) as error:
        raise ValueError("invalid syslog timestamp") from error
    return (date - datetime(2000, 1, 1)).total_seconds(), match.group(2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    add_detection_options(parser)
    parser.add_argument("log_file", nargs="?", type=Path,
                        default=Path(__file__).resolve().parent / "sample_logs.txt")
    args = parser.parse_args(argv)
    detector = Detector(args.threshold, args.window)
    parsed = skipped = alerts = 0
    try:
        with args.log_file.open(encoding="utf-8") as source:
            for number, line in enumerate(source, 1):
                try:
                    event = parse_line(line)
                    if event is None:
                        skipped += 1
                        continue
                    parsed += 1
                    timestamp, message = event
                    ip = detector.feed(message, timestamp)
                except ValueError as error:
                    raise ValueError(f"line {number}: {error}") from error
                if ip:
                    alerts += 1
                    print(alert_message(ip, detector))
        if not parsed:
            raise ValueError("no supported SSH syslog records found")
        print(f"Replay complete: {parsed} SSH records, {skipped} skipped, {alerts} alerts.")
        return 0
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
