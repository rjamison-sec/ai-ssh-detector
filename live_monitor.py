"""Follow new SSH journal events; alert without changing the firewall."""

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import subprocess
import sys
import time

from detector import Detector, add_detection_options, alert_message


def journal_message(line):
    try:
        entry = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(entry, dict):
        return None
    if entry.get("_COMM") not in ("sshd", "sshd-session"):
        return None
    message = entry.get("MESSAGE")
    return message if isinstance(message, str) else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    add_detection_options(parser)
    parser.add_argument("--unit", default="ssh", help="SSH systemd unit (default: ssh)")
    parser.add_argument("--log-file", type=Path,
                        default=Path(__file__).resolve().parent / "runtime" / "alerts.log")
    args = parser.parse_args(argv)
    detector = Detector(args.threshold, args.window)
    logger = logging.getLogger("ssh_detector")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = None
    process = None
    try:
        args.log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(args.log_file, maxBytes=1_000_000,
                                      backupCount=3, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logger.addHandler(handler)
        process = subprocess.Popen(
            ["journalctl", "--unit", args.unit, "--follow", "--lines=0",
             "--no-pager", "--output=json"],
            stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        print(f"Monitoring new {args.unit} SSH events. Simulation only; "
              f"press Ctrl+C to stop. Alerts: {args.log_file}", flush=True)
        for line in process.stdout:
            message = journal_message(line)
            ip = detector.feed(message or "", time.monotonic())
            if ip:
                alert = alert_message(ip, detector)
                print(alert, flush=True)
                logger.info(alert)
        code = process.wait()
        print(f"SSH journal stream ended (exit {code}). Check journal access "
              "and the SSH service unit.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        return 0
    except OSError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if process.stdout:
                process.stdout.close()
        if handler:
            logger.removeHandler(handler)
            handler.close()


if __name__ == "__main__":
    raise SystemExit(main())
