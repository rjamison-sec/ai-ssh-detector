import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from detector import Detector, failed_ip
import live_monitor
import replay_detector


def failure(ip="192.0.2.10"):
    return f"Failed password for invalid user test from {ip} port 12345 ssh2"


class DetectionTests(unittest.TestCase):
    def test_ipv4_ipv6_and_invalid_addresses(self):
        self.assertEqual(failed_ip(failure()), "192.0.2.10")
        self.assertEqual(failed_ip(failure("2001:0db8::1")), "2001:db8::1")
        self.assertIsNone(failed_ip(failure("999.1.2.3")))
        self.assertIsNone(failed_ip("Accepted password for x from 192.0.2.10 port 22"))

    def test_threshold_deduplication_and_bounded_history(self):
        detector = Detector()
        results = [detector.feed(failure(), n) for n in range(20)]
        self.assertEqual(results.count("192.0.2.10"), 1)
        self.assertEqual(len(detector.attempts["192.0.2.10"]), 3)

    def test_old_failures_do_not_accumulate(self):
        detector = Detector()
        for timestamp in (0, 61, 122):
            self.assertIsNone(detector.feed(failure(), timestamp))

    def test_exact_window_boundary_excluded(self):
        detector = Detector()
        for timestamp in (0, 1, 60):
            self.assertIsNone(detector.feed(failure(), timestamp))

    def test_new_burst_rearms_and_inactive_state_expires(self):
        detector = Detector()
        for timestamp in (0, 1, 2):
            detector.feed(failure(), timestamp)
        detector.feed("Accepted password", 63)
        self.assertEqual(detector.attempts, {})
        self.assertEqual(detector.alerted, set())
        for timestamp in (64, 65):
            self.assertIsNone(detector.feed(failure(), timestamp))
        self.assertEqual(detector.feed(failure(), 66), "192.0.2.10")

    def test_sources_are_independent(self):
        detector = Detector(threshold=2)
        detector.feed(failure(), 0)
        self.assertIsNone(detector.feed(failure("192.0.2.11"), 1))
        self.assertEqual(detector.feed(failure(), 2), "192.0.2.10")

    def test_bad_configuration_and_out_of_order(self):
        for values in ((0, 60), (3, 0), (3, float("nan"))):
            with self.assertRaises(ValueError):
                Detector(*values)
        detector = Detector()
        detector.feed(failure(), 5)
        with self.assertRaises(ValueError):
            detector.feed(failure(), 4)

    def test_journal_requires_sshd_and_text_message(self):
        valid = {"_COMM": "sshd", "MESSAGE": failure()}
        self.assertEqual(live_monitor.journal_message(json.dumps(valid)), failure())
        for entry in ({"_COMM": "other", "MESSAGE": failure()},
                      {"_COMM": "sshd", "MESSAGE": [1]},
                      {"_COMM": [], "MESSAGE": failure()}, []):
            self.assertIsNone(live_monitor.journal_message(json.dumps(entry)))
        self.assertIsNone(live_monitor.journal_message("not json"))

    def test_sample_replay_from_another_directory(self):
        script = Path(replay_detector.__file__).resolve()
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(script)], cwd=directory,
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("6 SSH records, 0 skipped, 1 alerts", result.stdout)
        self.assertIn("SIMULATED", result.stdout)

    def test_replay_uses_event_times_and_reports_bad_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.log"
            for content, expected in (
                ("".join(f"Apr 20 15:0{n}:01 host sshd[1]: {failure()}\n"
                         for n in (1, 3, 5)), 0),
                ("unrecognized format\n", 1),
                (f"Apr 20 15:02:01 host sshd[1]: {failure()}\n"
                 f"Apr 20 15:01:01 host sshd[1]: {failure()}\n", 1)):
                path.write_text(content)
                with contextlib.redirect_stdout(io.StringIO()) as out, \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(replay_detector.main([str(path)]), expected)
                if expected == 0:
                    self.assertIn("0 alerts", out.getvalue())

    def test_live_stream_alert_and_process_failure(self):
        process = Mock()
        process.stdout = io.StringIO("\n".join(json.dumps(
            {"_COMM": "sshd", "MESSAGE": failure()}) for _ in range(3)))
        process.wait.return_value = 1
        process.poll.return_value = 1
        with tempfile.TemporaryDirectory() as directory:
            logfile = Path(directory) / "alerts.log"
            with patch("live_monitor.subprocess.Popen", return_value=process) as popen, \
                    patch("live_monitor.time.monotonic", side_effect=[0, 1, 2]), \
                    contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(live_monitor.main(["--log-file", str(logfile)]), 1)
            self.assertEqual(logfile.read_text().count("[ALERT]"), 1)
            self.assertIn("--lines=0", popen.call_args.args[0])
            self.assertTrue(process.stdout.closed)

    def test_ctrl_c_terminates_child(self):
        process = Mock()
        class InterruptedStream(io.StringIO):
            def __next__(self):
                raise KeyboardInterrupt
        process.stdout = InterruptedStream()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as directory, \
                patch("live_monitor.subprocess.Popen", return_value=process), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(live_monitor.main(
                ["--log-file", str(Path(directory) / "alerts.log")]), 0)
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=3)

    def test_missing_journalctl_has_actionable_error(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch("live_monitor.subprocess.Popen", side_effect=FileNotFoundError("journalctl")), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            self.assertEqual(live_monitor.main(
                ["--log-file", str(Path(directory) / "alerts.log")]), 1)
        self.assertIn("journalctl", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
