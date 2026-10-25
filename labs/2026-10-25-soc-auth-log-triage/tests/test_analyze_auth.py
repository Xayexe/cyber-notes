import tempfile
import unittest
from pathlib import Path
from analyze_auth import analyze, read_events


class AuthAnalyzerTests(unittest.TestCase):
    def test_detects_brute_force_and_follow_on_success(self):
        events = read_events(Path(__file__).resolve().parents[1] / 'data' / 'auth_events.csv')
        report = analyze(events)
        self.assertEqual(report['events_processed'], 15)
        self.assertEqual(report['failed_logins'], 10)
        self.assertEqual(report['successful_logins'], 5)
        self.assertEqual(len(report['alerts']), 3)
        self.assertEqual(sum(a['type'] == 'POSSIBLE_BRUTE_FORCE' for a in report['alerts']), 2)
        self.assertEqual(sum(a['type'] == 'SUCCESS_AFTER_FAILURES' for a in report['alerts']), 1)

    def test_normal_activity_has_no_alerts(self):
        events = read_events(Path(__file__).resolve().parents[1] / 'data' / 'auth_events.csv')
        normal = [event for event in events if event['src_ip'] == '192.0.2.10']
        self.assertEqual(analyze(normal)['alerts'], [])

    def test_invalid_event_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'invalid.csv'
            path.write_text('timestamp,src_ip,username,event_type\n'
                            '2026-10-25T14:00:00Z,192.0.2.1,alex,UNKNOWN\n')
            with self.assertRaises(ValueError):
                read_events(path)

    def test_window_does_not_count_old_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'window.csv'
            path.write_text('timestamp,src_ip,username,event_type\n'
                            '2026-10-25T14:00:00Z,192.0.2.1,alex,LOGIN_FAILED\n'
                            '2026-10-25T14:20:00Z,192.0.2.1,alex,LOGIN_FAILED\n'
                            '2026-10-25T14:21:00Z,192.0.2.1,alex,LOGIN_FAILED\n'
                            '2026-10-25T14:22:00Z,192.0.2.1,alex,LOGIN_FAILED\n')
            self.assertEqual(analyze(read_events(path))['alerts'], [])


if __name__ == '__main__':
    unittest.main()
