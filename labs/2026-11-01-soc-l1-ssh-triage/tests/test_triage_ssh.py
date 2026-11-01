import unittest
from triage_ssh import parse_events, detect, markdown_report

def line(minute, action, host='web-01', user='svc-backup', ip='198.51.100.23'):
    return (f'2026-11-01T13:{minute:02d}:00Z {host} sshd[1001]: '
            f'{action} password for {user} from {ip} port 44000 ssh2')

class TriageTests(unittest.TestCase):
    def test_burst_and_success_is_high(self):
        events, skipped = parse_events('\n'.join([line(i, 'Failed') for i in range(4)]
                                                 + [line(5, 'Accepted')]))
        alerts = detect(events, {})
        self.assertEqual(skipped, 0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['severity'], 'high')

    def test_burst_without_success_is_medium(self):
        events, _ = parse_events('\n'.join(line(i, 'Failed') for i in range(4)))
        self.assertEqual(detect(events, {})[0]['severity'], 'medium')

    def test_approved_source_still_alerts(self):
        events, _ = parse_events('\n'.join(line(i, 'Failed') for i in range(4)))
        approved = {'198.51.100.23': {'host': 'web-01', 'user': 'svc-backup', 'ticket': 'CHG-1'}}
        alerts = detect(events, approved)
        self.assertTrue(alerts[0]['approved_activity_match'])
        self.assertIn('Verify', alerts[0]['triage'])

    def test_typo_does_not_alert(self):
        events, _ = parse_events(line(1, 'Failed') + '\n' + line(2, 'Accepted'))
        self.assertEqual(detect(events, {}), [])

    def test_host_isolation(self):
        events, _ = parse_events('\n'.join([line(0, 'Failed'), line(1, 'Failed'),
                                              line(2, 'Failed', host='db-01'),
                                              line(3, 'Failed', host='db-01')]))
        self.assertEqual(detect(events, {}), [])

    def test_out_of_window_does_not_alert(self):
        events, _ = parse_events('\n'.join(line(i, 'Failed') for i in [0, 11, 22, 33]))
        self.assertEqual(detect(events, {}), [])

    def test_malformed_line_skipped(self):
        events, skipped = parse_events('invalid log line\n' + line(0, 'Failed'))
        self.assertEqual((len(events), skipped), (1, 1))

    def test_report_contains_pending_review(self):
        events, _ = parse_events('\n'.join(line(i, 'Failed') for i in range(4)))
        self.assertIn('PENDING HUMAN REVIEW', markdown_report(detect(events, {}), len(events), 0))

if __name__ == '__main__':
    unittest.main()
