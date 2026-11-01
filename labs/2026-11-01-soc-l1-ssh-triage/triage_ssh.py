"""SOC L1 SSH log triage, synthetic events only. Python 3.9+."""
import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

PATTERN = re.compile(
    r'^(?P<time>\S+) (?P<host>[\w.-]+) sshd\[\d+\]: '
    r'(?P<action>Failed|Accepted) password for (?P<user>[\w.-]+) '
    r'from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2$'
)

def parse_events(text):
    events, skipped = [], 0
    for line in text.splitlines():
        match = PATTERN.match(line.strip())
        if not match:
            skipped += 1
            continue
        record = match.groupdict()
        try:
            record['time'] = datetime.fromisoformat(record['time'].replace('Z', '+00:00'))
            if record['time'].tzinfo is None:
                raise ValueError('missing timezone')
            record['time'] = record['time'].astimezone(timezone.utc)
        except ValueError:
            skipped += 1
            continue
        events.append(record)
    return sorted(events, key=lambda e: e['time']), skipped

def detect(events, approved, threshold=4, window_minutes=10, success_minutes=15):
    if threshold < 2 or window_minutes < 1 or success_minutes < 1:
        raise ValueError('Invalid threshold or time window')
    groups = defaultdict(list)
    for e in events:
        groups[(e['host'], e['user'], e['ip'])].append(e)
    alerts = []
    for (host, user, ip), group in sorted(groups.items()):
        failures = [e for e in group if e['action'] == 'Failed']
        trigger = None
        for index in range(threshold - 1, len(failures)):
            window = failures[index - threshold + 1:index + 1]
            if window[-1]['time'] - window[0]['time'] <= timedelta(minutes=window_minutes):
                trigger = window[-1]['time']
                break
        if trigger is None:
            continue
        success = next((e for e in group if e['action'] == 'Accepted'
                        and trigger <= e['time'] <= trigger + timedelta(minutes=success_minutes)), None)
        entry = approved.get(ip)
        matched = bool(entry and entry.get('host') == host and entry.get('user') == user)
        alerts.append({
            'host': host, 'account': user, 'source_ip': ip,
            'failure_count': len(failures), 'threshold': threshold,
            'first_failure_utc': failures[0]['time'].isoformat(),
            'trigger_utc': trigger.isoformat(),
            'success_after_failures': success is not None,
            'success_utc': success['time'].isoformat() if success else None,
            'severity': 'high' if success else 'medium',
            'approved_activity_match': matched,
            'approval_reference': entry.get('ticket') if matched else None,
            'triage': ('Verify approval ticket and activity scope before closing.' if matched
                       else 'Escalate for account and source validation.' if success
                       else 'Investigate source, account, and related alerts.')
        })
    alerts.sort(key=lambda a: (a['severity'] != 'high', a['host'], a['source_ip']))
    for index, alert in enumerate(alerts, 1):
        alert['alert_id'] = f'SSH-{index:03d}'
    return alerts

def markdown_report(alerts, count, skipped):
    lines = [
        '# SOC L1 SSH Authentication Triage Report', '',
        'Synthetic SSH logs only. No production systems accessed.', '',
        f'Events parsed: {count} | Lines skipped: {skipped} | Alerts: {len(alerts)}', '',
        '| ID | Host | Account | Source | Failures | Successful login | Severity | Approved match |',
        '| --- | --- | --- | --- | ---: | --- | --- | --- |'
    ]
    for a in alerts:
        lines.append(f"| {a['alert_id']} | {a['host']} | {a['account']} | {a['source_ip']} | "
                     f"{a['failure_count']} | {'Yes' if a['success_after_failures'] else 'No'} | "
                     f"{a['severity']} | {'Yes' if a['approved_activity_match'] else 'No'} |")
    lines.extend(['', '## Analyst actions', ''])
    for a in alerts:
        lines.extend([f"### {a['alert_id']}: {a['host']} / {a['account']}", '',
                      f"- Evidence: {a['failure_count']} failed SSH logins from {a['source_ip']}. "
                      f"Successful login after threshold: {'yes' if a['success_after_failures'] else 'no'}.",
                      f"- Preliminary priority: {a['severity']}.",
                      f"- Next step: {a['triage']}",
                      '- Analyst disposition: **PENDING HUMAN REVIEW**.', ''])
    lines.extend(['## Investigation limits', '',
                  '- Host/account/source correlation misses distributed password spraying.',
                  '- Approved source matches are leads, not automatic clearance.',
                  '- Successful login alone does not prove compromise.',
                  '- IPs use reserved documentation ranges.', ''])
    return '\n'.join(lines)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('log', type=Path)
    p.add_argument('--approved', type=Path, default=Path('data/approved_activity.json'))
    p.add_argument('--output', type=Path, default=Path('reports'))
    p.add_argument('--threshold', type=int, default=4)
    args = p.parse_args()
    events, skipped = parse_events(args.log.read_text(encoding='utf-8'))
    approved = json.loads(args.approved.read_text(encoding='utf-8'))
    alerts = detect(events, approved, threshold=args.threshold)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'alerts.json').write_text(json.dumps(alerts, indent=2) + '\n', encoding='utf-8')
    (args.output / 'triage_report.md').write_text(markdown_report(alerts, len(events), skipped), encoding='utf-8')
    print(f'Parsed {len(events)} events; skipped {skipped}; created {len(alerts)} alerts.')
    for a in alerts:
        print(f"{a['alert_id']} {a['severity'].upper()} {a['host']} {a['account']} "
              f"{a['source_ip']} success={a['success_after_failures']} approved={a['approved_activity_match']}")

if __name__ == '__main__':
    main()
