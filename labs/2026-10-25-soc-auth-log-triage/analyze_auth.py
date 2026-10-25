"""Analyze synthetic authentication events for brute-force and follow-on success."""
import argparse
import csv
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

REQUIRED_COLUMNS = {'timestamp', 'src_ip', 'username', 'event_type'}
ALLOWED_EVENTS = {'LOGIN_FAILED', 'LOGIN_SUCCESS'}


def read_events(path):
    """Read CSV events, validate fields, and sort by UTC timestamp."""
    with open(path, newline='', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        if not REQUIRED_COLUMNS.issubset(reader.fieldnames or []):
            raise ValueError('CSV must include: timestamp,src_ip,username,event_type')
        events = []
        for row_number, row in enumerate(reader, start=2):
            if row['event_type'] not in ALLOWED_EVENTS:
                raise ValueError(f'Row {row_number}: unsupported event_type')
            if not row['src_ip'] or not row['username']:
                raise ValueError(f'Row {row_number}: missing src_ip or username')
            try:
                timestamp = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
            except ValueError as exc:
                raise ValueError(f'Row {row_number}: invalid timestamp') from exc
            if timestamp.tzinfo is None:
                raise ValueError(f'Row {row_number}: timestamp requires a timezone')
            events.append({**row, 'parsed_time': timestamp.astimezone(timezone.utc)})
    return sorted(events, key=lambda event: event['parsed_time'])


def analyze(events, threshold=4, window_minutes=10, success_minutes=15):
    """Return one brute-force alert per IP and one success-after-failures alert per IP/user."""
    recent_failures = defaultdict(deque)
    last_failures = defaultdict(list)
    brute_force_ips = set()
    success_alerts = set()
    alerts = []
    for event in events:
        when = event['parsed_time']
        ip = event['src_ip']
        user = event['username']
        if event['event_type'] == 'LOGIN_FAILED':
            queue = recent_failures[ip]
            queue.append(when)
            while queue and when - queue[0] > timedelta(minutes=window_minutes):
                queue.popleft()
            last_failures[(ip, user)].append(when)
            if len(queue) >= threshold and ip not in brute_force_ips:
                brute_force_ips.add(ip)
                alerts.append({
                    'type': 'POSSIBLE_BRUTE_FORCE', 'severity': 'medium',
                    'src_ip': ip, 'timestamp': when.isoformat(),
                    'failed_attempts_in_window': len(queue),
                    'window_minutes': window_minutes,
                    'reason': 'Repeated failed logins from one source IP.'
                })
        else:
            failures = [t for t in last_failures[(ip, user)]
                        if timedelta(0) <= when - t <= timedelta(minutes=success_minutes)]
            if len(failures) >= threshold and (ip, user) not in success_alerts:
                success_alerts.add((ip, user))
                alerts.append({
                    'type': 'SUCCESS_AFTER_FAILURES', 'severity': 'high',
                    'src_ip': ip, 'username': user, 'timestamp': when.isoformat(),
                    'preceding_failures': len(failures),
                    'lookback_minutes': success_minutes,
                    'reason': 'Successful login followed multiple failures for the same IP and account.'
                })
    return {
        'events_processed': len(events),
        'failed_logins': sum(e['event_type'] == 'LOGIN_FAILED' for e in events),
        'successful_logins': sum(e['event_type'] == 'LOGIN_SUCCESS' for e in events),
        'alerts': alerts,
        'disclaimer': 'Heuristic alerts from synthetic data; not proof of compromise.'
    }


def main():
    parser = argparse.ArgumentParser(description='SOC authentication-log triage lab')
    parser.add_argument('csv_path', type=Path, help='Authentication event CSV')
    parser.add_argument('--output', type=Path, default=Path('reports/alerts.json'))
    parser.add_argument('--threshold', type=int, default=4)
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error('--threshold must be at least 1')
    report = analyze(read_events(args.csv_path), threshold=args.threshold)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f"Processed {report['events_processed']} events; found {len(report['alerts'])} alerts.")
    for alert in report['alerts']:
        print(f"  [{alert['severity'].upper()}] {alert['type']} from {alert['src_ip']}")
    print(f'Report: {args.output}')


if __name__ == '__main__':
    main()
