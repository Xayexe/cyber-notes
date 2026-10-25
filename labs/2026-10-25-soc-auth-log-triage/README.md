# SOC Authentication Log Triage Lab

**Date:** October 25, 2026
**Track:** Blue team / SOC analysis / Python automation
**Environment:** Python 3.9+, standard library only
**Scope:** Synthetic CSV events only. No live systems, accounts, or scanning.

## Objective

Detect repeated authentication failures and successful logins after multiple failures. Export JSON alerts and document analyst triage.

## Run

From this lab directory:

1. Run `python analyze_auth.py data/auth_events.csv --output reports/alerts.json`.
2. Run `python -m unittest discover -s tests -v`.

On Windows, `py` may work instead of `python`.

## Rules

- **Possible brute force:** 4 failed logins from one IP within a rolling 10-minute window.
- **Success after failures:** 4 failed logins for the same IP and username within 15 minutes before a successful login.
- Alerts are heuristic indicators, not proof of compromise.

## Verified sample results

15 events processed, 3 alerts generated, 4 unit tests passed.

- Medium: possible brute force from `198.51.100.23`.
- High: success after failures from `198.51.100.23`.
- Medium: possible brute force from `203.0.113.77`.

The IPs are reserved documentation addresses, not live targets.

## Analyst workflow

1. Validate event times and affected accounts.
2. Check approved sign-in telemetry, MFA, devices, and activity.
3. Rule out legitimate testing, shared NAT addresses, and user error.
4. Escalate suspicious cases under the organization's incident-response process.

## Limitations

- Synthetic input only.
- Per-IP thresholds may create false positives for shared NATs.
- Only first brute-force threshold crossing per IP is reported.
- No distributed password-spray detection or native Windows Event ID ingestion.

## Portfolio evidence

- `analyze_auth.py`: CSV parsing, rolling-window detection, JSON alerts.
- `tests/test_analyze_auth.py`: four automated tests.
- `data/auth_events.csv`: reproducible synthetic evidence.
- `reports/alerts.json`: sample report.
- `FINDINGS.md`: triage observations and next steps.

**Skills:** Python, SOC triage, log parsing, authentication monitoring, detection engineering, unit testing, and technical documentation.

**Attribution:** The initial prototype was created with AI assistance. Independently rerun and improve the work before claiming independent implementation.
