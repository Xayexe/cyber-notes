# SOC Level 1: SSH Alert Triage and Reporting

Date: November 1, 2026
Track: TryHackMe SOC Level 1, Section 1: Blue Team Introduction (SSH alert practice)
Environment: Python 3.9+, standard library only
Scope: Synthetic local SSH logs. No external targets.

## Objective
Investigate failed SSH logins, identify successes after failure bursts, correlate authorized test activity, prioritize alerts, and write a SOC L1 escalation report. Independent practice scenario, not a completed TryHackMe room.

## Run
From this folder:

    python triage_ssh.py data/ssh_auth.log --approved data/approved_activity.json --output reports
    python -m unittest discover -s tests -v

Windows: replace python with py if needed.

## Rules
- Four or more failures for the same host, account, and IP in ten minutes trigger a medium alert.
- A success within 15 minutes after the failure threshold raises priority to high.
- Approved-source matches require human verification; they do not suppress alerts.

## Verified sample output
- 19 parsed events and 3 alerts.
- SSH-001: high, jump-01/analyst, 203.0.113.44, approved test reference present.
- SSH-002: high, web-01/svc-backup, 198.51.100.23, no approved reference.
- SSH-003: medium, db-01/root, 198.51.100.88, failures without success.
- 8 unit tests passed in the prepared starter project.

## Hands-on exercise, 30–45 minutes
1. Run the script and review reports/triage_report.md.
2. Investigate SSH-002. Write a two-sentence escalation to the SOC lead.
3. Compare SSH-001 with SSH-002. Explain why a change ticket must be verified.
4. Run with --threshold 6 and explain why the alert count drops from 3 to 0.
5. Fill out ANALYST_NOTES.md in your own words and commit your updated notes.

## Portfolio skills
Python, log parsing, detection logic, SOC L1 triage, evidence review, alert prioritization, incident reporting, unit tests, and false-positive analysis.

## Limitations and attribution
Synthetic data and heuristic thresholds. No real compromise established. Documentation IP ranges only. Starter code and synthetic cases were prepared with AI assistance. Run and modify the code independently before claiming independent implementation.
