# SOC L1 SSH Authentication Triage Report

Synthetic SSH logs only. No production systems accessed.

Events parsed: 19 | Lines skipped: 0 | Alerts: 3

| ID | Host | Account | Source | Failures | Successful login | Severity | Approved match |
| --- | --- | --- | --- | ---: | --- | --- | --- |
| SSH-001 | jump-01 | analyst | 203.0.113.44 | 4 | Yes | high | Yes |
| SSH-002 | web-01 | svc-backup | 198.51.100.23 | 5 | Yes | high | No |
| SSH-003 | db-01 | root | 198.51.100.88 | 5 | No | medium | No |

## Analyst actions

### SSH-001: jump-01 / analyst

- Evidence: 4 failed SSH logins from 203.0.113.44. Successful login after threshold: yes.
- Preliminary priority: high.
- Next step: Verify approval ticket and activity scope before closing.
- Analyst disposition: **PENDING HUMAN REVIEW**.

### SSH-002: web-01 / svc-backup

- Evidence: 5 failed SSH logins from 198.51.100.23. Successful login after threshold: yes.
- Preliminary priority: high.
- Next step: Escalate for account and source validation.
- Analyst disposition: **PENDING HUMAN REVIEW**.

### SSH-003: db-01 / root

- Evidence: 5 failed SSH logins from 198.51.100.88. Successful login after threshold: no.
- Preliminary priority: medium.
- Next step: Investigate source, account, and related alerts.
- Analyst disposition: **PENDING HUMAN REVIEW**.

## Investigation limits

- Host/account/source correlation misses distributed password spraying.
- Approved source matches are leads, not automatic clearance.
- Successful login alone does not prove compromise.
- IPs use reserved documentation ranges.
